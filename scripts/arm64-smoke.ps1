# Run only on the token-free native ARM64 validation runner.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$credentialPattern = '^(?:ACTIONS_.*|GITHUB_TOKEN|GITHUB_PAT|GITHUB_ENTERPRISE_TOKEN|GH_TOKEN|GH_ENTERPRISE_TOKEN|CARGO_.*TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|NUGET_AUTH_TOKEN|PYPI_API_TOKEN|TWINE_USERNAME|TWINE_PASSWORD)$'
Get-ChildItem Env: | Where-Object { $_.Name -match $credentialPattern } |
    ForEach-Object { Remove-Item "Env:$($_.Name)" }

function Assert-NoArtifactCredentials {
    $exposed = @(Get-ChildItem Env: | Where-Object { $_.Name -match $credentialPattern })
    if ($exposed.Count -ne 0) {
        throw "Refusing to execute artifact code with credentials: $($exposed.Name -join ', ')"
    }
}

function Invoke-Checked {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [AllowNull()][object]$InputObject,
        [switch]$WithInput
    )
    Assert-NoArtifactCredentials
    if ($WithInput) {
        $InputObject | & $Command @Arguments
    } else {
        & $Command @Arguments
    }
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

function Start-ArtifactProcess {
    param([string]$FilePath, [string[]]$ArgumentList)
    Assert-NoArtifactCredentials
    Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
}

Assert-NoArtifactCredentials
$snapshot = $env:SNAPSHOT | ConvertFrom-Json
$expected = "wezterm $($snapshot.version)"
$reported = (Invoke-Checked .\arm-smoke\wezterm.exe @('--version')).Trim()
if ($reported -cne $expected) { throw "Unexpected ARM64 version: $reported" }

foreach ($program in @('wezterm.exe', 'wezterm-gui.exe', 'wezterm-mux-server.exe',
                       'strip-ansi-escapes.exe')) {
    Invoke-Checked ".\arm-smoke\$program" @('--help') | Out-Null
}

$plain = Invoke-Checked -Command .\arm-smoke\strip-ansi-escapes.exe -Arguments @() `
   -InputObject "plain`e[31m-red`e[0m" -WithInput
if (($plain -join "`n") -cne 'plain-red') { throw 'strip-ansi-escapes smoke failed' }

# WezTerm creates the console child through ConPTY. Keeping a uniquely marked cmd
# alive proves native process creation. WebGpu uses Windows' native D3D backend;
# Software would require the Mesa DLL that is deliberately absent from this ZIP.
$marker = "wezterm-arm64-conpty-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
$arguments = @('--config', "front_end='WebGpu'", 'start', '--always-new-process', '--',
               'cmd.exe', '/d', '/c', "title $marker && ping -n 30 127.0.0.1 >nul")
$gui = Start-ArtifactProcess -FilePath .\arm-smoke\wezterm-gui.exe -ArgumentList $arguments
try {
    Start-Sleep -Seconds 12
    if ($gui.HasExited) { throw "ARM64 GUI/renderer exited early with $($gui.ExitCode)" }
    $child = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -ieq 'cmd.exe' -and $_.CommandLine -like "*$marker*"
    }
    if (-not $child) { throw 'ARM64 ConPTY console child was not observed' }
} finally {
    Get-CimInstance Win32_Process | Where-Object {
        $_.Name -ieq 'cmd.exe' -and $_.CommandLine -like "*$marker*"
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    if (-not $gui.HasExited) { Stop-Process -Id $gui.Id -Force }
}
