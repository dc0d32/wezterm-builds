# Build untrusted upstream only on the disposable, read-only Windows runner.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare', 'Compile')][string]$Phase,
    [Parameter(Mandatory)][ValidateSet('x86_64', 'aarch64')][string]$Architecture
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($Phase -eq 'Compile') {
    Get-ChildItem Env: | Where-Object { $_.Name -match '^ACTIONS_' } |
        ForEach-Object { Remove-Item "Env:$($_.Name)" }
}

if ($env:GITHUB_REPOSITORY -ne 'dc0d32/wezterm-builds') { throw 'Wrong build repository' }
if ($env:GITHUB_EVENT_NAME -notin @('schedule', 'workflow_dispatch')) { throw 'Wrong event' }
if (-not $env:BUILD_DEFAULT_BRANCH -or $env:GITHUB_REF -cne "refs/heads/$env:BUILD_DEFAULT_BRANCH") {
    throw 'Build must run on the default branch'
}
if ($env:GITHUB_TOKEN -or $env:GH_TOKEN) { throw 'Do not expose API tokens to upstream' }
if (Get-ChildItem Env: | Where-Object { $_.Name -match '^CARGO_.*TOKEN$' }) {
    throw 'Do not expose Cargo registry credentials to upstream'
}
function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

$root = (Get-Location).Path
$target = if ($Architecture -eq 'aarch64') {
    'aarch64-pc-windows-msvc'
} else {
    'x86_64-pc-windows-msvc'
}
$env:GIT_TERMINAL_PROMPT = '0'
$snapshot = $env:SNAPSHOT | ConvertFrom-Json
$sha = $snapshot.request.source_sha
$version = $snapshot.version
if ($sha -cnotmatch '^[0-9a-f]{40}$' -or $version -cnotmatch '^\d{8}-\d{6}-[0-9a-f]{8}$') {
    throw 'Invalid source/version'
}
if ($Phase -eq 'Prepare') {
    foreach ($path in @('candidate', '.cargo-build', '.nextest', '.nextest-install',
                       '.build-identity.json', '.build-cache-plan.json')) {
        if (Test-Path $path) { throw "Preparation requires fresh $path" }
    }
    # Public clone: unlike checkout with submodules, no token is passed to upstream.
    Invoke-Checked git @('-c', 'credential.helper=', '-c', 'core.autocrlf=false', 'init', 'candidate')
    Invoke-Checked git @('-C', 'candidate', 'remote', 'add', 'origin', 'https://github.com/wezterm/wezterm.git')
    Invoke-Checked git @('-C', 'candidate', '-c', 'credential.helper=', 'fetch', '--no-tags', '--depth=1', 'origin', $sha)
    Invoke-Checked git @('-C', 'candidate', '-c', 'core.autocrlf=false', 'checkout', '--detach', 'FETCH_HEAD')
    Invoke-Checked git @('-C', 'candidate', '-c', 'credential.helper=', '-c', 'protocol.allow=never',
                         '-c', 'protocol.https.allow=always', 'submodule', 'update', '--init', '--recursive', '--depth=1')
}
if ((Invoke-Checked git @('-C', 'candidate', 'rev-parse', 'HEAD')).Trim() -cne $sha) {
    throw 'Wrong source commit'
}
Invoke-Checked git @('-C', 'candidate', 'submodule', 'status', '--recursive') | ForEach-Object {
    if ($_ -notmatch '^ [0-9a-f]{40} ') { throw "Non-exact submodule: $_" }
}

$env:TZ = 'UTC'
$actual = (Invoke-Checked git @('-C', 'candidate', '-c', 'core.abbrev=8', 'show', '-s',
                               '--format=%cd-%h', '--date=format-local:%Y%m%d-%H%M%S')).Trim()
if ($actual -cne $version) { throw 'Upstream commit date/version mismatch' }
# Both upstream version build scripts consume .tag; retain its intended format,
# not the transport's source/run/attempt build ID.
[IO.File]::WriteAllText((Join-Path (Resolve-Path candidate) '.tag'), "$version`n",
    [Text.UTF8Encoding]::new($false))

$env:CARGO_HOME = Join-Path $root '.cargo-build'
$env:CARGO_TARGET_DIR = Join-Path $root 'candidate/target'
$env:CARGO_INCREMENTAL = '0'
$env:RUSTUP_WINDOWS_PATH_ADD_BIN = '1'
$env:RUSTUP_TOOLCHAIN = 'stable'
# Avoid installing unpinned Rust actions. windows-2025 provides rustup; stable
# matches upstream Windows CI. The explicit override also prevents a candidate
# rust-toolchain file from changing the prepared compiler after cache restore.
# Cargo dependencies remain locked.
if ($Phase -eq 'Prepare') {
    Invoke-Checked rustup @('toolchain', 'install', 'stable', '--profile', 'minimal')
    Invoke-Checked rustup @('default', 'stable')
    Invoke-Checked rustup @('target', 'add', $target)
}
# Resolve the native compiler explicitly, rather than guessing the hosted image's
# default Visual Studio installation. Import the same environment in both phases.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$component = if ($Architecture -eq 'aarch64') {
    'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
} else {
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
}
$vs = (Invoke-Checked $vswhere @('-latest', '-products', '*', '-requires',
          $component, '-property', 'installationPath')).Trim()
if (-not $vs) { throw 'MSVC installation missing' }
$vsDevCmd = Join-Path $vs 'Common7/Tools/VsDevCmd.bat'
# CALL keeps cmd /s from stripping the quotes around the batch-file path.
$nativeArch = if ($Architecture -eq 'aarch64') { 'arm64' } else { 'x64' }
$nativeEnvironment = Invoke-Checked cmd.exe @('/d', '/s', '/c',
    "call `"$vsDevCmd`" -no_logo -arch=$nativeArch -host_arch=x64 >nul && set")
foreach ($line in $nativeEnvironment) {
    if ($line -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
$env:PATH = "C:\Strawberry\perl\bin;C:\Program Files\Inno Setup 6;$env:PATH"
$env:CARGO_BUILD_TARGET = if ($Architecture -eq 'aarch64') { $target } else { $null }
if ($Architecture -eq 'aarch64') {
    $env:CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUSTFLAGS = '-Ctarget-feature=+crt-static'
}
$compiler = (Get-Command cl.exe -CommandType Application).Source
$linker = (Get-Command link.exe -CommandType Application).Source
$environment = [ordered]@{}
foreach ($name in @('PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VCToolsVersion',
                   'WindowsSDKVersion', 'WindowsSdkDir', 'UCRTVersion', 'CC', 'CXX',
                   'CFLAGS', 'CXXFLAGS', 'CL', '_CL_', 'LINK', '_LINK_', 'RUSTFLAGS',
                   'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET',
                   'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_INCREMENTAL',
                   'CARGO_PROFILE_RELEASE_LTO', 'CARGO_PROFILE_RELEASE_CODEGEN_UNITS',
                   'CARGO_PROFILE_RELEASE_OPT_LEVEL', 'CARGO_PROFILE_DEV_OPT_LEVEL')) {
    $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Get-ChildItem Env: | Where-Object {
    $_.Name -match '^(CARGO_|RUST|CC($|_)|CXX($|_)|AR($|_)|CFLAGS($|_)|CXXFLAGS($|_)|CPPFLAGS($|_)|LDFLAGS($|_)|SCCACHE_)'
} | ForEach-Object { $environment[$_.Name] = $_.Value }
$identity = [ordered]@{
    os = $env:RUNNER_OS
    arch = $env:RUNNER_ARCH
    target = $target
    rustc = (Invoke-Checked rustc @('-vV')) -join "`n"
    cargo = (Invoke-Checked cargo @('-vV')) -join "`n"
    image_os = $env:ImageOS
    image_version = $env:ImageVersion
    native = "$compiler`n$((Get-FileHash $compiler -Algorithm SHA256).Hash)`n$linker`n$((Get-FileHash $linker -Algorithm SHA256).Hash)"
    environment = $environment
}
[IO.File]::WriteAllText((Join-Path $root '.build-identity.json'),
    ($identity | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
if ($Phase -eq 'Prepare') {
    Invoke-Checked python @('-B', 'control/scripts/build_cache.py', 'prepare')
    exit 0
}
# Cache files are untrusted. Check shape/links before executing any cached tool
# or allowing Cargo to consume cached artifacts; identity must still match.
Invoke-Checked python @('-B', 'control/scripts/build_cache.py', 'verify')
if ($Architecture -eq 'x86_64') {
    $nextestVersion = (Invoke-Checked python @('-B', 'control/scripts/build_cache.py', 'nextest-version')).Trim()
    $nextest = Join-Path $root '.nextest/bin/cargo-nextest.exe'
    if (-not (Test-Path $nextest)) {
        if ($env:NEXTEST_CACHE_MATCHED) { throw 'Nextest cache hit is missing its executable' }
        if (Test-Path '.nextest-install') { throw 'Nextest install root must be fresh' }
        # Install outside candidate and cache only the binary, not Cargo receipts,
        # configuration, install dependencies, or the entire Cargo home.
        Invoke-Checked cargo @('install', 'cargo-nextest', '--locked', '--version', "=$nextestVersion",
                              '--root', (Join-Path $root '.nextest-install'),
                              '--target-dir', (Join-Path $root '.nextest-install/target'))
        New-Item -ItemType Directory -Force '.nextest/bin' | Out-Null
        Copy-Item '.nextest-install/bin/cargo-nextest.exe' $nextest
        Remove-Item -Recurse -Force '.nextest-install'
    }
    # Executing this check is intentionally inside the token-free compile boundary.
    # A corrupt hit fails the build; never silently reinstall or suppress failures.
    $toolVersion = (Invoke-Checked $nextest @('nextest', '--version')).Trim()
    Invoke-Checked python @('-B', 'control/scripts/build_cache.py', 'check-nextest-version', $toolVersion)
}
Push-Location candidate
try {
    Invoke-Checked cargo @('vendor', '--locked', '--versioned-dirs') |
        Out-File -Append -Encoding utf8 .cargo/config.toml
    # Restore only dependency reuse, not workspace freshness. Cargo clean removes
    # both release/debug workspace fingerprints, build scripts and final EXEs.
    # This includes wezterm-version (.tag) and local/submodule path dependencies.
    $metadata = (Invoke-Checked cargo @('metadata', '--locked', '--format-version', '1')) |
        ConvertFrom-Json
    foreach ($package in $metadata.packages) {
        if ($null -eq $package.source) {
            Invoke-Checked cargo @('clean', '--package', $package.id)
        }
    }
    $releaseDir = if ($Architecture -eq 'aarch64') {
        "target/$target/release"
    } else {
        'target/release'
    }
    foreach ($exe in @('wezterm', 'wezterm-gui', 'wezterm-mux-server', 'strip-ansi-escapes')) {
        if (Test-Path "$releaseDir/$exe.exe") { throw "Stale workspace executable: $exe" }
    }
    $buildArgs = @('build', '--locked', '--release', '-p', 'wezterm', '-p', 'wezterm-gui',
                   '-p', 'wezterm-mux-server', '-p', 'strip-ansi-escapes')
    if ($Architecture -eq 'aarch64') { $buildArgs += @('--target', $target) }
    Invoke-Checked cargo $buildArgs
    if ($Architecture -eq 'x86_64') {
        # Preserve upstream's full native Windows test suite.
        Invoke-Checked $nextest @('nextest', 'run', '--locked', '--all', '--no-fail-fast')
    } else {
        # Cross-built tests cannot run here; compile every test target on the x64 runner.
        Invoke-Checked cargo @('test', '--locked', '--all', '--no-run', '--target', $target)
    }
    foreach ($exe in @('wezterm', 'wezterm-gui', 'wezterm-mux-server', 'strip-ansi-escapes')) {
        if (-not (Test-Path "$releaseDir/$exe.exe")) { throw "Missing $exe.exe" }
    }
    if ($Architecture -eq 'x86_64') {
        $reported = (Invoke-Checked './target/release/wezterm.exe' @('--version')).Trim()
        if ($reported -cne "wezterm $version") { throw "Unexpected executable version: $reported" }
        $env:TAG_NAME = $version
        $env:BUILD_REASON = ''
        # Upstream ci/deploy.ps1 does not exist; its Windows CI uses deploy.sh.
        # Git for Windows bash selects msys, packages all runtime DLLs and runs ISCC.
        Invoke-Checked 'C:\Program Files\Git\bin\bash.exe' @('ci/deploy.sh')
        if (-not (Test-Path "WezTerm-windows-$version.zip")) { throw 'Upstream ZIP missing' }
    }
} finally {
    Pop-Location
}
Invoke-Checked python @('-B', 'control/scripts/pipeline.py', 'package', $Architecture)
Invoke-Checked python @('-B', 'control/scripts/build_cache.py', 'validate')
