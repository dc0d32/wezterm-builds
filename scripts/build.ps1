# Build untrusted upstream only on the disposable, read-only Windows runner.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

if ($env:GITHUB_REPOSITORY -ne 'dc0d32/wezterm-builds') { throw 'Wrong build repository' }
if ($env:GITHUB_EVENT_NAME -notin @('schedule', 'workflow_dispatch')) { throw 'Wrong event' }
if ($env:GITHUB_TOKEN -or $env:GH_TOKEN) { throw 'Do not expose API tokens to upstream' }
$env:GIT_TERMINAL_PROMPT = '0'
$snapshot = $env:SNAPSHOT | ConvertFrom-Json
$sha = $snapshot.request.source_sha
$version = $snapshot.version
if ($sha -cnotmatch '^[0-9a-f]{40}$' -or $version -cnotmatch '^\d{8}-\d{6}-[0-9a-f]{8}$') {
    throw 'Invalid source/version'
}
if (Test-Path candidate) { throw 'Candidate directory must be fresh' }

# Public clone: unlike checkout with submodules, no token is passed to upstream.
git -c credential.helper= -c core.autocrlf=false init candidate
git -C candidate remote add origin https://github.com/wezterm/wezterm.git
git -C candidate -c credential.helper= fetch --no-tags --depth=1 origin $sha
git -C candidate -c core.autocrlf=false checkout --detach FETCH_HEAD
if ((git -C candidate rev-parse HEAD).Trim() -cne $sha) { throw 'Wrong source commit' }
git -C candidate -c credential.helper= -c protocol.allow=never -c protocol.https.allow=always submodule update --init --recursive --depth=1
git -C candidate submodule status --recursive | ForEach-Object {
    if ($_ -notmatch '^ [0-9a-f]{40} ') { throw "Non-exact submodule: $_" }
}

$env:TZ = 'UTC'
$actual = (git -C candidate -c core.abbrev=8 show -s '--format=%cd-%h' '--date=format-local:%Y%m%d-%H%M%S').Trim()
if ($actual -cne $version) { throw 'Upstream commit date/version mismatch' }
# Both upstream version build scripts consume .tag; retain its intended format,
# not the transport's source/run/attempt build ID.
[IO.File]::WriteAllText((Join-Path (Resolve-Path candidate) '.tag'), "$version`n",
    [Text.UTF8Encoding]::new($false))

$env:PATH = "C:\Strawberry\perl\bin;C:\Program Files\Inno Setup 6;$env:PATH"
$env:CARGO_INCREMENTAL = '0'
$env:RUSTUP_WINDOWS_PATH_ADD_BIN = '1'
# Avoid installing unpinned Rust actions. windows-2025 provides rustup; stable
# matches upstream Windows CI. Cargo dependencies remain locked.
rustup toolchain install stable --profile minimal
rustup default stable
rustup target add x86_64-pc-windows-msvc
# Install outside candidate so its vendored source replacement does not apply
# to Nextest's own dependencies, matching upstream's cargo-install CI step.
cargo install cargo-nextest --locked
Push-Location candidate
try {
    cargo vendor --locked --versioned-dirs | Out-File -Append -Encoding utf8 .cargo/config.toml
    cargo build --locked --release -p wezterm -p wezterm-gui -p wezterm-mux-server -p strip-ansi-escapes
    # Follow upstream Windows CI; SSH integration tests already ignore Windows.
    cargo nextest run --locked --all --no-fail-fast
    foreach ($exe in @('wezterm', 'wezterm-gui', 'wezterm-mux-server', 'strip-ansi-escapes')) {
        if (-not (Test-Path "target/release/$exe.exe")) { throw "Missing $exe.exe" }
    }
    $reported = (& ./target/release/wezterm.exe --version).Trim()
    if ($reported -cne "wezterm $version") { throw "Unexpected executable version: $reported" }
    $env:TAG_NAME = $version
    $env:BUILD_REASON = ''
    # Upstream ci/deploy.ps1 does not exist; its Windows CI uses deploy.sh.
    # Git for Windows bash selects msys, packages all runtime DLLs and runs ISCC.
    & 'C:\Program Files\Git\bin\bash.exe' ci/deploy.sh
    if (-not (Test-Path "WezTerm-windows-$version.zip")) { throw 'Upstream ZIP missing' }
} finally {
    Pop-Location
}
python -B control/scripts/pipeline.py package
