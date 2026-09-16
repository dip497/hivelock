# Install hivelock from GitHub releases (Windows).
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/dip497/hivelock/main/install.ps1 | iex"
#   (works from cmd.exe and PowerShell)
# Env: HIVELOCK_VERSION (default: latest), HIVELOCK_BIN_DIR (default: %LOCALAPPDATA%\Programs\hivelock), HIVELOCK_NO_SETUP=1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'dip497/hivelock'
$binDir = if ($env:HIVELOCK_BIN_DIR) { $env:HIVELOCK_BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\hivelock' }
$version = if ($env:HIVELOCK_VERSION) { $env:HIVELOCK_VERSION } else {
    (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
}

$name = "hivelock-$version-x86_64-pc-windows-msvc"
$base = "https://github.com/$repo/releases/download/$version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hivelock-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "downloading $name"
    Invoke-WebRequest "$base/$name.zip" -OutFile "$tmp\$name.zip" -UseBasicParsing
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing

    $expected = (Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match " $([regex]::Escape("$name.zip"))$" }) -split ' ' | Select-Object -First 1
    $actual = (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash.ToLower()
    if (-not $expected -or $expected -ne $actual) { throw 'checksum mismatch, not installing' }

    Expand-Archive "$tmp\$name.zip" -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Copy-Item "$tmp\$name\hivelock.exe" "$binDir\hivelock.exe" -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $binDir)) {
    [Environment]::SetEnvironmentVariable('Path', (($userPath, $binDir) | Where-Object { $_ }) -join ';', 'User')
    Write-Host "added $binDir to your PATH (open a new terminal)"
}
$env:Path = "$binDir;$env:Path"
Write-Host "installed $(& "$binDir\hivelock.exe" --version) to $binDir\hivelock.exe"
if (-not $env:HIVELOCK_NO_SETUP -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
    & "$binDir\hivelock.exe" setup
} else {
    Write-Host 'next: hivelock setup'
}
