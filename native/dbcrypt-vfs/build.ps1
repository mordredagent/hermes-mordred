param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$SqliteIncludeDirectory = $env:MORDRED_SQLITE_INCLUDE_DIR
)
$ErrorActionPreference = 'Stop'
if (-not $SqliteIncludeDirectory) { throw 'Provide -SqliteIncludeDirectory with matching SQLite API headers.' }
foreach ($header in @('sqlite3.h', 'sqlite3ext.h')) {
    if (-not (Test-Path -LiteralPath (Join-Path $SqliteIncludeDirectory $header) -PathType Leaf)) {
        throw "Missing SQLite API header: $header"
    }
}
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'MSVC x64 build tools are required.' }
    $vsInstall = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsInstall) { throw 'MSVC x64 build tools are unavailable.' }
    $devCmd = Join-Path $vsInstall 'Common7\Tools\VsDevCmd.bat'
    $environmentLines = & $env:ComSpec /d /s /c "`"`"$devCmd`" -arch=x64 -host_arch=x64 >nul && set`""
    if ($LASTEXITCODE -ne 0) { throw 'MSVC environment initialization failed.' }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
}
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputPath) | Out-Null
$target = Join-Path $outputPath 'mordred_dbcrypt_probe.dll'
if (Test-Path -LiteralPath $target) { throw 'Refusing to replace an existing probe DLL.' }
$staging = Join-Path $outputPath ('.probe-build-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
$source = Join-Path $PSScriptRoot 'probe.c'
$include = [IO.Path]::GetFullPath($SqliteIncludeDirectory)
Push-Location $staging
try {
    # sqlite3ext.h resolves APIs through the caller; no SQLite .lib/.dll linkage.
    & cl.exe /nologo /O2 /LD /W4 /WX /TC "/I$include" $source '/Femordred_dbcrypt_probe.dll' '/Foprobe.obj' /link /INCREMENTAL:NO
    if ($LASTEXITCODE -ne 0) { throw 'Diagnostic VFS compilation failed.' }
    [IO.File]::Move((Join-Path $staging 'mordred_dbcrypt_probe.dll'), $target)
    Get-FileHash -Algorithm SHA256 -LiteralPath $target
} finally {
    Pop-Location
}
