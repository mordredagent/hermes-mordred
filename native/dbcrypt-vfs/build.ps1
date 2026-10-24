param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$SqliteIncludeDirectory = $env:MORDRED_SQLITE_INCLUDE_DIR,
    [ValidateSet('Probe', 'Checked', 'CheckedTest')][string]$Target = 'Probe'
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
$libraryName = if ($Target -eq 'CheckedTest') {
    'mordred_dbcrypt_checked_test.dll'
} elseif ($Target -eq 'Checked') {
    'mordred_dbcrypt_checked.dll'
} else { 'mordred_dbcrypt_probe.dll' }
$targetPath = Join-Path $outputPath $libraryName
if (Test-Path -LiteralPath $targetPath) { throw 'Refusing to replace an existing VFS DLL.' }
$staging = Join-Path $outputPath ('.vfs-build-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null
$sources = if ($Target -ne 'Probe') {
    @((Join-Path $PSScriptRoot 'vfs.c'), (Join-Path $PSScriptRoot 'checked_io.c'))
} else {
    @((Join-Path $PSScriptRoot 'probe.c'))
}
$include = [IO.Path]::GetFullPath($SqliteIncludeDirectory)
Push-Location $staging
try {
    # sqlite3ext.h resolves APIs through the caller; no SQLite .lib/.dll linkage.
    $testFlags = if ($Target -eq 'CheckedTest') { @('/DMORDRED_VFS_TESTING') } else { @() }
    & cl.exe /nologo /O2 /LD /W4 /WX /TC /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS @testFlags "/I$include" @sources "/Fe$libraryName" /link /INCREMENTAL:NO Advapi32.lib
    if ($LASTEXITCODE -ne 0) { throw 'VFS compilation failed.' }
    [IO.File]::Move((Join-Path $staging $libraryName), $targetPath)
    Get-FileHash -Algorithm SHA256 -LiteralPath $targetPath
} finally {
    Pop-Location
}
