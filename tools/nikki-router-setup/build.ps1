[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$PythonExecutable,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$ToolRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ToolRoot)
if (-not $PythonExecutable) {
    $RepoVenvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    $PythonExecutable = if (Test-Path -LiteralPath $RepoVenvPython) { $RepoVenvPython } else { 'python' }
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepoRoot 'operations\tmp\nikki-router-setup'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$ScratchRoot = Join-Path $OutputDirectory '.build'
$SpecRoot = Join-Path $ScratchRoot 'spec'
$WorkRoot = Join-Path $ScratchRoot 'work'
$ArtifactBase = 'KatoVPN-Router-Control-v0.4.3-preview'
$ExePath = Join-Path $OutputDirectory "$ArtifactBase.exe"
$VersionInfoPath = Join-Path $ToolRoot 'windows-version-info.txt'
$ManifestPath = Join-Path $ToolRoot 'windows-app.manifest'

function Assert-PathInsideDirectory {
    param([string]$Path, [string]$Directory)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullDirectory = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\')
    if ($fullPath -ne $fullDirectory -and -not $fullPath.StartsWith("$fullDirectory\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe build path outside output directory: $fullPath"
    }
}

Assert-PathInsideDirectory -Path $ScratchRoot -Directory $OutputDirectory
Assert-PathInsideDirectory -Path $ExePath -Directory $OutputDirectory
New-Item -ItemType Directory -Force -Path $OutputDirectory,$SpecRoot,$WorkRoot | Out-Null

if (-not $SkipTests) {
    & $PythonExecutable -m unittest discover -s (Join-Path $RepoRoot 'tools\tests') -p 'test_*router*.py' -v
    if ($LASTEXITCODE -ne 0) { throw 'Nikki router setup tests failed.' }
}

$addWeb = "{0};web" -f (Join-Path $ToolRoot 'web')
$addProfile = "{0};profile" -f (Join-Path $ToolRoot 'profile')
$iconPath = Join-Path $ToolRoot 'web\logo.png'
& $PythonExecutable -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --noupx `
    --name $ArtifactBase `
    --icon $iconPath `
    --version-file $VersionInfoPath `
    --manifest $ManifestPath `
    --distpath $OutputDirectory `
    --workpath $WorkRoot `
    --specpath $SpecRoot `
    --paths $ToolRoot `
    --add-data $addWeb `
    --add-data $addProfile `
    (Join-Path $ToolRoot 'app.py')
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ExePath)) {
    throw "PyInstaller did not create $ArtifactBase.exe."
}

$smoke = Start-Process -FilePath $ExePath -ArgumentList '--smoke-test','--no-browser' -Wait -PassThru -WindowStyle Hidden
if ($smoke.ExitCode -ne 0) { throw "Executable smoke test failed with exit code $($smoke.ExitCode)." }

$hash = Get-FileHash -LiteralPath $ExePath -Algorithm SHA256
$file = Get-Item -LiteralPath $ExePath
$result = [pscustomobject][ordered]@{
    schema = 'katovpn.nikki_router_setup_build.v1'
    generated_at = (Get-Date).ToString('o')
    executable = $file.FullName
    bytes = $file.Length
    sha256 = $hash.Hash.ToLowerInvariant()
    tests = if ($SkipTests) { 'skipped' } else { 'passed' }
    smoke_test = 'passed'
    live_router_changes = 'none'
}
$result | ConvertTo-Json -Depth 5
