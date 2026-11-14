param(
    [Parameter(Mandatory)][string]$Sdk,
    [Parameter(Mandatory)][string]$Jdk,
    [Parameter(Mandatory)][string]$Keystore,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
$Sdk = (Resolve-Path -LiteralPath $Sdk).Path
$Jdk = (Resolve-Path -LiteralPath $Jdk).Path
$Keystore = (Resolve-Path -LiteralPath $Keystore).Path
if (!$env:KATO_ANDROID_SIGN_PASSWORD) { throw 'Set KATO_ANDROID_SIGN_PASSWORD before building.' }
$env:JAVA_HOME = $Jdk
$bin = Join-Path $Jdk 'bin'
$tools = Join-Path $Sdk 'build-tools/35.0.0'
$platform = Join-Path $Sdk 'platforms/android-35/android.jar'
$work = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ('kato-android-build-' + [guid]::NewGuid()))

function Invoke-BuildTool([string]$Name, [string[]]$Arguments) {
    & $Name @Arguments
    if ($LASTEXITCODE) { throw "$Name exited with $LASTEXITCODE" }
}

function Get-VerifiedDependency([string]$Path, [string]$Sha256) {
    $destination = Join-Path $work ($Path.Split('/')[-1])
    Invoke-WebRequest -Uri "https://repo.maven.apache.org/maven2/$Path" -OutFile $destination -TimeoutSec 60
    if ((Get-FileHash -LiteralPath $destination).Hash -ne $Sha256) { throw 'Dependency SHA-256 mismatch' }
    $destination
}
$dependencies = @(
    (Get-VerifiedDependency 'com/github/mwiede/jsch/2.28.8/jsch-2.28.8.jar' '2afca1357d816028f2ac33f22407d2488a68406682973949cebb1b8ea6688a8b')
    (Get-VerifiedDependency 'org/bouncycastle/bcprov-jdk18on/1.87/bcprov-jdk18on-1.87.jar' '12d2d3dd82a9ec15e92ec7c7943ee64f6097c6dc12c07e984f1693b77565b9aa')
)
$classes = New-Item -ItemType Directory -Path (Join-Path $work 'classes')
$dex = New-Item -ItemType Directory -Path (Join-Path $work 'dex')
$assets = New-Item -ItemType Directory -Path (Join-Path $work 'assets')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../nikki-router-setup/profile/support-relay.json') -Destination $assets.FullName
$unsigned = Join-Path $work 'unsigned.apk'
$aligned = Join-Path $work 'aligned.apk'
$sources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.java' -File | ForEach-Object FullName)
$tests = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'test') -Filter '*.java' -File | ForEach-Object FullName)
Invoke-BuildTool (Join-Path $bin 'javac.exe') (@('--release','11','-encoding','UTF-8','-cp',("$platform;" + ($dependencies -join ';')),'-d',$classes.FullName) + $sources + $tests)
Invoke-BuildTool (Join-Path $bin 'java.exe') @('-cp',$classes.FullName,'app.katovpn.support.SupportPolicyTest')
Invoke-BuildTool (Join-Path $tools 'aapt2.exe') @('link','-I',$platform,'--manifest',(Join-Path $PSScriptRoot 'AndroidManifest.xml'),'-A',$assets.FullName,'-o',$unsigned)
$classFiles = @(Get-ChildItem -LiteralPath $classes.FullName -Recurse -Filter '*.class' -File |
    Where-Object Name -notlike '*Test*' | ForEach-Object FullName)
Invoke-BuildTool (Join-Path $tools 'd8.bat') (@('--release','--min-api','29','--lib',$platform,'--output',$dex.FullName) + $dependencies + $classFiles)

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::Open($unsigned, [IO.Compression.ZipArchiveMode]::Update)
try {
    foreach ($file in (Get-ChildItem -LiteralPath $dex.FullName -Filter '*.dex' -File)) {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $file.Name) | Out-Null
    }
    foreach ($dependency in $dependencies) {
        $library = [IO.Compression.ZipFile]::OpenRead($dependency)
        try {
            $licenses = @($library.Entries | Where-Object Name -match '^LICENSE(?:\.[A-Za-z0-9]+)*\.(txt|md)$')
            if (!$licenses.Count) { throw 'Dependency license is missing' }
            foreach ($license in $licenses) {
                $input = $license.Open()
                $output = $archive.CreateEntry('assets/' + [IO.Path]::GetFileNameWithoutExtension($dependency) + '-' + $license.Name).Open()
                try { $input.CopyTo($output) } finally { $input.Dispose(); $output.Dispose() }
            }
        } finally { $library.Dispose() }
    }
} finally { $archive.Dispose() }

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$apk = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path 'KatoVPN-Router-Support-v0.1.1-preview.apk'
Invoke-BuildTool (Join-Path $tools 'zipalign.exe') @('-f','4',$unsigned,$aligned)
Invoke-BuildTool (Join-Path $tools 'apksigner.bat') @('sign','--ks',$Keystore,'--ks-key-alias','katovpn-support','--ks-pass','env:KATO_ANDROID_SIGN_PASSWORD','--out',$apk,$aligned)
Invoke-BuildTool (Join-Path $tools 'apksigner.bat') @('verify','--verbose','--print-certs',$apk)
Invoke-BuildTool (Join-Path $tools 'aapt.exe') @('dump','badging',$apk)
Get-FileHash -LiteralPath $apk
