[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$AllowedRootFiles = @(
    '.gitignore', 'LICENSE', 'README.md', 'SECURITY.md', 'PRIVACY.md',
    'CODE_SIGNING.md', 'CHANGELOG.md', 'RELEASE_NOTES.md'
)
$AllowedHosts = @(
    'about.signpath.io', 'api.github.com', 'github.com', 'ifconfig.co', 'ipapi.co', 'ipwho.is',
    'katovpn.app', 'nikkinikki.pages.dev', 'openwrt.org',
    'router-support.katovpn.app', 'signpath.org', 't.me'
)
$AllowedPublicIps = @('1.1.1.1', '8.8.8.8', '223.5.5.5', '223.6.6.6')
$TextExtensions = @('.css', '.html', '.js', '.json', '.md', '.ps1', '.py', '.txt', '.uci', '.yml', '.yaml', '.xml')
$Violations = [System.Collections.Generic.List[string]]::new()

$paths = @(& git -C $RepoRoot ls-files --cached --others --exclude-standard) |
    ForEach-Object { $_.Trim().Replace('\', '/') } |
    Where-Object { $_ } |
    Sort-Object -Unique

foreach ($path in $paths) {
    $allowed = $AllowedRootFiles -contains $path -or $path.StartsWith('.github/') -or $path.StartsWith('tools/')
    if (-not $allowed) {
        $Violations.Add("path outside public allowlist: $path")
        continue
    }
    if ($path -match '(^|/)(?:\.env(?:\.|$)|secrets?|inventory|nodes?|operations?|backups?)(/|$)' -or
        $path -match '\.(?:key|pem|p12|pfx|ppk)$') {
        $Violations.Add("prohibited path or key material: $path")
        continue
    }

    $fullPath = Join-Path $RepoRoot $path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { continue }
    if ($TextExtensions -notcontains [System.IO.Path]::GetExtension($path).ToLowerInvariant()) { continue }
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $fullPath

    $secretPatterns = @(
        '-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----',
        '\bgh[pousr]_[A-Za-z0-9]{20,}\b',
        '\bgithub_pat_[A-Za-z0-9_]{20,}\b',
        '\bAKIA[0-9A-Z]{16}\b'
    )
    foreach ($pattern in $secretPatterns) {
        if ([regex]::IsMatch($text, $pattern)) {
            $Violations.Add("secret-like material: $path")
            break
        }
    }

    foreach ($match in [regex]::Matches($text, 'https?://([A-Za-z0-9.-]+)')) {
        $urlHost = $match.Groups[1].Value.ToLowerInvariant().TrimEnd('.')
        if (-not $urlHost -or $urlHost.EndsWith('.example.test')) { continue }
        $parsedIp = $null
        if ([System.Net.IPAddress]::TryParse($urlHost, [ref]$parsedIp)) { continue }
        if ($AllowedHosts -notcontains $urlHost) {
            $Violations.Add("unapproved public hostname '$urlHost': $path")
        }
    }

    foreach ($match in [regex]::Matches($text, '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])')) {
        $value = $match.Value
        $parts = @($value.Split('.') | ForEach-Object { [int]$_ })
        if ($parts | Where-Object { $_ -gt 255 }) { continue }
        $isSafe = $parts[0] -eq 0 -or $parts[0] -eq 10 -or $parts[0] -eq 127 -or $parts[0] -ge 224 -or
            ($parts[0] -eq 169 -and $parts[1] -eq 254) -or
            ($parts[0] -eq 172 -and $parts[1] -ge 16 -and $parts[1] -le 31) -or
            ($parts[0] -eq 100 -and $parts[1] -ge 64 -and $parts[1] -le 127) -or
            ($parts[0] -eq 192 -and $parts[1] -eq 168) -or
            ($parts[0] -eq 192 -and $parts[1] -eq 0 -and $parts[2] -eq 2) -or
            ($parts[0] -eq 198 -and ($parts[1] -eq 18 -or $parts[1] -eq 19)) -or
            ($parts[0] -eq 198 -and $parts[1] -eq 51 -and $parts[2] -eq 100) -or
            ($parts[0] -eq 203 -and $parts[1] -eq 0 -and $parts[2] -eq 113) -or
            $AllowedPublicIps -contains $value
        if (-not $isSafe) {
            $Violations.Add("unapproved public IPv4 address: $path")
        }
    }
}

if ($Violations.Count) {
    $Violations | Sort-Object -Unique | ForEach-Object { Write-Error $_ }
    throw "Public-source policy failed with $($Violations.Count) finding(s)."
}

[pscustomobject][ordered]@{
    schema = 'katovpn.router_control.public_source_check.v1'
    files_checked = $paths.Count
    approved_hosts = $AllowedHosts.Count
    findings = 0
} | ConvertTo-Json
