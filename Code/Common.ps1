#requires -Version 5.1
<# Shared input/output helpers. Dot-sourcing only defines functions; it does not scan,
configure remoting or contact targets. version 0.6, PostureKit. #>
function Assert-Windows {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
        throw 'Use 64-bit Windows PowerShell 5.1 on an authorized Windows lab system.'
    }
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
        throw 'This tool targets Windows PowerShell 5.1 (powershell.exe), not pwsh. Other engines need separate validation.'
    }
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        throw 'Application control restricts this tool. Record the blocker; do not weaken policy.'
    }
}
function Test-Id {
    param([object]$Value)
    return ($Value -is [string] -and $Value -cmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
}
function Read-Scope {
    param([string]$Path, [switch]$RequireApproval)
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 1048576) { throw 'Scope is too large.' }
    $s = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($s.schema_version -ne '1.0' -or -not (Test-Id $s.engagement_id)) { throw 'Invalid scope schema or engagement identifier.' }
    if ($s.approved_for_lab -isnot [bool]) { throw 'approved_for_lab must be a JSON boolean.' }
    if ($RequireApproval -and -not $s.approved_for_lab) { throw 'Obtain approval, review the scope, then set approved_for_lab to true.' }
    if ($RequireApproval -and ([string]::IsNullOrWhiteSpace([string]$s.approval_reference) -or $s.approval_reference -eq 'UNAPPROVED')) {
        throw 'Record the real lab approval reference; the shipped scope is not approved.'
    }
    $targets = @($s.targets)
    if ($targets.Count -lt 1 -or $targets.Count -gt 20) { throw 'Require 1-20 explicit targets.' }
    $ids = @{}; $names = @{}
    foreach ($t in $targets) {
        foreach ($k in @('asset_id','site_id','computer_name')) {
            if (-not (Test-Id $t.$k)) { throw "Invalid target field: $k" }
        }
        if ($ids.ContainsKey([string]$t.asset_id)) { throw 'Asset identifiers must be unique, including case-insensitive duplicates.' }
        $ids[[string]$t.asset_id] = $true
        if ($t.enabled -isnot [bool]) { throw 'Each enabled flag must be a JSON boolean.' }
        if ($t.transport -notin @('Kerberos','HttpsNegotiate')) { throw 'Use Kerberos or HttpsNegotiate transport.' }
        if ($t.connection_name -isnot [string] -or $t.connection_name.Length -gt 253) { throw 'Invalid connection name.' }
        foreach ($label in $t.connection_name.Split('.')) {
            if ($label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { throw 'Use an exact host/DNS name without wildcards, URLs or shell expressions.' }
        }
        $ip = $null
        if ([Net.IPAddress]::TryParse($t.connection_name, [ref]$ip)) { throw 'Remote connection names must be host/DNS names, not IP literals.' }
        if ($t.enabled) {
            $key = ([string]$t.site_id) + '|' + ([string]$t.connection_name)
            if ($names.ContainsKey($key)) { throw 'The same enabled connection name appears twice in a site.' }
            $names[$key] = $true
        }
    }
    # Set-StrictMode 2.0 throws on a missing property, so test for presence before reading it.
    # An absent network block is valid and means network testing is not part of this scope;
    # Network.ps1 refuses to run in that case. A present block must still be explicit.
    if ($s.PSObject.Properties.Match('network').Count -gt 0 -and $null -ne $s.network) {
        if ($s.network.PSObject.Properties.Match('enabled').Count -eq 0 -or $s.network.enabled -isnot [bool]) { throw 'network.enabled must be a JSON boolean.' }
    }
    return $s
}
function Write-Json {
    param([string]$Path, [object]$Value, [int]$Depth = 14)
    # The caller owns the dedicated output folder. The temporary sibling is overwritten.
    $tmp = $Path + '.tmp'
    $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $tmp -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
}
function ConvertTo-CsvText {
    param([object]$Value)
    $text = [string]$Value
    if ($text -match '^[\s]*[=+@-]' -or $text -match '^[\t\r\n]') { return "'" + $text }
    return $text
}
function Get-Digest {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}
function Write-Manifest {
    param([string]$Directory)
    Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -notin @('Manifest.txt','Manifest.txt.tmp') } |
        Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-Digest $_.FullName), $_.Name } |
        Set-Content -LiteralPath (Join-Path $Directory 'Manifest.txt') -Encoding UTF8
}
