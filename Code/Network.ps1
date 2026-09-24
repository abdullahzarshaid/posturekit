#requires -Version 5.1
<# Optional lab-only TCP connection observations. No service payloads, discovery,
authentication or vulnerability inference. Use from the approved source only. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ScopePath,
      [Parameter(Mandatory=$true)][string]$OutputPath,
      [ValidateRange(250,5000)][int]$TimeoutMs=2000,
      [switch]$AuthorizedLabRun)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $AuthorizedLabRun) { throw 'Source review and lab approval are required.' }
Assert-Windows
$scope = Read-Scope -Path $ScopePath -RequireApproval
if (-not $scope.network.enabled) { throw 'Network mode is disabled in scope.' }
$source = @($scope.targets | Where-Object { $_.asset_id -ceq $scope.network.source_asset_id -and $_.enabled })
if ($source.Count -ne 1 -or $source[0].computer_name -ine $env:COMPUTERNAME) { throw 'This computer is not the approved network-test source.' }
if ([string]::IsNullOrWhiteSpace([string]$scope.network.source_context)) { throw 'Document the source network position.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Use a new evidence filename.' }
function Get-LabAddress {
    param([object]$Value)
    if ($Value -isnot [string]) { throw 'IP must be a string.' }
    $ip=$null
    if (-not [Net.IPAddress]::TryParse($Value,[ref]$ip)) { throw 'Only literal addresses are permitted; no DNS resolution or discovery.' }
    $b=$ip.GetAddressBytes(); $allowed=$false
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        # Reject ambiguous short/hex/leading-zero IPv4 forms accepted by some .NET versions.
        if ($ip.ToString() -cne $Value) { throw 'IPv4 must be canonical dotted decimal.' }
        $allowed=($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))
    } elseif ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        $allowed=(($b[0] -band 254) -eq 252 -and $ip.ScopeId -eq 0)
    }
    if (-not $allowed) { throw 'This reference implementation permits private IPv4 or IPv6 ULA addresses only.' }
    return $ip
}
$sourceIp = Get-LabAddress $scope.network.source_ip
$bound = @(Get-NetIPAddress | Where-Object { [Net.IPAddress]::Parse($_.IPAddress).Equals($sourceIp) })
if ($bound.Count -ne 1) { throw 'The source IP must identify exactly one configured local address.' }
$paths=@($scope.network.paths)
if ($scope.network.paths -isnot [array] -or $paths.Count -lt 1 -or $paths.Count -gt 32) { throw 'Require 1-32 explicitly approved IP/port pairs.' }
$seen=@{}
for ($i=0; $i -lt $paths.Count; $i++) {
    $p=$paths[$i]
    $ip=Get-LabAddress $p.target_ip
    if ($ip.AddressFamily -ne $sourceIp.AddressFamily) { throw 'Use separate scopes for IPv4 and IPv6 source positions.' }
    if ($p.port -isnot [int] -and $p.port -isnot [long]) { throw 'Port must be a JSON integer.' }
    if ($p.port -lt 1 -or $p.port -gt 65535 -or $p.expected -notin @('Reachable','Blocked')) { throw 'Invalid port or expected state.' }
    if ($p.PSObject.Properties['test_id'] -and -not [string]::IsNullOrWhiteSpace([string]$p.test_id)) {
        if (-not (Test-Id $p.test_id)) { throw 'Invalid network test_id.' }
    }
    $key=$ip.ToString()+':'+[string]$p.port
    if ($seen.ContainsKey($key)) { throw 'Duplicate network-test pair.' }
    $seen[$key]=$true
}
# Validate everything and make the output writable BEFORE any connection attempt.
$document=[ordered]@{schema_version='1.0';evidence_kind='NetworkObservations';tool_version='0.6';
    engagement_id=$scope.engagement_id;scope_sha256=(Get-Digest $ScopePath);script_sha256=(Get-Digest $PSCommandPath);
    started_utc=[DateTime]::UtcNow.ToString('o');completed_utc=$null;
    source_asset_id=$source[0].asset_id;source_site_id=$source[0].site_id;source_computer=$env:COMPUTERNAME;source_ip=$sourceIp.ToString();
    source_interface=$bound[0].InterfaceAlias;source_context=$scope.network.source_context;
    evidence_notice='Operator must verify the source VLAN/routes. No connection remains inconclusive. No automatic vulnerability or severity assignment.';
    results=@()}
$rows=New-Object 'System.Collections.Generic.List[object]'
for ($i=0; $i -lt $paths.Count; $i++) {
    $p=$paths[$i]
    $testId=if($p.PSObject.Properties['test_id'] -and -not [string]::IsNullOrWhiteSpace([string]$p.test_id)){[string]$p.test_id}else{'NET{0:D3}' -f ($i+1)}
    [void]$rows.Add([pscustomobject]@{test_id=$testId;target_ip=$p.target_ip;port=$p.port;expected=$p.expected;
        connected=$null;outcome='NotAttempted';local_endpoint=$null;elapsed_ms=$null;error=$null;timestamp_utc=$null})
}
$document.results=@($rows.ToArray())
Write-Json -Path $OutputPath -Value $document
foreach ($row in $rows) {
    $endpoint=New-Object -TypeName Net.IPEndPoint -ArgumentList @($sourceIp,0)
    $client=New-Object -TypeName Net.Sockets.TcpClient -ArgumentList $endpoint
    $async=$null; $row.connected=$false
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $async=$client.BeginConnect([Net.IPAddress]::Parse($row.target_ip),[int]$row.port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw 'TCP connection wait expired; cause not established.' }
        $client.EndConnect($async)
        $row.connected=$client.Connected
        if ($row.connected) { $row.local_endpoint=$client.Client.LocalEndPoint.ToString() }
    } catch { $row.error=$_.Exception.Message }
    finally { $client.Close(); if ($async) { $async.AsyncWaitHandle.Close() }; $watch.Stop() }
    $row.outcome='Inconclusive'
    if ($row.connected) { $row.outcome=if ($row.expected -eq 'Reachable') {'ExpectedReachable'} else {'UnexpectedReachable'} }
    $row.elapsed_ms=$watch.ElapsedMilliseconds; $row.timestamp_utc=[DateTime]::UtcNow.ToString('o')
    $document.results=@($rows.ToArray()); Write-Json -Path $OutputPath -Value $document
    Start-Sleep -Milliseconds 250
}
$document.completed_utc=[DateTime]::UtcNow.ToString('o')
Write-Json -Path $OutputPath -Value $document
Write-Host "TCP observations written to $OutputPath. Review separately; they are not host-rule findings."
