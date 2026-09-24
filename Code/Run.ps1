#requires -Version 5.1
<# PostureKit | Lab version 0.6.
Launch collection locally or through an EXISTING approved WinRM route. Sequential
1-20 scoped systems, not an enterprise deployment service. No remoting setup,
credential persistence, automatic retries, downloads, or target remediation. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScopePath,
    [ValidateSet('Local','Remote')][string]$Mode = 'Local',
    [string]$AssetId,
    [string]$OutputRoot,
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateRange(30,900)][int]$TimeoutSeconds = 180,
    [ValidateRange(10,5000)][int]$MaxItems = 1000,
    [switch]$AuthorizedLabRun
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# $PSScriptRoot is EMPTY inside a param() default under Windows PowerShell 5.1 when invoked
# with powershell.exe -File. Resolve script-relative defaults in the body, not the param block.
$ScriptRoot = $PSScriptRoot
if (-not $ScriptRoot) { $ScriptRoot = Split-Path -Parent $PSCommandPath }
if (-not $ScriptRoot) { throw 'Unable to determine the package directory.' }
if (-not $OutputRoot) { $OutputRoot = Join-Path $ScriptRoot 'Evidence' }
. (Join-Path $ScriptRoot 'Common.ps1')
if (-not $AuthorizedLabRun) { throw 'Review code and scope, obtain lab approval, then supply -AuthorizedLabRun.' }
Assert-Windows
$scope = Read-Scope -Path $ScopePath -RequireApproval
$targets = @($scope.targets)
if ($Mode -eq 'Local' -and [string]::IsNullOrWhiteSpace($AssetId)) { throw 'Local mode requires -AssetId.' }
if ($AssetId) {
    $selected = @($targets | Where-Object { $_.asset_id -ceq $AssetId -and $_.enabled })
    if ($selected.Count -ne 1) { throw '-AssetId must exactly name one enabled scope entry.' }
    if ($Mode -eq 'Local' -and $selected[0].computer_name -ine $env:COMPUTERNAME) { throw 'The selected local target is not this computer.' }
}
$collector = Join-Path $ScriptRoot 'Collect.ps1'
$scopeHash = Get-Digest $ScopePath
$collectorHash = Get-Digest $collector
$batchId = [guid]::NewGuid().ToString('N')
$rawRoot = Join-Path $OutputRoot 'Raw'
New-Item -ItemType Directory -Path $rawRoot -Force -ErrorAction Stop | Out-Null
$dir = Join-Path $rawRoot $batchId
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $ScopePath -Destination (Join-Path $dir 'Scope.json') -ErrorAction Stop
$log = Join-Path $dir 'Run.log'
$ledger = New-Object 'System.Collections.Generic.List[object]'
$batch = [ordered]@{
    schema_version='1.0';evidence_kind='CollectionBatch';batch_id=$batchId;tool_version='0.6';
    engagement_id=$scope.engagement_id;mode=$Mode;selected_asset=$AssetId;
    scope_sha256=$scopeHash;collector_sha256=$collectorHash;
    launcher_sha256=(Get-Digest $PSCommandPath);common_sha256=(Get-Digest (Join-Path $ScriptRoot 'Common.ps1'));
    started_utc=[DateTime]::UtcNow.ToString('o');completed_utc=$null;
    timeout_seconds=$TimeoutSeconds;max_items=$MaxItems;targets=@()
}
foreach ($t in $targets) {
    $status = 'Pending'
    if (-not $t.enabled) { $status = 'Excluded' }
    elseif ($AssetId -and $t.asset_id -cne $AssetId) { $status = 'NotAttempted' }
    [void]$ledger.Add([pscustomobject]@{
        asset_id=$t.asset_id;site_id=$t.site_id;computer_name=$t.computer_name;connection_name=$t.connection_name;transport=$t.transport;
        status=$status;evidence_file=$null;evidence_sha256=$null;error=$null
    })
}
function Save-Batch {
    $batch.targets = @($ledger.ToArray())
    Write-Json -Path (Join-Path $dir 'Batch.json') -Value $batch
}
Save-Batch
Write-Host "Evidence batch: $dir"
Write-Host 'A STOP file in this batch folder prevents the next target starting. It does not interrupt an active provider.'
try {
    foreach ($entry in $ledger) {
        if ($entry.status -ne 'Pending') { continue }
        if (Test-Path -LiteralPath (Join-Path $dir 'STOP')) {
            $entry.status='NotAttempted';$entry.error='Operator stop requested before this target.'; Save-Batch; continue
        }
        $t = @($targets | Where-Object { $_.asset_id -ceq $entry.asset_id })[0]
        $session=$null; $job=$null
        Add-Content -LiteralPath $log -Value ('{0} START {1}' -f [DateTime]::UtcNow.ToString('o'),$entry.asset_id) -Encoding UTF8
        try {
            # Positional order matches Collect.ps1. Boolean consent is explicit and lab-only.
            $arguments = @([string]$scope.engagement_id,[string]$t.site_id,[string]$t.asset_id,
                $scopeHash,$collectorHash,$MaxItems,$true)
            if ($Mode -eq 'Local') {
                $job = Start-Job -FilePath $collector -ArgumentList $arguments -ErrorAction Stop
            } else {
                $options = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 60000
                $sessionArgs = @{ComputerName=[string]$t.connection_name;SessionOption=$options;ErrorAction='Stop';ConfigurationName='Microsoft.PowerShell'}
                if ($t.transport -eq 'Kerberos') {
                    $sessionArgs.Authentication='Kerberos'
                    if ($Credential) { $sessionArgs.Credential=$Credential }
                } else {
                    if (-not $Credential) { throw 'HttpsNegotiate requires an explicit approved PSCredential in this tool.' }
                    $sessionArgs.Authentication='Negotiate';$sessionArgs.UseSSL=$true;$sessionArgs.Credential=$Credential
                }
                $session = New-PSSession @sessionArgs
                $job = Invoke-Command -Session $session -FilePath $collector -ArgumentList $arguments -AsJob -ErrorAction Stop
            }
            $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if (-not $finished) { throw 'Collection wait expired. Cancellation will be attempted; verify target-side termination.' }
            if ($job.State -ne 'Completed') {
                # Surface provider/permission errors rather than a generic empty-result message.
                $null = Receive-Job -Job $job -ErrorAction Stop
                throw "Collection job ended in state: $($job.State)"
            }
            $output = @(Receive-Job -Job $job -ErrorAction Stop)
            $json = [string]::Join([Environment]::NewLine,[string[]]$output)
            if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 20971520) { throw 'Evidence exceeds 20 MiB; reduce collection scope and record the limitation.' }
            $raw = $json | ConvertFrom-Json -ErrorAction Stop
            if ($raw.schema_version -ne '1.0' -or $raw.tool_version -ne '0.6' -or
                $raw.evidence_kind -ne 'WindowsCollection' -or $raw.engagement_id -cne $scope.engagement_id -or
                $raw.asset_id -cne $t.asset_id -or $raw.site_id -cne $t.site_id -or
                $raw.host.computer_name -ine $t.computer_name -or $raw.scope_sha256 -cne $scopeHash -or
                $raw.collector_sha256 -cne $collectorHash -or $raw.collection_status -notin @('Complete','Partial')) {
                throw 'Returned evidence identity, version, scope, or collector digest mismatch.'
            }
            $name = 'Host.' + [string]$t.asset_id + '.json'
            $path = Join-Path $dir $name
            $json | Set-Content -LiteralPath $path -Encoding UTF8
            # A secondary source-status CSV; original JSON remains the authoritative raw output.
            $raw.sources | ForEach-Object {
                [pscustomobject]@{Source=$_.id;Status=$_.status;Retained=$_.retained_count;
                    Note=(ConvertTo-CsvText $_.note);Error=(ConvertTo-CsvText $_.error)}
            } | Export-Csv -LiteralPath (Join-Path $dir ('Sources.' + [string]$t.asset_id + '.csv')) -NoTypeInformation -Encoding UTF8
            $entry.evidence_file=$name; $entry.evidence_sha256=Get-Digest $path
            $entry.status=[string]$raw.collection_status
        } catch {
            $entry.status='Error';$entry.error=$_.Exception.Message
        } finally {
            if ($job) { Stop-Job -Job $job -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
            if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
            Add-Content -LiteralPath $log -Value ('{0} END {1} {2} {3}' -f [DateTime]::UtcNow.ToString('o'),$entry.asset_id,$entry.status,$entry.error) -Encoding UTF8
            Save-Batch
        }
    }
    $batch.completed_utc=[DateTime]::UtcNow.ToString('o')
} finally {
    Save-Batch
    $ledger | ForEach-Object {
        [pscustomobject]@{Asset=$_.asset_id;Site=$_.site_id;Computer=$_.computer_name;Connection=$_.connection_name;Transport=$_.transport;Status=$_.status;Evidence=$_.evidence_file;Error=(ConvertTo-CsvText $_.error)}
    } | Export-Csv -LiteralPath (Join-Path $dir 'Coverage.csv') -NoTypeInformation -Encoding UTF8
    Write-Manifest -Directory $dir
    # Seal raw artifacts against casual post-run edits. Start a new batch for any rerun; derived/manual files belong elsewhere.
    Get-ChildItem -LiteralPath $dir -File | ForEach-Object { try { $_.IsReadOnly=$true } catch {} }
}
Write-Host "Collection attempt finished: $dir"
Write-Host 'Inspect Batch.json and Coverage.csv; reaching this line is NOT a successful security assessment.'
Write-Host 'Files are plaintext. Use approved storage/transfer. Run Analyze.py on the approved analysis computer.'
