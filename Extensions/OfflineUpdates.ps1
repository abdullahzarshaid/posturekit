#requires -Version 5.1
<#
PostureKit | Research extension 0.6
LOCAL-ONLY lab module for Microsoft Windows Update Agent (WUA) offline applicability.
It does not install updates. It requires a current Microsoft-signed Wsusscn2.cab that the
operator has obtained through an approved channel. Do not run this through Run.ps1 until
remote-session behavior has been separately validated; Microsoft documents that
AddScanPackageService cannot be called from a remote computer.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CabPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$EngagementId,
    [Parameter(Mandatory=$true)][string]$SiteId,
    [Parameter(Mandatory=$true)][string]$AssetId,
    [Parameter(Mandatory=$true)][string]$ScopeHash,
    [switch]$AuthorizedLabRun
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if (-not $AuthorizedLabRun) { throw 'Review this extension, use an isolated Windows lab, then supply -AuthorizedLabRun.' }
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows.' }
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Validate with Windows PowerShell 5.1 first.' }
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Application control blocks this extension; do not weaken policy.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Choose a new output filename.' }
$cab=(Resolve-Path -LiteralPath $CabPath -ErrorAction Stop).Path
if ((Get-Item -LiteralPath $cab).PSIsContainer) { throw 'CabPath must be a file.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated lab session for this WUA experiment.' }
$signature=Get-AuthenticodeSignature -FilePath $cab
if ($signature.Status -ne 'Valid') { throw "The CAB signature is not Valid: $($signature.Status). Do not continue." }
$start=[DateTime]::UtcNow.ToString('o')
$serviceManager=$null; $service=$null
try {
    $session=New-Object -ComObject Microsoft.Update.Session
    $serviceManager=New-Object -ComObject Microsoft.Update.ServiceManager
    # Flags 0 requests a volatile scan-package registration. WUA also validates the CAB signature.
    $service=$serviceManager.AddScanPackageService('Offline Scan Package',$cab,0)
    $searcher=$session.CreateUpdateSearcher()
    $searcher.ServerSelection=3 # ssOthers
    $searcher.ServiceID=[string]$service.ServiceID
    $result=$searcher.Search("IsInstalled=0 and Type='Software'")
    $updates=New-Object 'System.Collections.Generic.List[object]'
    for ($i=0; $i -lt $result.Updates.Count; $i++) {
        $u=$result.Updates.Item($i)
        $kb=@(); foreach ($x in $u.KBArticleIDs) { $kb += [string]$x }
        $cats=@(); foreach ($c in $u.Categories) { $cats += [string]$c.Name }
        [void]$updates.Add([pscustomobject]@{
            Title=[string]$u.Title
            KBArticleIDs=$kb
            MsrcSeverity=[string]$u.MsrcSeverity
            Categories=$cats
            RebootRequired=[bool]$u.RebootRequired
            UpdateID=[string]$u.Identity.UpdateID
            RevisionNumber=[int]$u.Identity.RevisionNumber
        })
    }
    $doc=[ordered]@{
        schema_version='1.0';tool_version='0.6';evidence_kind='WuaOfflineUpdateApplicability';
        engagement_id=$EngagementId;site_id=$SiteId;asset_id=$AssetId;scope_sha256=$ScopeHash;
        started_utc=$start;completed_utc=[DateTime]::UtcNow.ToString('o');computer_name=$env:COMPUTERNAME;
        execution_identity=$identity.Name;cab_path=$cab;cab_sha256=(Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash.ToLowerInvariant();
        cab_signature_status=$signature.Status.ToString();cab_signer_subject=if($signature.SignerCertificate){$signature.SignerCertificate.Subject}else{$null};
        missing_applicable_count=$updates.Count;updates=@($updates.ToArray());
        limitations=@(
          'This is a lab research extension, not production-approved code.',
          'Wsusscn2.cab covers Microsoft security-related update metadata; it is not a third-party vulnerability feed.',
          'A missing applicable update is evidence for patch/update review, not automatic proof of exploitability.',
          'Microsoft warns offline scans can use substantial memory.',
          'Remote-session execution has not been validated and may be blocked by WUA API restrictions.'
        )
    }
    $doc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "WUA offline applicability evidence written to $OutputPath"
} finally {
    if ($serviceManager -and $service) {
        try { $serviceManager.RemoveService([string]$service.ServiceID) } catch { Write-Warning "Could not remove the temporary WUA scan service registration: $($_.Exception.Message)" }
    }
}
