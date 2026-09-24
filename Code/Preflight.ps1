#requires -Version 5.1
<# Local prerequisite survey only. No remote host contact, no configuration changes.
Run after source review. The output is a prerequisite record, not a security verdict. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ScopePath,
      [Parameter(Mandatory=$true)][string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-Windows
$scope = Read-Scope -Path $ScopePath
if (Test-Path -LiteralPath $OutputPath) { throw 'Choose a new output filename.' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $id
$commands = @('Get-CimInstance','Get-NetFirewallProfile','Get-SmbServerConfiguration',
 'Get-SmbClientConfiguration','Get-LocalGroupMember','Get-LocalUser','Get-NetTCPConnection',
 'Get-NetUDPEndpoint','Get-NetIPAddress','Get-MpComputerStatus','Start-Job','New-PSSession','New-CimSession')
$availability = @($commands | ForEach-Object {
    $cmd = Get-Command $_ -ErrorAction SilentlyContinue
    [pscustomobject]@{command=$_; available=($null -ne $cmd)}
})
$providers = @('Win32_OperatingSystem','Win32_ComputerSystem')
$identityEvidence = @($providers | ForEach-Object {
    $class = $_
    try {
        $obj = Get-CimInstance -ClassName $class -OperationTimeoutSec 15 -ErrorAction Stop
        if ($class -eq 'Win32_OperatingSystem') { $data = $obj | Select-Object Caption,Version,BuildNumber,OSArchitecture,OSLanguage }
        else { $data = $obj | Select-Object Name,Domain,DomainRole,PartOfDomain }
        [pscustomobject]@{source=$class;status='Collected';data=$data;error=$null}
    } catch { [pscustomobject]@{source=$class;status='Error';data=$null;error=$_.Exception.Message} }
})
Write-Json -Path $OutputPath -Value ([ordered]@{
    schema_version='1.0';tool_version='0.6';evidence_kind='LocalPreflight';
    timestamp_utc=[DateTime]::UtcNow.ToString('o');computer_name=$env:COMPUTERNAME;
    powershell_version=$PSVersionTable.PSVersion.ToString();edition=$PSVersionTable.PSEdition;
    elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
    execution_identity=$id.Name;language_mode=$ExecutionContext.SessionState.LanguageMode.ToString();
    execution_policies=@(Get-ExecutionPolicy -List | Select-Object Scope,@{n='Policy';e={$_.ExecutionPolicy.ToString()}});
    scope_sha256=(Get-Digest $ScopePath);scope_approved=$scope.approved_for_lab;
    commands=$availability;host_sources=$identityEvidence;
    notes=@('No remote authentication or network reachability was tested.',
      'Unavailable optional providers reduce evidence; a local prerequisite check is not a fleet readiness result.',
      'Output creation is tested by writing this file. Storage capacity and ACLs need manual review.')
})
Write-Host "Local preflight written to $OutputPath"
