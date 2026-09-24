#requires -Version 5.1
<# PostureKit | Agentless CIM feasibility survey 0.6.
Read-only subset only. It does NOT equal the full Collect.ps1 coverage and does not install an agent.
Use only in an isolated/authorized lab or expressly authorized client scope. #>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ComputerName,
  [ValidateSet('Kerberos','Negotiate')][string]$Authentication='Kerberos',
  [System.Management.Automation.PSCredential]$Credential,
  [switch]$UseSsl,
  [Parameter(Mandatory=$true)][string]$OutputPath,
  [switch]$AuthorizedLabRun
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
if(-not $AuthorizedLabRun){throw 'Review and authorize this lab survey first.'}
if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Run from 64-bit Windows PowerShell 5.1 for initial validation.'}
$ip=$null
if([Net.IPAddress]::TryParse($ComputerName,[ref]$ip)){throw 'Use the approved DNS/host name rather than an IP literal.'}
if($Authentication -eq 'Negotiate' -and -not $Credential){throw 'Negotiate survey requires an explicit approved credential.'}
if(Test-Path -LiteralPath $OutputPath){throw 'Choose a new output file.'}
$opt=if($UseSsl){New-CimSessionOption -UseSsl}else{New-CimSessionOption -Protocol Wsman}
$args=@{ComputerName=$ComputerName;Authentication=$Authentication;SessionOption=$opt;OperationTimeoutSec=30;ErrorAction='Stop'}
if($Credential){$args.Credential=$Credential}
$session=$null
$rows=New-Object 'System.Collections.Generic.List[object]'
function Add-Result([string]$Id,[scriptblock]$Block,[string]$Limitation){
  try{$d=@(& $Block);[void]$rows.Add([pscustomobject]@{id=$Id;status='Collected';data=$d;error=$null;limitation=$Limitation})}
  catch{[void]$rows.Add([pscustomobject]@{id=$Id;status='Error';data=@();error=$_.Exception.Message;limitation=$Limitation})}
}
try{
  $session=New-CimSession @args
  Add-Result 'identity' { Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture,OSLanguage; Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem | Select Name,Domain,DomainRole,PartOfDomain } 'Identity subset.'
  Add-Result 'firewall' { Get-NetFirewallProfile -CimSession $session -PolicyStore ActiveStore | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction } 'Effective profile summary, not every rule.'
  Add-Result 'smbserver' { Get-SmbServerConfiguration -CimSession $session | Select EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData } 'Server-side SMB configuration.'
  Add-Result 'smbclient' { Get-SmbClientConfiguration -CimSession $session | Select RequireSecuritySignature,EnableInsecureGuestLogons } 'Client-side SMB configuration.'
  Add-Result 'connections' { Get-NetTCPConnection -CimSession $session | Where-Object {$_.State.ToString() -in @('Listen','Established')} | Select -First 500 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess } 'Bounded current TCP snapshot; not traffic history.'
  Add-Result 'addresses' { Get-NetIPAddress -CimSession $session | Select InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength,AddressFamily } 'Remote IP configuration.'
  Add-Result 'services' { Get-CimInstance -CimSession $session -ClassName Win32_Service | Select -First 1000 Name,State,StartMode } 'Service inventory subset.'
  [void]$rows.Add([pscustomobject]@{id='local_accounts';status='NotImplemented';data=@();error=$null;limitation='The native LocalAccounts cmdlets do not expose a CimSession parameter. Full host collection or another approved method is required.'})
  $doc=[ordered]@{schema_version='1.0';tool_version='0.6';evidence_kind='AgentlessCimSubset';computer_name=$ComputerName;authentication=$Authentication;use_ssl=[bool]$UseSsl;timestamp_utc=[DateTime]::UtcNow.ToString('o');sources=@($rows.ToArray());limitations=@('This is deliberately a reduced agentless subset, not a substitute for Collect.ps1.','No configuration changes are made.','WSMan/permissions/firewall/application-control prerequisites remain client-controlled.')}
  $doc|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $OutputPath -Encoding UTF8
} finally { if($session){Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue} }
Write-Host "Agentless CIM subset written to $OutputPath"
