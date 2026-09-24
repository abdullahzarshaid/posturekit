#requires -Version 5.1
<#
PostureKit | version 0.6
Read-only Windows evidence collector. No remediation, downloads, remote discovery,
credential collection or CVE assertions. Standard output is one JSON document.
Target: 64-bit Windows PowerShell 5.1. Windows execution is NOT yet validated.
Review Readme.txt before use. Use Run.ps1 for normal lab execution.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$EngagementId,
    [Parameter(Mandatory=$true)][string]$SiteId,
    [Parameter(Mandatory=$true)][string]$AssetId,
    [Parameter(Mandatory=$true)][string]$ScopeHash,
    [Parameter(Mandatory=$true)][string]$CollectorHash,
    [ValidateRange(10,5000)][int]$MaxItems = 1000,
    [bool]$AuthorizedLabRun = $false
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (-not $AuthorizedLabRun) { throw 'Use the reviewed Run.ps1 lab launcher with explicit authorization.' }
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) { throw 'Use Windows PowerShell 5.1; other engines need separate validation.' }
if ($env:OS -ne 'Windows_NT') { throw 'This collector requires Windows; no Windows collection was performed.' }
if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'FullLanguage is required by this tool. Do not weaken application control; record the blocker.'
}
$start = [DateTime]::UtcNow.ToString('o')
$records = New-Object 'System.Collections.Generic.List[object]'

function Capture {
    param([string]$Id, [string[]]$Commands, [scriptblock]$Read, [string]$Note = '')
    $item = [ordered]@{ id=$Id; status='Collected'; started_utc=[DateTime]::UtcNow.ToString('o');
        completed_utc=$null; data=@(); returned_count=0; retained_count=0; note=$Note; error=$null }
    try {
        foreach ($command in $Commands) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
                $item.status='Unsupported'; $item.error="Required command unavailable: $command"; break
            }
        }
        if ($item.status -eq 'Collected') {
            $values = New-Object 'System.Collections.Generic.List[object]'
            $counter = @{count=0}
            & $Read | ForEach-Object {
                $counter.count++
                if ($values.Count -lt $MaxItems) { [void]$values.Add($_) }
            }
            $item.returned_count = $counter.count
            $item.data = @($values.ToArray())
            $item.retained_count = $item.data.Count
            if ($counter.count -gt $MaxItems) {
                $item.status='Partial'; $item.note += " Retained only $MaxItems records; no completeness claim."
            }
        }
    } catch {
        $item.status='Error'; $item.error=$_.Exception.Message; $item.data=@(); $item.returned_count=0; $item.retained_count=0
    }
    $item.completed_utc=[DateTime]::UtcNow.ToString('o')
    [void]$records.Add([pscustomobject]$item)
}
function NotApplicable {
    param([string]$Id,[string]$Reason)
    [void]$records.Add([pscustomobject]@{id=$Id;status='NotApplicable';started_utc=[DateTime]::UtcNow.ToString('o');
      completed_utc=[DateTime]::UtcNow.ToString('o');data=@();returned_count=0;retained_count=0;note=$Reason;error=$null})
}

# These identity queries are mandatory: a failure stops the host collection.
$os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 20
$machine = Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 20
$productUuid=$null; $machineGuid=$null
$regBuild=$null; $regUbr=$null; $regFullBuild=$null; $regDisplay=$null
try {
    $cvKey = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $regBuild   = [string]$cvKey.CurrentBuild
    $regUbr     = $cvKey.UBR
    $regDisplay = [string]$cvKey.DisplayVersion
    if ($regBuild -and $null -ne $regUbr) { $regFullBuild = "10.0.$regBuild.$regUbr" }
} catch {}
try { $productUuid=[string](Get-CimInstance -ClassName Win32_ComputerSystemProduct -OperationTimeoutSec 20 -ErrorAction Stop).UUID } catch {}
try { $machineGuid=[string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch {}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isDc = ([int]$machine.DomainRole -in @(4,5))

Capture 'firewall' @('Get-NetFirewallProfile') {
    Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,
      @{n='Enabled';e={$_.Enabled.ToString()}}, @{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}},
      @{n='DefaultOutboundAction';e={$_.DefaultOutboundAction.ToString()}}
} 'ActiveStore profile configuration. Does not validate every rule, interface or actual traffic enforcement.'
Capture 'smbserver' @('Get-SmbServerConfiguration') {
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData
} 'Server-side configuration only; client SMB1 and protocol negotiation are separate checks.'
Capture 'smbclient' @('Get-SmbClientConfiguration') {
    Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableInsecureGuestLogons
} 'Client-side configuration. No authentication or access attempt is made.'
Capture 'rdp' @('Get-CimInstance','Get-ItemProperty') {
    $providerError=$null
    try {
        $service = @(Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TerminalServiceSetting -OperationTimeoutSec 20 -ErrorAction Stop)
        if ($service.Count -ne 1) { throw 'Expected one terminal-service settings object.' }
        $settings = @(Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" -OperationTimeoutSec 20 -ErrorAction Stop)
        $nla=$null; $origin=$null
        if ($settings.Count -eq 1) { $nla=$settings[0].UserAuthenticationRequired; $origin=$settings[0].PolicySourceUserAuthenticationRequired }
        [pscustomobject]@{ EvidenceMethod='TerminalServicesWmi'; AllowTSConnections=[int]$service[0].AllowTSConnections;
          UserAuthenticationRequired=if($null -ne $nla){[int]$nla}else{$null};
          PolicySourceUserAuthenticationRequired=$origin; ListenerObjects=$settings.Count; ProviderError=$null }
    } catch {
        $providerError=$_.Exception.Message
        # Fallback for editions/builds where the TerminalServices WMI namespace/provider is unavailable.
        # fDenyTSConnections: 0 = RDP enabled, 1 = RDP denied. UserAuthentication: 1 = NLA required.
        $ts=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
        $rdp=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue
        $policy=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
        $allow=if([int]$ts.fDenyTSConnections -eq 0){1}else{0}
        $nla=$null; $origin='LocalConfiguration'
        if ($policy -and $policy.PSObject.Properties['UserAuthentication']) { $nla=[int]$policy.UserAuthentication; $origin='Policy' }
        elseif ($rdp -and $rdp.PSObject.Properties['UserAuthentication']) { $nla=[int]$rdp.UserAuthentication }
        [pscustomobject]@{ EvidenceMethod='RegistryFallback'; AllowTSConnections=$allow;
          UserAuthenticationRequired=$nla; PolicySourceUserAuthenticationRequired=$origin;
          ListenerObjects=$null; ProviderError=$providerError }
    }
} 'Read-only RDP configuration. The WMI provider is preferred; documented registry settings are used as a fallback. This does not prove TCP/3389 reachability.'
Capture 'uac' @('Get-ItemProperty') {
    Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA |
      Select-Object EnableLUA
} 'Configured EnableLUA value only. A pending restart or other runtime controls are not evaluated.'
if ($isDc) {
    NotApplicable 'localadmins' 'Domain controller: local SAM administrator enumeration is not used. Directory privilege assessment is separate.'
    NotApplicable 'localguest' 'Domain controller: local SAM guest check is not used. Domain accounts require separate rules.'
} else {
    Capture 'localadmins' @('Get-LocalGroupMember') {
        Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,ObjectClass,
          @{n='SID';e={$_.SID.Value}},@{n='PrincipalSource';e={if ($null -ne $_.PrincipalSource) {$_.PrincipalSource.ToString()} else {$null}}}
    } 'Direct membership only; does not expand nested domain groups or classify members as authorized.'
    Capture 'localguest' @('Get-LocalUser') {
        Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } |
          Select-Object Name,Enabled,@{n='SID';e={$_.SID.Value}}
    } 'Built-in local guest selected by RID, not its localized display name.'
}
Capture 'tcplisteners' @('Get-NetTCPConnection','Get-Process') {
    $names=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id]=[string]$_.ProcessName }
    Get-NetTCPConnection | Where-Object { $_.State.ToString() -eq 'Listen' } | ForEach-Object {
      [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess;
        ProcessName=if($names.ContainsKey([int]$_.OwningProcess)){$names[[int]$_.OwningProcess]}else{$null}}
    }
} 'A local listener is not proof of remote exposure or a vulnerability. Process names are best-effort; command lines and executable paths are not collected.'
Capture 'udpendpoints' @('Get-NetUDPEndpoint','Get-Process') {
    $names=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id]=[string]$_.ProcessName }
    Get-NetUDPEndpoint | ForEach-Object {
      [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess;
        ProcessName=if($names.ContainsKey([int]$_.OwningProcess)){$names[[int]$_.OwningProcess]}else{$null}}
    }
} 'Local endpoint inventory; no UDP probes are sent. Process names are best-effort.'
Capture 'connections' @('Get-NetTCPConnection','Get-Process') {
    $names=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id]=[string]$_.ProcessName }
    Get-NetTCPConnection | Where-Object { $_.State.ToString() -eq 'Established' } | ForEach-Object {
      [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;
        OwningProcess=$_.OwningProcess;ProcessName=if($names.ContainsKey([int]$_.OwningProcess)){$names[[int]$_.OwningProcess]}else{$null}}
    }
} 'Point-in-time snapshot, not history or network-wide passive monitoring. No payloads, command lines or executable paths are collected.'
Capture 'software' @('Get-ChildItem','Get-ItemProperty') {
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                       'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath
                if ($p.PSObject.Properties['DisplayName'] -and $p.DisplayName) {
                    $v=$null; $pub=$null
                    if ($p.PSObject.Properties['DisplayVersion']) {$v=$p.DisplayVersion}
                    if ($p.PSObject.Properties['Publisher']) {$pub=$p.Publisher}
                    [pscustomobject]@{Name=$p.DisplayName;Version=$v;Publisher=$pub;RegistryRoot=$root}
                }
            }
        }
    }
} 'Machine uninstall registry only. Omits user-only, portable and other unregistered software. No Win32_Product query.'
Capture 'hotfixes' @('Get-CimInstance') {
    Get-CimInstance -ClassName Win32_QuickFixEngineering -OperationTimeoutSec 20 |
      Select-Object HotFixID,Description,@{n='InstalledOn';e={[string]$_.InstalledOn}}
} 'Limited update inventory only. No missing-update, support-lifecycle or CVE conclusion is made.'
Capture 'addresses' @('Get-NetIPAddress') {
    Get-NetIPAddress | Select-Object InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength,
      @{n='AddressFamily';e={$_.AddressFamily.ToString()}}
} 'Local address inventory. Does not discover or authorize other subnets.'
Capture 'defender' @('Get-MpComputerStatus') {
    Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,
      AntivirusSignatureVersion,@{n='AntivirusSignatureLastUpdated';e={if ($null -ne $_.AntivirusSignatureLastUpdated) {([DateTime]$_.AntivirusSignatureLastUpdated).ToUniversalTime().ToString('o')} else {$null}}}
} 'Microsoft Defender only. Absence or disabled state is not automatically missing third-party endpoint protection.'
Capture 'services' @('Get-CimInstance') {
    Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 20 |
      Select-Object Name,DisplayName,State,StartMode,StartName,PathName,
        @{n='UnquotedPath';e={
            $p=[string]$_.PathName
            ($p -and $p.Trim() -notmatch '^"' -and $p -match '^[A-Za-z]:\\[^"]* [^"]*' -and $p -notmatch '^[A-Za-z]:\\Windows\\')
        }}
} 'Service inventory with binary path and logon account. The UnquotedPath flag is a candidate only: it does not test directory permissions and is not by itself an exploitable finding. No service was started, stopped or modified.'

# ---------------------------------------------------------------------------
# Security configuration sources. All read-only registry / built-in queries.
# Absence of a registry value is itself evidence: it means the OS default
# applies. These record the observed value or $null; they never interpret.
# ---------------------------------------------------------------------------
function Get-RegValue {
    param([string]$Path,[string]$Name)
    try { $k = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop; return $k.$Name } catch { return $null }
}

Capture 'patchlevel' @('Get-ItemProperty') {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = Get-RegValue $cv 'CurrentBuild'
    $ubr   = Get-RegValue $cv 'UBR'
    [pscustomobject]@{
        CurrentBuild     = $build
        UBR              = $ubr
        FullBuild        = if ($null -ne $build -and $null -ne $ubr) { "10.0.$build.$ubr" } else { $null }
        DisplayVersion   = Get-RegValue $cv 'DisplayVersion'
        ReleaseId        = Get-RegValue $cv 'ReleaseId'
        ProductName      = Get-RegValue $cv 'ProductName'
        InstallationType = Get-RegValue $cv 'InstallationType'
    }
} 'Exact servicing level. FullBuild is the authoritative patch state for Windows 10/11 and Server 2016+; the hotfix list is not, because Win32_QuickFixEngineering omits cumulative updates. Missing-patch determination is performed off-host against vendor data.'

Capture 'lsa' @('Get-ItemProperty') {
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    [pscustomobject]@{
        RunAsPPL             = Get-RegValue $p 'RunAsPPL'
        RunAsPPLBoot         = Get-RegValue $p 'RunAsPPLBoot'
        NoLMHash             = Get-RegValue $p 'NoLMHash'
        LmCompatibilityLevel = Get-RegValue $p 'LmCompatibilityLevel'
        RestrictAnonymous    = Get-RegValue $p 'RestrictAnonymous'
        RestrictAnonymousSAM = Get-RegValue $p 'RestrictAnonymousSAM'
        DisableDomainCreds   = Get-RegValue $p 'DisableDomainCreds'
    }
} 'LSA protection and legacy authentication settings. A null value means the key is absent and the OS default applies.'

Capture 'wdigest' @('Get-ItemProperty') {
    [pscustomobject]@{ UseLogonCredential = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' }
} 'WDigest credential caching. 1 causes cleartext credentials to be held in LSASS. Null or 0 is the safe modern default.'

Capture 'logonpolicy' @('Get-ItemProperty') {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $pw = Get-RegValue $p 'DefaultPassword'
    [pscustomobject]@{
        CachedLogonsCount        = Get-RegValue $p 'CachedLogonsCount'
        AutoAdminLogon           = Get-RegValue $p 'AutoAdminLogon'
        DefaultUserName          = Get-RegValue $p 'DefaultUserName'
        DefaultDomainName        = Get-RegValue $p 'DefaultDomainName'
        DefaultPasswordIsPresent = [bool]($null -ne $pw -and [string]$pw -ne '')
    }
} 'Interactive logon policy. The stored autologon password is deliberately NOT collected; only whether one is present is recorded.'

Capture 'nameresolution' @('Get-ItemProperty') {
    $nb = @()
    try {
        $nb = Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop |
              ForEach-Object { [pscustomobject]@{ Interface=$_.PSChildName; NetbiosOptions=(Get-RegValue $_.PSPath 'NetbiosOptions') } }
    } catch {}
    [pscustomobject]@{
        LlmnrEnableMulticast = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        NetbiosInterfaces    = @($nb)
    }
} 'LLMNR and NetBIOS name resolution. A null LlmnrEnableMulticast means no policy is set and LLMNR remains enabled by default. NetbiosOptions 2 is disabled.'

Capture 'installerpolicy' @('Get-ItemProperty') {
    [pscustomobject]@{
        MachineAlwaysInstallElevated = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
        UserAlwaysInstallElevated    = Get-RegValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    }
} 'Windows Installer elevation policy. Both values set to 1 permits any user to install as SYSTEM. The user-side value reflects the collecting account only.'

Capture 'powershelllogging' @('Get-ItemProperty') {
    $b = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    [pscustomobject]@{
        EnableScriptBlockLogging = Get-RegValue "$b\ScriptBlockLogging" 'EnableScriptBlockLogging'
        EnableModuleLogging      = Get-RegValue "$b\ModuleLogging" 'EnableModuleLogging'
        EnableTranscripting      = Get-RegValue "$b\Transcription" 'EnableTranscripting'
        TranscriptOutputDirectory= Get-RegValue "$b\Transcription" 'OutputDirectory'
    }
} 'PowerShell audit logging policy. Null means no policy is configured, so the capability is not enabled.'

Capture 'uacpolicy' @('Get-ItemProperty') {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    [pscustomobject]@{
        EnableLUA                    = Get-RegValue $p 'EnableLUA'
        ConsentPromptBehaviorAdmin   = Get-RegValue $p 'ConsentPromptBehaviorAdmin'
        ConsentPromptBehaviorUser    = Get-RegValue $p 'ConsentPromptBehaviorUser'
        FilterAdministratorToken     = Get-RegValue $p 'FilterAdministratorToken'
        LocalAccountTokenFilterPolicy= Get-RegValue $p 'LocalAccountTokenFilterPolicy'
    }
} 'User Account Control policy detail beyond the EnableLUA master switch.'

Capture 'smb1driver' @('Get-ItemProperty') {
    [pscustomobject]@{
        Mrxsmb10Start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
        LanmanWorkstationDependOn = @(Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' 'DependOnService')
    }
} 'SMBv1 client driver state. Start 4 is disabled. This complements the server-side EnableSMB1Protocol value.'

Capture 'autorunpolicy' @('Get-ItemProperty') {
    [pscustomobject]@{
        NoDriveTypeAutoRun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
        NoAutorun          = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun'
    }
} 'AutoRun / AutoPlay policy for removable media.'

Capture 'laps' @('Get-ItemProperty') {
    $roots = @(
        @{n='WindowsLapsCsp'; p='HKLM:\Software\Microsoft\Policies\LAPS'},
        @{n='WindowsLapsGpo'; p='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'},
        @{n='WindowsLapsLocal';p='HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config'},
        @{n='LegacyAdmPwd';   p='HKLM:\Software\Policies\Microsoft Services\AdmPwd'}
    )
    $found = @()
    foreach ($r in $roots) { if (Test-Path -LiteralPath $r.p) { $found += $r.n } }
    [pscustomobject]@{ ConfiguredRoots = @($found); AnyLapsConfigured = [bool]($found.Count -gt 0) }
} 'Local Administrator Password Solution configuration presence, checked across the Windows LAPS and legacy AdmPwd registry roots. Presence of a root is not proof the policy is applied.'

Capture 'passwordpolicy' @('Get-CimInstance') {
    $d = Get-CimInstance -ClassName Win32_AccountUsingSecuritySettings -ErrorAction SilentlyContinue
    $out = [ordered]@{ MinimumPasswordLength=$null; MaximumPasswordAge=$null; MinimumPasswordAge=$null
                       PasswordHistoryLength=$null; LockoutThreshold=$null; Source='net accounts' }
    try {
        $na = & "$env:SystemRoot\System32\net.exe" accounts 2>$null
        foreach ($line in $na) {
            if ($line -match '^\s*Minimum password length\s*:\s*(\S+)')  { $out.MinimumPasswordLength = $Matches[1] }
            if ($line -match '^\s*Maximum password age.*:\s*(\S+)')      { $out.MaximumPasswordAge    = $Matches[1] }
            if ($line -match '^\s*Minimum password age.*:\s*(\S+)')      { $out.MinimumPasswordAge    = $Matches[1] }
            if ($line -match '^\s*Length of password history.*:\s*(\S+)'){ $out.PasswordHistoryLength = $Matches[1] }
            if ($line -match '^\s*Lockout threshold\s*:\s*(\S+)')        { $out.LockoutThreshold      = $Matches[1] }
        }
    } catch {}
    [pscustomobject]$out
} 'Local account password policy. Parsed from the built-in net accounts output, so the field labels are English-locale dependent; on a non-English host these values may be null and must not be read as a finding. Domain policy is not represented here.'

Capture 'bootintegrity' @('Get-CimInstance') {
    $sb = $null
    try { $sb = Confirm-SecureBootUEFI } catch { $sb = $null }
    $bl = $null
    try {
        $bl = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop |
              Select-Object DriveLetter,ProtectionStatus,ConversionStatus
    } catch { $bl = $null }
    [pscustomobject]@{ SecureBootEnabled = $sb; EncryptableVolumes = @($bl) }
} 'Secure Boot and volume encryption state. Both queries require elevation; a null value on a non-elevated run means not determined, not disabled.'

# ---------------------------------------------------------------------------
# Active Directory evidence. Read-only LDAP reads through System.DirectoryServices,
# which is present on every Windows host - no RSAT or ActiveDirectory module is
# required. On a workgroup host every source records NotApplicable rather than
# an error, because the absence of a domain is a fact, not a failure.
# Nothing here enumerates attack paths; directory attack-path assessment is a
# separate workstream.
# ---------------------------------------------------------------------------
$adReason = 'Host is not domain joined. Directory evidence does not apply.'

function Get-DomainRoot {
    # Returns the domain's root directory entry, or $null when unavailable.
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        return $dom.GetDirectoryEntry()
    } catch { return $null }
}

if (-not $machine.PartOfDomain) {
    NotApplicable 'domainidentity'        $adReason
    NotApplicable 'domainpolicy'          $adReason
    NotApplicable 'domainprivilegedgroups' $adReason
    NotApplicable 'domaintrusts'          $adReason
    NotApplicable 'kerberospolicy'        $adReason
    NotApplicable 'gpoapplied'            $adReason
} else {

Capture 'domainidentity' @('Get-CimInstance') {
    $d = $null
    try { $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() } catch {}
    $f = $null
    try { $f = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() } catch {}
    [pscustomobject]@{
        DomainName            = if ($d) { [string]$d.Name } else { [string]$machine.Domain }
        ForestName            = if ($f) { [string]$f.Name } else { $null }
        DomainMode            = if ($d) { [string]$d.DomainMode } else { $null }
        ForestMode            = if ($f) { [string]$f.ForestMode } else { $null }
        DomainControllerUsed  = if ($d) { [string]$d.FindDomainController().Name } else { $null }
        DomainControllerCount = if ($d) { @($d.DomainControllers).Count } else { $null }
        ChildDomainCount      = if ($d) { @($d.Children).Count } else { $null }
    }
} 'Directory identity and functional level. Functional level constrains which security features are available; a low level is a configuration observation, not a vulnerability by itself.'

Capture 'domainpolicy' @('Get-CimInstance') {
    $root = Get-DomainRoot
    if ($null -eq $root) { throw 'The domain root object could not be read with the collecting account.' }
    function Sec([object]$v) {
        # AD stores these intervals as negative 100-nanosecond values.
        if ($null -eq $v) { return $null }
        try { $n = [int64]$v } catch { return $null }
        if ($n -eq 0 -or $n -eq -9223372036854775808) { return 0 }
        return [math]::Round([math]::Abs($n) / 10000000)
    }
    [pscustomobject]@{
        MinimumPasswordLength   = [int]$root.Properties['minPwdLength'].Value
        PasswordHistoryLength   = [int]$root.Properties['pwdHistoryLength'].Value
        MaximumPasswordAgeDays  = [math]::Round((Sec $root.Properties['maxPwdAge'].Value) / 86400, 1)
        MinimumPasswordAgeDays  = [math]::Round((Sec $root.Properties['minPwdAge'].Value) / 86400, 1)
        LockoutThreshold        = [int]$root.Properties['lockoutThreshold'].Value
        LockoutDurationMinutes  = [math]::Round((Sec $root.Properties['lockoutDuration'].Value) / 60, 1)
        LockoutWindowMinutes    = [math]::Round((Sec $root.Properties['lockOutObservationWindow'].Value) / 60, 1)
        PasswordComplexityFlags = [int]$root.Properties['pwdProperties'].Value
        MachineAccountQuota     = [int]$root.Properties['ms-DS-MachineAccountQuota'].Value
    }
} 'Default domain password and lockout policy read from the domain root. Fine-grained password policies applied to specific groups are NOT represented here and must be reviewed separately. MachineAccountQuota above zero allows any authenticated user to join machines to the domain.'

Capture 'domainprivilegedgroups' @('Get-CimInstance') {
    $root = Get-DomainRoot
    if ($null -eq $root) { throw 'The domain root object could not be read with the collecting account.' }
    $dn = [string]$root.Properties['distinguishedName'].Value
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.PageSize = 200
    $searcher.SizeLimit = 2000
    # Well-known privileged groups by RID, resolved through the domain SID.
    $rids = @{ 512='Domain Admins'; 519='Enterprise Admins'; 518='Schema Admins';
               548='Account Operators'; 551='Backup Operators'; 544='Administrators';
               550='Print Operators'; 549='Server Operators' }
    $out = @()
    foreach ($rid in $rids.Keys) {
        $searcher.Filter = "(&(objectClass=group)(objectSid=*-$rid))"
        $found = $null
        try { $found = $searcher.FindOne() } catch {}
        if ($null -eq $found) { continue }
        $members = @()
        try { $members = @($found.Properties['member'] | ForEach-Object { [string]$_ }) } catch {}
        $out += [pscustomobject]@{
            GroupName    = $rids[$rid]
            Rid          = $rid
            MemberCount  = $members.Count
            Members      = @($members | Select-Object -First 60)
            Truncated    = ($members.Count -gt 60)
        }
    }
    $out
} 'Membership of well-known privileged directory groups, resolved by relative identifier so a renamed group is still found. Nested group membership is NOT expanded, so the real effective count may be higher. Membership is not itself a finding; excessive or stale membership is, and that requires client confirmation.'

Capture 'domaintrusts' @('Get-CimInstance') {
    $d = $null
    try { $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() } catch {}
    if ($null -eq $d) { throw 'The current domain could not be resolved with the collecting account.' }
    $out = @()
    foreach ($rel in @($d.GetAllTrustRelationships())) {
        $out += [pscustomobject]@{
            SourceName      = [string]$rel.SourceName
            TargetName      = [string]$rel.TargetName
            TrustDirection  = [string]$rel.TrustDirection
            TrustType       = [string]$rel.TrustType
        }
    }
    if ($out.Count -eq 0) { [pscustomobject]@{ SourceName=[string]$d.Name; TargetName=$null; TrustDirection='None'; TrustType='NoTrustsFound' } } else { $out }
} 'Trust relationships visible from this domain. SID filtering and selective authentication state are NOT read here and must be confirmed separately before any trust is described as a risk.'

Capture 'kerberospolicy' @('Get-CimInstance') {
    $root = Get-DomainRoot
    if ($null -eq $root) { throw 'The domain root object could not be read with the collecting account.' }
    $dn = [string]$root.Properties['distinguishedName'].Value
    $policy = $null
    try {
        $policy = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$dn")
        $null = $policy.Guid
    } catch { $policy = $null }
    [pscustomobject]@{
        DefaultDomainPolicyReadable = ($null -ne $policy)
        DefaultDomainPolicyPath     = if ($policy) { [string]$policy.Path } else { $null }
        SupportedEncryptionTypes    = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' 'SupportedEncryptionTypes'
        RequireStrongKey            = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireStrongKey'
        RequireSignOrSeal           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireSignOrSeal'
        SealSecureChannel           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SealSecureChannel'
    }
} 'Kerberos and secure-channel settings as they apply to this host. Ticket lifetime policy lives inside the Default Domain Policy Group Policy object and is not parsed here; this records only whether that object is readable, plus the host-side encryption and secure-channel values.'

Capture 'gpoapplied' @('Get-ItemProperty') {
    # The History hive records the last successful policy application, keyed by
    # client-side extension. The same policy object appears under every extension
    # that processed it, so the same name is collected several times and must be
    # reduced to one entry per policy.
    $seen = @{}
    $out = @()
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History'
    $entries = @()
    try {
        $entries = Get-ChildItem -LiteralPath $root -ErrorAction Stop |
                   ForEach-Object { Get-ChildItem -LiteralPath $_.PSPath -ErrorAction SilentlyContinue }
    } catch {}
    foreach ($entry in $entries) {
        $name = Get-RegValue $entry.PSPath 'DisplayName'
        if (-not $name) { continue }
        $id = [string](Get-RegValue $entry.PSPath 'GPOName')
        $key = [string]$name + '|' + $id
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $out += [pscustomobject]@{
            Scope       = 'Machine'
            DisplayName = [string]$name
            GpoId       = $id
            FileSysPath = [string](Get-RegValue $entry.PSPath 'FileSysPath')
            Version     = Get-RegValue $entry.PSPath 'Version'
        }
    }
    if ($out.Count -eq 0) {
        [pscustomobject]@{ Scope='Machine'; DisplayName=$null; GpoId=$null; FileSysPath=$null; Version=$null }
    } else { $out }
} 'Computer-scope Group Policy objects recorded as applied to this host, reduced to one entry per policy. This is the local record of the last successful application, not a live read from the directory, and it does not show which settings each object contains. Per-user policy is NOT collected: it is recorded per user profile and the collecting account is not necessarily a user of this host.'

}

# ---------------------------------------------------------------------------
# Additional security configuration. All read-only, none requires elevation.
# ---------------------------------------------------------------------------

Capture 'updatesource' @('Get-ItemProperty') {
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $server = Get-RegValue $wu 'WUServer'
    [pscustomobject]@{
        UseWUServer        = Get-RegValue "$wu\AU" 'UseWUServer'
        WUServer           = [string]$server
        WUStatusServer     = [string](Get-RegValue $wu 'WUStatusServer')
        WUServerScheme     = if ($server -match '^(?i)(https?)://') { $Matches[1].ToLower() } else { $null }
        ProxyBehaviour     = Get-RegValue $wu 'SetProxyBehaviorForUpdateDetection'
        TlsPinningDisabled = Get-RegValue $wu 'DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection'
    }
} 'Windows Update source. WUServer only takes effect when UseWUServer is 1; otherwise it is inert and must not be reported. An http:// update server allows an attacker on the path to supply content that installs with SYSTEM privileges.'

Capture 'pointandprint' @('Get-ItemProperty') {
    $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    $spooler = $null
    try { $spooler = Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -OperationTimeoutSec 20 | Select-Object -First 1 } catch {}
    [pscustomobject]@{
        SpoolerState                            = if ($spooler) { [string]$spooler.State } else { $null }
        SpoolerStartMode                        = if ($spooler) { [string]$spooler.StartMode } else { $null }
        RestrictDriverInstallationToAdministrators = Get-RegValue $pp 'RestrictDriverInstallationToAdministrators'
        NoWarningNoElevationOnInstall           = Get-RegValue $pp 'NoWarningNoElevationOnInstall'
        UpdatePromptSettings                    = Get-RegValue $pp 'UpdatePromptSettings'
    }
} 'Print spooler and Point and Print driver installation policy. Microsoft states that no combination of other mitigations is equivalent to restricting driver installation to administrators.'

Capture 'winrmconfig' @('Get-ItemProperty') {
    $s = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $c = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    $th = $null
    try { $th = (Get-Item -LiteralPath 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction Stop).Value } catch {}
    [pscustomobject]@{
        ServiceAllowUnencryptedTraffic = Get-RegValue $s 'AllowUnencryptedTraffic'
        ServiceAllowBasic              = Get-RegValue $s 'AllowBasic'
        ServiceAllowCredSSP            = Get-RegValue $s 'AllowCredSSP'
        ClientAllowUnencryptedTraffic  = Get-RegValue $c 'AllowUnencryptedTraffic'
        ClientAllowBasic               = Get-RegValue $c 'AllowBasic'
        ClientTrustedHosts             = [string]$th
    }
} 'Windows Remote Management transport policy. The policy is named AllowUnencrypted; the registry value is AllowUnencryptedTraffic. Basic authentication combined with unencrypted transport places credentials on the wire, so the two values must be read together.'

Capture 'credentialguard' @('Get-ItemProperty') {
    $running = $null
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1
        $running = @($dg.SecurityServicesRunning)
    } catch {}
    [pscustomobject]@{
        LsaCfgFlags                     = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags'
        PolicyLsaCfgFlags               = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags'
        EnableVirtualizationBasedSecurity = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity'
        SecurityServicesRunning         = @($running)
    }
} 'Credential Guard configuration and running state. SecurityServicesRunning containing 1 indicates Credential Guard is active. A configured policy value is not proof the service is running.'

Capture 'optionalfeatures' @('Get-CimInstance') {
    # Win32_OptionalFeature reads without elevation; Get-WindowsOptionalFeature
    # does not. InstallState: 1 Enabled, 2 Disabled, 3 Absent, 4 Unknown.
    $want = @('SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server',
              'MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root',
              'TelnetClient','TFTP','SimpleTCP','WindowsMediaPlayer')
    Get-CimInstance -ClassName Win32_OptionalFeature -OperationTimeoutSec 30 |
      Where-Object { $want -contains $_.Name } |
      Select-Object Name,Caption,InstallState
} 'Selected optional Windows features. InstallState 1 is enabled, 2 disabled, 3 absent. PowerShell 2.0 was removed from Windows 11 version 24H2 and Windows Server 2025 during 2025, so its absence on a current build is expected rather than a control.'

Capture 'pscorelogging' @('Get-ItemProperty') {
    # PowerShell 7 reads a different policy root from Windows PowerShell.
    $b = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore'
    [pscustomobject]@{
        CoreEnableScriptBlockLogging = Get-RegValue "$b\ScriptBlockLogging" 'EnableScriptBlockLogging'
        CoreEnableModuleLogging      = Get-RegValue "$b\ModuleLogging" 'EnableModuleLogging'
        CoreEnableTranscripting      = Get-RegValue "$b\Transcription" 'EnableTranscripting'
        PowerShellCoreInstalled      = [bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\PowerShellCore')
    }
} 'PowerShell 7 audit logging policy. Configuring the Windows PowerShell policy root does not configure PowerShell 7, so a host with both installed needs both.'

Capture 'lapsconfig' @('Get-ItemProperty') {
    # Precedence order, first populated root wins, no inheritance between roots.
    $roots = @(
        @{n='WindowsLapsCsp';   p='HKLM:\Software\Microsoft\Policies\LAPS'},
        @{n='WindowsLapsGpo';   p='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'},
        @{n='WindowsLapsLocal'; p='HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config'}
    )
    $effective = $null; $backup = $null
    foreach ($r in $roots) {
        $v = Get-RegValue $r.p 'BackupDirectory'
        if ($null -ne $v) { $effective = $r.n; $backup = $v; break }
    }
    [pscustomobject]@{
        EffectiveRoot          = $effective
        BackupDirectory        = $backup
        PasswordAgeDays        = if ($effective) { Get-RegValue ($roots | Where-Object { $_.n -eq $effective }).p 'PasswordAgeDays' } else { $null }
        LegacyAdmPwdConfigured = [bool](Test-Path -LiteralPath 'HKLM:\Software\Policies\Microsoft Services\AdmPwd')
        LapsDllPresent         = [bool](Test-Path -LiteralPath "$env:SystemRoot\System32\laps.dll")
    }
} 'Local administrator password management. BackupDirectory is the determining value: absent or 0 means no password backup is configured, 1 is Entra ID and 2 is Active Directory. The presence of a registry root alone is not evidence that the policy is in effect.'

# ---- Wireless (Layer A: host-side 802.11 configuration via netsh wlan; no radio/over-the-air) ----
# Parsed once from netsh text (English labels). Read-only; no PSKs are read or exported.
$wlanPresent = $false; $wlanIface = $null; $wlanProfiles = @(); $wlanAdapter = $null
function Get-NetshField { param([string]$Text,[string]$Key)
    $m=[regex]::Match($Text,"(?im)^\s*$([regex]::Escape($Key))\s*:\s*(.+?)\s*$"); if($m.Success){$m.Groups[1].Value.Trim()}else{$null} }
try {
    $ifaceText = (& netsh wlan show interfaces 2>&1 | Out-String)
    if ($ifaceText -match 'no wireless interface' -or $ifaceText -match 'is not running' -or $ifaceText -match 'AutoConfig') {
        $wlanPresent = $false
    } else {
        $wlanPresent = $true
        # AKM suite (last octet of 00-0f-ac:NN) indicates PMF: 2=PSK(no PMF), 6=PSK-SHA256(PMF), 8=SAE/WPA3(PMF).
        $akmMatch=[regex]::Match($ifaceText,'(?im)akm\s*=\s*00-0f-ac:0*([0-9]+)')
        $connAkm= if($akmMatch.Success){[int]$akmMatch.Groups[1].Value}else{$null}
        $wlanIface = [pscustomobject]@{
            State=Get-NetshField $ifaceText 'State'; Ssid=Get-NetshField $ifaceText 'SSID';
            Authentication=Get-NetshField $ifaceText 'Authentication'; Cipher=Get-NetshField $ifaceText 'Cipher';
            Band=Get-NetshField $ifaceText 'Band'; RadioType=Get-NetshField $ifaceText 'Radio type'; AkmSuite=$connAkm }
        $drvText = (& netsh wlan show drivers 2>&1 | Out-String)
        $wlanAdapter = [pscustomobject]@{
            RadioTypesSupported=Get-NetshField $drvText 'Radio types supported';
            HostedNetworkSupported=Get-NetshField $drvText 'Hosted network supported' }
        $names = @((& netsh wlan show profiles 2>&1) | Select-String 'All User Profile' | ForEach-Object { ($_ -split ':',2)[1].Trim() })
        foreach ($n in $names) {
            $p = (& netsh wlan show profile name="$n" 2>&1 | Out-String)
            $onex = [bool]($p -match '(?im)802\.1X\s*:\s*Enabled')
            $serverVal = $null
            if ($onex) {
                try {
                    $tmp = Join-Path $env:TEMP ('wlanprofile_' + [guid]::NewGuid().ToString('N'))
                    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
                    & netsh wlan export profile name="$n" folder="$tmp" | Out-Null   # no key=clear: no secret exported
                    $xf = Get-ChildItem -LiteralPath $tmp -Filter *.xml -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($xf) {
                        $xt = Get-Content -LiteralPath $xf.FullName -Raw
                        $serverVal = [bool](($xt -match 'ServerValidation') -and ($xt -match '(?i)DisableUserPromptForServerValidation>\s*true'))
                    }
                    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
                } catch { $serverVal = $null }
            }
            $wlanProfiles += [pscustomobject]@{ Name=$n; Authentication=(Get-NetshField $p 'Authentication');
                Cipher=(Get-NetshField $p 'Cipher'); ConnectionMode=(Get-NetshField $p 'Connection mode');
                Dot1X=$onex; ServerCertValidation=$serverVal }
        }
    }
} catch { $wlanPresent = $false }

Capture 'wirelessadapters' @('netsh') {
    if ($wlanPresent -and $wlanAdapter) { $wlanAdapter } else { }
} 'Wireless adapter capability from netsh wlan show drivers. HostedNetworkSupported=No means this built-in adapter cannot perform over-the-air (monitor/AP) testing.'
Capture 'wirelessinterface' @('netsh') {
    if ($wlanPresent -and $wlanIface) { $wlanIface } else { }
} 'Currently connected wireless network security (netsh wlan show interfaces). Absent when disconnected or no wireless adapter is present.'
Capture 'wirelessprofiles' @('netsh') {
    $wlanProfiles
} 'Saved wireless profiles with their authentication, cipher, auto-connect mode and 802.1X flag. Pre-shared keys are never read or exported.'
Capture 'wirelessposture' @('netsh') {
    $open=@($wlanProfiles | Where-Object { ($_.Authentication -match 'Open') -or [string]::IsNullOrWhiteSpace($_.Authentication) })
    $openAuto=@($open | Where-Object { $_.ConnectionMode -match 'auto' })
    $legacy=@($wlanProfiles | Where-Object { ($_.Authentication -match 'WPA-') -or ($_.Authentication -match 'WEP') -or ($_.Cipher -match 'WEP') })
    $tkip=@($wlanProfiles | Where-Object { $_.Cipher -match 'TKIP' })
    $ent=@($wlanProfiles | Where-Object { $_.Dot1X })
    $entNoVal=@($ent | Where-Object { $_.ServerCertValidation -ne $true })
    $psk=@($wlanProfiles | Where-Object { $_.Authentication -match 'Personal' })
    $connOk=$null; $connPmf=$null
    if ($wlanIface -and ($wlanIface.State -match 'connected')) {
        $connOk=[bool]($wlanIface.Authentication -match 'WPA2|WPA3')
        # PMF present when WPA3/SAE or a SHA256 AKM (6/8) is negotiated; absent for classic WPA2-PSK (AKM 2); null if unknown.
        if (($wlanIface.Authentication -match 'WPA3') -or ($wlanIface.AkmSuite -in @(6,8,9,18))) { $connPmf=$true }
        elseif (($wlanIface.AkmSuite -eq 2) -or ($wlanIface.Authentication -match 'WPA2')) { $connPmf=$false }
    }
    [pscustomobject]@{
        WirelessPresent=[int]([bool]$wlanPresent)
        ProfilesTotal=@($wlanProfiles).Count
        OpenNetworkCount=$open.Count
        OpenAutoConnectCount=$openAuto.Count
        LegacyEncryptionCount=$legacy.Count
        TkipCipherCount=$tkip.Count
        EnterpriseNetworkCount=$ent.Count
        EnterpriseNoServerValidationCount=$entNoVal.Count
        PskNetworkCount=$psk.Count
        ConnectedAuthWpa2OrBetter=$connOk
        ConnectedManagementFrameProtection=$connPmf
    }
} 'Aggregated host-side wireless posture used by the WLAN rules. Over-the-air, rogue-AP and evil-twin testing require a monitor-mode adapter and physical presence, and are a separate layer.'

$complete=@($records | Where-Object { $_.status -notin @('Collected','NotApplicable') }).Count -eq 0
$coverage=if ($complete) {'Complete'} else {'Partial'}
$result = [ordered]@{
    schema_version='1.0'; tool_version='0.6'; evidence_kind='WindowsCollection';
    run_id=[guid]::NewGuid().ToString('N'); engagement_id=$EngagementId;site_id=$SiteId;asset_id=$AssetId;
    scope_sha256=$ScopeHash;collector_sha256=$CollectorHash;started_utc=$start;completed_utc=[DateTime]::UtcNow.ToString('o');
    collection_status=$coverage;
    host=[ordered]@{computer_name=$env:COMPUTERNAME;os_caption=$os.Caption;version=$os.Version;build=$os.BuildNumber;
      architecture=$os.OSArchitecture;os_language=$os.OSLanguage;product_type=[int]$os.ProductType;domain_role=[int]$machine.DomainRole;
      part_of_domain=[bool]$machine.PartOfDomain;domain=$machine.Domain;is_domain_controller=$isDc;
      powershell_version=$PSVersionTable.PSVersion.ToString();execution_identity=$identity.Name;
      elevated=$isAdmin;language_mode=$ExecutionContext.SessionState.LanguageMode.ToString();
      fqdn=if($machine.PartOfDomain){([string]$machine.Name + '.' + [string]$machine.Domain)}else{[string]$machine.Name};
      timezone=[TimeZoneInfo]::Local.Id;system_uuid=$productUuid;machine_guid=$machineGuid;
      current_build=$regBuild;ubr=$regUbr;full_build=$regFullBuild;display_version=$regDisplay};
    sources=@($records.ToArray());
    limitations=@('Reference implementation, not validated on the five target Windows platforms.',
      'Missing-patch and CVE determination is performed off-host from the recorded servicing level against vendor data; this collector makes no vulnerability claim itself.',
      'Directory evidence covers identity, policy, privileged group membership, trusts and applied policy objects. It does NOT perform attack-path analysis, expand nested group membership, or assess packet capture, application or cloud.',
      'Wireless assessment is host-side 802.11 configuration only (saved profiles, encryption, auto-join, 802.1X server-certificate validation) parsed from netsh with English labels. It does NOT include over-the-air, rogue-AP, evil-twin or controller-side testing, which require a monitor-mode adapter and physical presence.',
      'Collection can trigger normal OS, security and domain-resolution activity; not zero network traffic.',
      'MaxItems bounds retained rows, not all provider enumeration work. Run.ps1 bounds its wait, but cancellation/cleanup require Windows validation.',
      'Read-only target intent: evidence files and OS execution logs are expected side effects.')
}
$result | ConvertTo-Json -Depth 12
