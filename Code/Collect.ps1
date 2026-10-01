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
    [bool]$AuthorizedLabRun = $false,
    # Eighth positional: corporate SSID list, semicolon separated, resolved by Run.ps1 from the
    # scope document (wireless.corporate_ssids) or its -CorporateSsids parameter. Ninth: where
    # that list came from ("scope" or "parameter"); it is recorded, never interpreted.
    [string]$CorporateSsids = '',
    [string]$CorporateSsidSource = ''
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

function ConvertTo-PolicyNumber {
    # net accounts fallback only: the English words it prints for the edge values.
    param([string]$Text)
    switch -Regex ($Text) {
        '^\d+$'        { return [int]$Text }
        '^(Never|None)$' { return 0 }
        '^Unlimited$'  { return -1 }
        default        { return $Text }
    }
}

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
    if ($regBuild -and $null -ne $regUbr) { $regFullBuild = "10.0.$regBuild.$regUbr" }
    # DisplayVersion exists only from Windows 10 20H2 and Server 2022. Server 2016 and
    # 2019 carry ReleaseId only. Read both guarded, and after full_build, so StrictMode
    # cannot abort this block before the servicing level is recorded.
    if ($cvKey.PSObject.Properties['DisplayVersion']) { $regDisplay = [string]$cvKey.DisplayVersion }
    elseif ($cvKey.PSObject.Properties['ReleaseId']) { $regDisplay = [string]$cvKey.ReleaseId }
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
        # Interfaces where NetBIOS is not explicitly disabled (NetbiosOptions 2). Values 0
        # and 1 and an absent value all leave NetBIOS enabled by default.
        NetbiosEnabledCount  = @($nb | Where-Object { $null -eq $_.NetbiosOptions -or [int]$_.NetbiosOptions -ne 2 }).Count
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

Capture 'passwordpolicy' @('net') {
    $out = [ordered]@{ MinimumPasswordLength=$null; MaximumPasswordAge=$null; MinimumPasswordAge=$null
                       PasswordHistoryLength=$null; LockoutThreshold=$null; LockoutDurationMinutes=$null
                       LockoutWindowMinutes=$null; Source=$null }
    # Preferred path: the NetUserModalsGet API, which is what net accounts itself prints from.
    # The values are integers, so nothing depends on the display language, and no elevation is
    # needed. Ages arrive in seconds and are recorded in days (password ages) or minutes (lockout)
    # to match the net accounts presentation. 0xFFFFFFFF means never and is recorded as -1.
    try {
        if (-not ('UserModalsReader' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class UserModalsReader {
    [StructLayout(LayoutKind.Sequential)]
    public struct USER_MODALS_INFO_0 { public uint min_passwd_len; public uint max_passwd_age; public uint min_passwd_age; public uint force_logoff; public uint password_hist_len; }
    [StructLayout(LayoutKind.Sequential)]
    public struct USER_MODALS_INFO_3 { public uint lockout_duration; public uint lockout_observation_window; public uint lockout_threshold; }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    static extern int NetUserModalsGet(string server, int level, out IntPtr buffer);
    [DllImport("netapi32.dll")]
    static extern int NetApiBufferFree(IntPtr buffer);
    public static long[] Read() {
        IntPtr b;
        int r = NetUserModalsGet(null, 0, out b);
        if (r != 0) { throw new Exception("NetUserModalsGet level 0 returned " + r); }
        USER_MODALS_INFO_0 m0 = (USER_MODALS_INFO_0)Marshal.PtrToStructure(b, typeof(USER_MODALS_INFO_0));
        NetApiBufferFree(b);
        r = NetUserModalsGet(null, 3, out b);
        if (r != 0) { throw new Exception("NetUserModalsGet level 3 returned " + r); }
        USER_MODALS_INFO_3 m3 = (USER_MODALS_INFO_3)Marshal.PtrToStructure(b, typeof(USER_MODALS_INFO_3));
        NetApiBufferFree(b);
        return new long[] { m0.min_passwd_len, m0.max_passwd_age, m0.min_passwd_age, m0.password_hist_len, m3.lockout_threshold, m3.lockout_duration, m3.lockout_observation_window };
    }
}
'@
        }
        $m = [UserModalsReader]::Read()
        $never = [int64][uint32]::MaxValue
        $out.MinimumPasswordLength  = [int]$m[0]
        $out.MaximumPasswordAge     = if ($m[1] -eq $never) { -1 } else { [int][math]::Floor($m[1] / 86400) }
        $out.MinimumPasswordAge     = [int][math]::Floor($m[2] / 86400)
        $out.PasswordHistoryLength  = [int]$m[3]
        $out.LockoutThreshold       = [int]$m[4]
        $out.LockoutDurationMinutes = if ($m[5] -eq $never) { -1 } else { [int][math]::Floor($m[5] / 60) }
        $out.LockoutWindowMinutes   = [int][math]::Floor($m[6] / 60)
        $out.Source = 'NetUserModalsGet'
    } catch { $out.Source = $null }
    if (-not $out.Source) {
        # Fallback only: parse the net accounts text. English labels only; on any other display
        # language the values stay null and the analyzer records Unknown, never a value.
        try {
            $na = & "$env:SystemRoot\System32\net.exe" accounts 2>$null
            foreach ($line in $na) {
                if ($line -match '^\s*Minimum password length\s*:\s*(\S+)')  { $out.MinimumPasswordLength = ConvertTo-PolicyNumber $Matches[1] }
                if ($line -match '^\s*Maximum password age.*:\s*(\S+)')      { $out.MaximumPasswordAge    = ConvertTo-PolicyNumber $Matches[1] }
                if ($line -match '^\s*Minimum password age.*:\s*(\S+)')      { $out.MinimumPasswordAge    = ConvertTo-PolicyNumber $Matches[1] }
                if ($line -match '^\s*Length of password history.*:\s*(\S+)'){ $out.PasswordHistoryLength = ConvertTo-PolicyNumber $Matches[1] }
                if ($line -match '^\s*Lockout threshold\s*:\s*(\S+)')        { $out.LockoutThreshold      = ConvertTo-PolicyNumber $Matches[1] }
                if ($line -match '^\s*Lockout duration.*:\s*(\S+)')          { $out.LockoutDurationMinutes= ConvertTo-PolicyNumber $Matches[1] }
                if ($line -match '^\s*Lockout observation window.*:\s*(\S+)'){ $out.LockoutWindowMinutes  = ConvertTo-PolicyNumber $Matches[1] }
            }
            $out.Source = 'net accounts'
        } catch {}
    }
    [pscustomobject]$out
} 'Local account password and lockout policy read through the NetUserModalsGet API, the same source net accounts prints from, so the values are integers and do not depend on the display language. Password ages are days, lockout values minutes, -1 means never. If the API call fails the net accounts text is parsed instead, and only English labels are understood there. Domain policy is not represented here.'

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
    # Returns the domain's root directory entry, or $null when it cannot be bound AND
    # read: domain unavailable, a non-domain collecting account, or the credential
    # second hop inside a remote session on a member host (the entry exists but its
    # properties come back empty).
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        $entry = $dom.GetDirectoryEntry()
        $dn = $null
        try { $dn = [string]$entry.Properties['distinguishedName'].Value } catch { $dn = $null }
        if ([string]::IsNullOrWhiteSpace($dn)) { return $null }
        return $entry
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

# Directory policy, privileged groups and Kerberos policy are domain facts, read once
# from the domain controller target. Inside a remote session on a member host the
# directory cannot be bound (credential second hop), so those three sources are
# recorded as not applicable there instead of failing.
$dirRoot = Get-DomainRoot
$dirReason = $null
if ($null -eq $dirRoot -and $machine.DomainRole -lt 4 -and (Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue)) {
    $dirReason = 'Directory policy, privileged-group and Kerberos-policy evidence is read once from the domain controller target. In a remote session on a member host the directory cannot be bound (credential second hop), so it is not repeated here.'
}

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

if ($dirReason) { NotApplicable 'domainpolicy' $dirReason } else {
Capture 'domainpolicy' @('Get-CimInstance') {
    $root = Get-DomainRoot
    if ($null -eq $root) { throw 'The domain root object could not be read with the collecting account.' }
    function Sec([object]$v) {
        # AD stores these intervals as negative 100-nanosecond values.
        if ($null -eq $v) { return $null }
        $n = $null
        try { $n = [int64]$v } catch { $n = $null }
        if ($null -eq $n) {
            # Interval attributes arrive as an IADsLargeInteger COM object, not a number.
            # Ask the directory entry to convert it; fall back to the COM properties.
            try { $n = [int64]$root.ConvertLargeIntegerToInt64($v) } catch { $n = $null }
        }
        if ($null -eq $n) {
            try {
                $hi = [int64]$v.GetType().InvokeMember('HighPart',[Reflection.BindingFlags]::GetProperty,$null,$v,$null)
                $lo = [int64]$v.GetType().InvokeMember('LowPart',[Reflection.BindingFlags]::GetProperty,$null,$v,$null)
                $n = ($hi -shl 32) -bor ($lo -band 0xFFFFFFFF)
            } catch { return $null }
        }
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
}

if ($dirReason) { NotApplicable 'domainprivilegedgroups' $dirReason } else {
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
    # objectSid is binary, so a wildcard string filter never matches. Build the exact SID:
    # domain groups hang off the domain SID, the built-in operator groups off S-1-5-32.
    $domainSid = New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$root.Properties['objectSid'].Value), 0)
    $out = @()
    foreach ($rid in $rids.Keys) {
        $sid = if ($rid -ge 544 -and $rid -le 551) { "S-1-5-32-$rid" } else { "$($domainSid.Value)-$rid" }
        $searcher.Filter = "(&(objectClass=group)(objectSid=$sid))"
        $found = $null
        try { $found = $searcher.FindOne() } catch {}
        if ($null -eq $found) { continue }
        $members = @()
        try { $members = @($found.Properties['member'] | ForEach-Object { [string]$_ }) } catch {}
        $out += [pscustomobject]@{
            GroupName    = $rids[$rid]
            Rid          = $rid
            Sid          = $sid
            MemberCount  = $members.Count
            Members      = @($members | Select-Object -First 60)
            Truncated    = ($members.Count -gt 60)
        }
    }
    $out
} 'Membership of well-known privileged directory groups, resolved by relative identifier so a renamed group is still found. Nested group membership is NOT expanded, so the real effective count may be higher. Membership is not itself a finding; excessive or stale membership is, and that requires client confirmation.'
}

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

if ($dirReason) { NotApplicable 'kerberospolicy' $dirReason } else {
Capture 'kerberospolicy' @('Get-CimInstance') {
    $root = Get-DomainRoot
    if ($null -eq $root) { throw 'The domain root object could not be read with the collecting account.' }
    $dn = [string]$root.Properties['distinguishedName'].Value
    $policy = $null
    try {
        $policy = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$dn")
        $null = $policy.Guid
    } catch { $policy = $null }
    # Ticket policy lives in the Default Domain Policy security template, not in LDAP.
    $kp = @{}
    $domainName = [string]$machine.Domain
    $gptRel = "Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    $gptPaths = @()
    if ($machine.DomainRole -ge 4) { $gptPaths += (Join-Path $env:SystemRoot ("SYSVOL\sysvol\" + $domainName + "\" + $gptRel)) }
    $gptPaths += ("\\" + $domainName + "\SYSVOL\" + $domainName + "\" + $gptRel)
    $gptRead = $null
    foreach ($gp in $gptPaths) {
        try {
            if (Test-Path -LiteralPath $gp) {
                $inSection = $false
                foreach ($line in (Get-Content -LiteralPath $gp -ErrorAction Stop)) {
                    if ($line -match '^\s*\[(.+)\]\s*$') { $inSection = ($Matches[1] -eq 'Kerberos Policy'); continue }
                    if ($inSection -and $line -match '^\s*(\w+)\s*=\s*(-?\d+)') { $kp[$Matches[1]] = [int]$Matches[2] }
                }
                $gptRead = $gp; break
            }
        } catch {}
    }
    function KpVal([string]$k) { if ($kp.ContainsKey($k)) { $kp[$k] } else { $null } }
    [pscustomobject]@{
        DefaultDomainPolicyReadable = ($null -ne $policy)
        DefaultDomainPolicyPath     = if ($policy) { [string]$policy.Path } else { $null }
        TicketPolicySource          = $gptRead
        MaxTicketAgeHours           = KpVal 'MaxTicketAge'
        MaxRenewAgeDays             = KpVal 'MaxRenewAge'
        MaxServiceAgeMinutes        = KpVal 'MaxServiceAge'
        MaxClockSkewMinutes         = KpVal 'MaxClockSkew'
        TicketValidateClient        = KpVal 'TicketValidateClient'
        SupportedEncryptionTypes    = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' 'SupportedEncryptionTypes'
        RequireStrongKey            = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireStrongKey'
        RequireSignOrSeal           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireSignOrSeal'
        SealSecureChannel           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SealSecureChannel'
    }
} 'Kerberos ticket policy parsed from the Default Domain Policy security template (GptTmpl.inf, Kerberos Policy section) when SYSVOL is readable from this host, plus the host-side encryption and secure-channel values. Null ticket fields mean the template could not be read from this host, not that no policy exists.'
}

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
    $useWu = Get-RegValue "$wu\AU" 'UseWUServer'
    [pscustomobject]@{
        UseWUServer        = $useWu
        # 1 only when the policy both names a server and switches it on; otherwise the WUServer
        # value is inert and the WSUS rules do not apply.
        WsusInEffect       = if (($null -ne $useWu) -and ([int]$useWu -eq 1) -and $server) { 1 } else { 0 }
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
        SpoolerRunning                          = if ($spooler -and [string]$spooler.State -eq 'Running') { 1 } else { 0 }
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
        PowerShellCoreInstalled      = [int][bool](Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\PowerShellCore')
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

# ---- BEGIN WIRELESS HELPERS ----
# Pure helpers: text and objects in, objects out. Nothing in this region calls netsh,
# Get-NetAdapter, the registry or the file system, so Code\CollectorHelperTests.ps1 can
# extract this region from Collect.ps1 by its two marker comments and run it on a host
# without a wireless adapter. The tested code is therefore byte-identical to the shipped
# code. Keep every function in this region free of side effects.
function Get-NetshField { param([string]$Text,[string]$Key)
    $m=[regex]::Match($Text,"(?im)^\s*$([regex]::Escape($Key))\s*:\s*(.+?)\s*$"); if($m.Success){$m.Groups[1].Value.Trim()}else{$null} }

function Test-WirelessAdapter {
    # True when a Get-NetAdapter style object describes an 802.11 adapter: PhysicalMediaType
    # 'Native 802.11', IANA InterfaceType 71 (ieee80211), or a Wi-Fi style name/description.
    param([object]$Adapter)
    if ($null -eq $Adapter) { return $false }
    $p = $Adapter.PSObject.Properties
    $media = ''; $ifType = $null; $name = ''; $desc = ''
    if ($p['PhysicalMediaType'] -and $null -ne $Adapter.PhysicalMediaType) { $media = [string]$Adapter.PhysicalMediaType }
    if ($p['InterfaceType'] -and $null -ne $Adapter.InterfaceType) { try { $ifType = [int]$Adapter.InterfaceType } catch { $ifType = $null } }
    if ($p['Name'] -and $null -ne $Adapter.Name) { $name = [string]$Adapter.Name }
    if ($p['InterfaceDescription'] -and $null -ne $Adapter.InterfaceDescription) { $desc = [string]$Adapter.InterfaceDescription }
    if ($media -match '(?i)native 802\.11') { return $true }
    if ($null -ne $ifType -and $ifType -eq 71) { return $true }
    if ($name -match '(?i)Wi-?Fi|Wireless|802\.11') { return $true }
    if ($desc -match '(?i)Wi-?Fi|Wireless|802\.11') { return $true }
    return $false
}

function Get-WirelessAdapterNames {
    # Names of the 802.11 adapters in a Get-NetAdapter style list. Always wrap the call in @().
    param([AllowNull()][object[]]$Adapters)
    $names = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Adapters) { return @($names.ToArray()) }
    foreach ($a in $Adapters) {
        if (Test-WirelessAdapter $a) {
            $n = '(unnamed)'
            if ($a.PSObject.Properties['Name'] -and $null -ne $a.Name) { $n = [string]$a.Name }
            [void]$names.Add($n)
        }
    }
    return @($names.ToArray())
}

function Resolve-WirelessPresence {
    # Three-way wireless presence (1, 0 or $null), always with a stated basis.
    #   InterfaceText : text of "netsh wlan show interfaces" in whatever language the host prints.
    #   Adapters      : the Get-NetAdapter result; @() when the host lists no adapters at all;
    #                   $null when Get-NetAdapter could not be run (adapter evidence unavailable).
    # Only the English netsh phrases are recognised. Anything else is "not understood" and
    # yields $null (never 0) unless the adapter list proves that no 802.11 adapter exists.
    param([AllowNull()][string]$InterfaceText, [AllowNull()][object[]]$Adapters)
    $text = if ($null -eq $InterfaceText) { '' } else { [string]$InterfaceText }
    $adapterKnown = ($null -ne $Adapters)
    $wifi = @(Get-WirelessAdapterNames $Adapters)
    $noAdapter = ($adapterKnown -and $wifi.Count -eq 0)
    $adapterNote = 'the adapter list is unavailable, so absence of an adapter could not be corroborated'
    if ($adapterKnown -and $wifi.Count -eq 0) { $adapterNote = 'no 802.11 adapter listed by Get-NetAdapter' }
    if ($adapterKnown -and $wifi.Count -gt 0) { $adapterNote = 'Get-NetAdapter lists an 802.11 adapter (' + ($wifi -join ', ') + ')' }
    $r = [ordered]@{ Present=$null; Basis=$null; InterfaceCount=$null; NetshUnderstood=$false;
                     AdapterListed=$(if ($adapterKnown) { ($wifi.Count -gt 0) } else { $null }); AdapterNames=@($wifi) }
    $count  = [regex]::Match($text, '(?i)there (?:is|are) (\d+) interfaces? on the system')
    $none   = ($text -match '(?i)there is no wireless interface on the system')
    $svc    = ($text -match '(?i)is not running')
    $denied = ($text -match '(?i)access (?:is )?denied')
    if ($count.Success) {
        $n = [int]$count.Groups[1].Value
        $r.InterfaceCount = $n; $r.NetshUnderstood = $true
        if ($n -ge 1) {
            $r.Present = 1; $r.Basis = "netsh wlan show interfaces reports $n wireless interface(s) on the system."
            return [pscustomobject]$r
        }
        $none = $true
    }
    if ($none) {
        $r.NetshUnderstood = $true
        if ($noAdapter) { $r.Present = 0; $r.Basis = "netsh wlan show interfaces reports no wireless interface and $adapterNote." }
        else { $r.Present = $null; $r.Basis = "netsh wlan show interfaces reports no wireless interface but $adapterNote; presence not determined." }
        return [pscustomobject]$r
    }
    if ($svc) {
        if ($noAdapter) { $r.Present = 0; $r.Basis = "The WLAN AutoConfig service (wlansvc) is not running and $adapterNote." }
        else { $r.Present = $null; $r.Basis = "The WLAN AutoConfig service (wlansvc) is not running, so netsh could not enumerate wireless interfaces; $adapterNote; presence not determined." }
        return [pscustomobject]$r
    }
    if ($denied) {
        if ($noAdapter) { $r.Present = 0; $r.Basis = "netsh wlan show interfaces was refused (access denied) and $adapterNote." }
        else { $r.Present = $null; $r.Basis = "netsh wlan show interfaces was refused (access denied); $adapterNote; presence not determined." }
        return [pscustomobject]$r
    }
    $first = @(($text -split "`r?`n") | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    $firstLine = if ($first.Count -eq 0) { '(no output)' } else { ([string]$first[0]).Trim() }
    if ($firstLine.Length -gt 120) { $firstLine = $firstLine.Substring(0, 120) + '...' }
    if ($noAdapter) {
        $r.Present = 0
        $r.Basis = "netsh wlan show interfaces output was not understood (only the English phrases are recognised; first line: '$firstLine') but $adapterNote."
    } else {
        $r.Present = $null
        $r.Basis = "netsh wlan show interfaces output was not understood (only the English phrases are recognised; first line: '$firstLine'); $adapterNote; presence not determined."
    }
    return [pscustomobject]$r
}

function Resolve-WirelessProfileList {
    # Parses "netsh wlan show profiles". Understood when at least one "All User Profile" line
    # is present, or the recognised English empty-list text appears (a "There is no profile"
    # message, or a "User profiles" section containing only <None>). Names keep their exact
    # spelling including trailing spaces, because netsh needs the exact name to read a profile.
    param([AllowNull()][string]$ProfilesText)
    $text = if ($null -eq $ProfilesText) { '' } else { [string]$ProfilesText }
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ($text -split "`r?`n")) {
        $m = [regex]::Match($line, '^\s*All User Profile\s*:\s?(.*)$')
        if ($m.Success) {
            $v = $m.Groups[1].Value.TrimEnd("`r")
            if ($v.Trim() -ne '') { [void]$names.Add($v) }
        }
    }
    $r = [ordered]@{ Understood=$false; Names=@($names.ToArray()); Basis=$null; Error=$null }
    if ($names.Count -gt 0) {
        $r.Understood = $true; $r.Basis = "netsh wlan show profiles listed $($names.Count) all-user profile(s)."
        return [pscustomobject]$r
    }
    if ($text -match '(?i)there (?:is|are) no profiles?') {
        $r.Understood = $true; $r.Basis = 'netsh wlan show profiles reports that no profile is saved.'
        return [pscustomobject]$r
    }
    if ($text -match '(?im)^\s*User profiles\s*$' -and $text -match '(?im)^\s*<None>\s*$') {
        $r.Understood = $true; $r.Basis = 'netsh wlan show profiles lists a User profiles section with no entries.'
        return [pscustomobject]$r
    }
    $first = @(($text -split "`r?`n") | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    $firstLine = if ($first.Count -eq 0) { '(no output)' } else { ([string]$first[0]).Trim() }
    if ($firstLine.Length -gt 160) { $firstLine = $firstLine.Substring(0, 160) + '...' }
    $r.Error = "netsh wlan show profiles output was not understood (only the English phrases are recognised; first line: '$firstLine'). Saved profiles could not be enumerated."
    return [pscustomobject]$r
}

function Resolve-EapServerValidation {
    # Namespace-aware read of an exported WLAN profile XML (exported without key=clear, so no
    # key material is present). Returns ServerCertValidation $true / $false / $null with a
    # basis, plus TrustedRootCount and ServerNamesPresent as separate observations.
    #   PEAP (25) and EAP-TTLS (21): the PerformServerValidation element decides.
    #   EAP-TLS (13): the ServerValidation block decides (user prompt disabled AND a trusted
    #   root present -> true; user prompt allowed -> false; neither root nor names -> null).
    param([AllowNull()][string]$ProfileXml)
    function Get-XmlText([object]$Node) { if ($null -eq $Node) { return '' } return ([string]$Node.InnerText).Trim() }
    function Measure-NonEmpty([object]$Nodes) { $c = 0; if ($null -ne $Nodes) { foreach ($x in $Nodes) { if ((Get-XmlText $x) -ne '') { $c++ } } } return $c }
    $r = [ordered]@{ ServerCertValidation=$null; ServerCertValidationBasis=$null; EapType=$null; TrustedRootCount=0; ServerNamesPresent=$false }
    if ([string]::IsNullOrWhiteSpace($ProfileXml)) { $r.ServerCertValidationBasis = 'No profile XML was available to read.'; return [pscustomobject]$r }
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    try { $doc.LoadXml($ProfileXml) } catch {
        $r.ServerCertValidationBasis = 'The profile XML could not be parsed: ' + $_.Exception.Message
        return [pscustomobject]$r
    }
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('wlan',  'http://www.microsoft.com/networking/WLAN/profile/v1')
    $ns.AddNamespace('onex',  'http://www.microsoft.com/networking/OneX/v1')
    $ns.AddNamespace('eh',    'http://www.microsoft.com/provisioning/EapHostConfig')
    $ns.AddNamespace('ec',    'http://www.microsoft.com/provisioning/EapCommon')
    $ns.AddNamespace('bec',   'http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1')
    $ns.AddNamespace('peap',  'http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1')
    $ns.AddNamespace('peap2', 'http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2')
    $ns.AddNamespace('tls',   'http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1')
    $ns.AddNamespace('ttls',  'http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1')
    $typeNode = $doc.SelectSingleNode('//eh:EapHostConfig/eh:EapMethod/ec:Type', $ns)
    if ($null -eq $typeNode) {
        $r.ServerCertValidationBasis = 'No EapHostConfig/EapMethod/Type element was found in the profile XML, so the EAP method could not be identified.'
        return [pscustomobject]$r
    }
    $eapType = $null
    try { $eapType = [int]$typeNode.InnerText.Trim() } catch { $eapType = $null }
    $r.EapType = $eapType
    $config = $doc.SelectSingleNode('//eh:EapHostConfig/eh:Config', $ns)
    if ($null -eq $config) {
        $r.ServerCertValidationBasis = "EAP type ${eapType}: the EapHostConfig/Config element is missing, so the method configuration could not be read."
        return [pscustomobject]$r
    }
    if ($eapType -eq 25) {
        $label = 'PEAP'
        $r.TrustedRootCount = Measure-NonEmpty ($config.SelectNodes('.//peap:ServerValidation/peap:TrustedRootCA', $ns))
        $snNode = $config.SelectSingleNode('.//peap:ServerValidation/peap:ServerNames', $ns)
        $psv = $config.SelectSingleNode('.//peap2:PerformServerValidation', $ns)
        $r.ServerNamesPresent = ((Get-XmlText $snNode) -ne '')
        if ($null -eq $psv) {
            # Tolerate the element in an unexpected namespace, but say so in the basis.
            $psv = $config.SelectSingleNode(".//*[local-name()='PerformServerValidation']")
            $nsNote = if ($null -ne $psv) { ' (element found outside its documented namespace)' } else { '' }
        } else { $nsNote = '' }
        if ($null -eq $psv) {
            $r.ServerCertValidationBasis = "$label (EAP type $eapType): the PerformServerValidation element is missing from the profile, so the server-certificate validation setting is not determined."
            return [pscustomobject]$r
        }
        $v = (Get-XmlText $psv).ToLowerInvariant()
        if ($v -eq 'true') { $r.ServerCertValidation = $true; $r.ServerCertValidationBasis = "$label (EAP type $eapType): PerformServerValidation is true$nsNote." }
        elseif ($v -eq 'false') { $r.ServerCertValidation = $false; $r.ServerCertValidationBasis = "$label (EAP type $eapType): PerformServerValidation is false$nsNote; the authentication server certificate is not validated." }
        else { $r.ServerCertValidationBasis = "$label (EAP type $eapType): PerformServerValidation holds the unrecognised value '$v'; not determined." }
        return [pscustomobject]$r
    }
    if ($eapType -eq 21) {
        # EAP-TTLS is judged from its own ServerValidation block (EapTtlsConnectionPropertiesV1):
        # DisablePrompt true means the user is not prompted and validation is enforced;
        # TrustedRootCAHash entries name the pinned roots.
        $sv = $config.SelectSingleNode('.//ttls:ServerValidation', $ns)
        if ($null -eq $sv) {
            $r.ServerCertValidationBasis = 'EAP-TTLS (EAP type 21): the ServerValidation block is missing from the profile, so the server-certificate validation setting is not determined.'
            return [pscustomobject]$r
        }
        $r.TrustedRootCount = Measure-NonEmpty ($sv.SelectNodes('ttls:TrustedRootCAHash', $ns))
        $snNode = $sv.SelectSingleNode('ttls:ServerNames', $ns)
        $r.ServerNamesPresent = ((Get-XmlText $snNode) -ne '')
        $promptNode = $sv.SelectSingleNode('ttls:DisablePrompt', $ns)
        $prompt = if ($null -eq $promptNode) { $null } else { (Get-XmlText $promptNode).ToLowerInvariant() }
        if ($prompt -eq 'false') {
            $r.ServerCertValidation = $false
            $r.ServerCertValidationBasis = 'EAP-TTLS (EAP type 21): DisablePrompt is false, so the user can accept any server certificate.'
            return [pscustomobject]$r
        }
        if ($r.TrustedRootCount -eq 0 -and -not $r.ServerNamesPresent) {
            $r.ServerCertValidationBasis = 'EAP-TTLS (EAP type 21): the ServerValidation block names no trusted root CA hash and no server names, so what the client would validate against is not determined.'
            return [pscustomobject]$r
        }
        if ($prompt -eq 'true' -and $r.TrustedRootCount -ge 1) {
            $r.ServerCertValidation = $true
            $r.ServerCertValidationBasis = "EAP-TTLS (EAP type 21): DisablePrompt is true and $($r.TrustedRootCount) trusted root CA hash(es) are pinned."
            return [pscustomobject]$r
        }
        if ($null -eq $prompt) {
            $r.ServerCertValidationBasis = 'EAP-TTLS (EAP type 21): the DisablePrompt element is missing from the ServerValidation block; not determined.'
        } elseif ($prompt -eq 'true') {
            $r.ServerCertValidationBasis = 'EAP-TTLS (EAP type 21): DisablePrompt is true but no trusted root CA hash is pinned (server names only), so validation against a trusted root is not determined.'
        } else {
            $r.ServerCertValidationBasis = "EAP-TTLS (EAP type 21): DisablePrompt holds the unrecognised value '$prompt'; not determined."
        }
        return [pscustomobject]$r
    }
    if ($eapType -eq 13) {
        $sv = $config.SelectSingleNode('.//tls:EapType/tls:ServerValidation', $ns)
        if ($null -eq $sv) { $sv = $config.SelectSingleNode('.//tls:ServerValidation', $ns) }
        if ($null -eq $sv) {
            $r.ServerCertValidationBasis = 'EAP-TLS (EAP type 13): the ServerValidation block is missing from the profile, so the server-certificate validation setting is not determined.'
            return [pscustomobject]$r
        }
        $r.TrustedRootCount = Measure-NonEmpty ($sv.SelectNodes('tls:TrustedRootCA', $ns))
        $snNode = $sv.SelectSingleNode('tls:ServerNames', $ns)
        $r.ServerNamesPresent = ((Get-XmlText $snNode) -ne '')
        $promptNode = $sv.SelectSingleNode('tls:DisableUserPromptForServerValidation', $ns)
        $prompt = if ($null -eq $promptNode) { $null } else { (Get-XmlText $promptNode).ToLowerInvariant() }
        if ($prompt -eq 'false') {
            $r.ServerCertValidation = $false
            $r.ServerCertValidationBasis = 'EAP-TLS (EAP type 13): DisableUserPromptForServerValidation is false, so the user can accept any server certificate.'
            return [pscustomobject]$r
        }
        if ($r.TrustedRootCount -eq 0 -and -not $r.ServerNamesPresent) {
            $r.ServerCertValidationBasis = 'EAP-TLS (EAP type 13): the ServerValidation block names no trusted root CA and no server names, so what the client would validate against is not determined.'
            return [pscustomobject]$r
        }
        if ($prompt -eq 'true' -and $r.TrustedRootCount -ge 1) {
            $r.ServerCertValidation = $true
            $r.ServerCertValidationBasis = "EAP-TLS (EAP type 13): DisableUserPromptForServerValidation is true and $($r.TrustedRootCount) trusted root CA thumbprint(s) are pinned."
            return [pscustomobject]$r
        }
        if ($null -eq $prompt) {
            $r.ServerCertValidationBasis = 'EAP-TLS (EAP type 13): the DisableUserPromptForServerValidation element is missing from the ServerValidation block; not determined.'
        } elseif ($prompt -eq 'true') {
            $r.ServerCertValidationBasis = 'EAP-TLS (EAP type 13): DisableUserPromptForServerValidation is true but no trusted root CA is pinned (server names only), so validation against a trusted root is not determined.'
        } else {
            $r.ServerCertValidationBasis = "EAP-TLS (EAP type 13): DisableUserPromptForServerValidation holds the unrecognised value '$prompt'; not determined."
        }
        return [pscustomobject]$r
    }
    $r.ServerCertValidationBasis = "EAP type $(if ($null -eq $eapType) { '(unreadable)' } else { $eapType }) has no server-certificate validation rule in this collector; not determined."
    return [pscustomobject]$r
}

function Get-AkmSuite {
    # The negotiated AKM suite selector (last octet of 00-0f-ac:NN) from netsh wlan show interfaces, or $null.
    param([AllowNull()][string]$InterfaceText)
    if ($null -eq $InterfaceText) { return $null }
    $m = [regex]::Match([string]$InterfaceText, '(?im)akm\s*=\s*00-0f-ac:0*([0-9]+)')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Resolve-Pmf {
    # Management-frame protection decided only from the negotiated AKM suite. Suites that
    # mandate protected management frames give $true; any other suite, or no suite, gives
    # $null, never $false, because netsh does not expose the RSN capability bits (MFPC/MFPR).
    param([AllowNull()][object]$AkmSuite)
    $mandating = @(5,6,8,9,11,12,13,18,19,20)
    $names = @{ 1='802.1X'; 2='PSK'; 3='FT-802.1X'; 4='FT-PSK'; 5='802.1X-SHA256'; 6='PSK-SHA256'; 7='TDLS';
                8='SAE'; 9='FT-SAE'; 11='Suite B 802.1X-SHA256'; 12='Suite B 802.1X-SHA384'; 13='FT-802.1X-SHA384';
                18='OWE'; 19='FT-PSK-SHA384'; 20='PSK-SHA384' }
    $akm = $null
    if ($null -ne $AkmSuite) { try { $akm = [int]$AkmSuite } catch { $akm = $null } }
    if ($null -eq $akm) {
        return [pscustomobject]@{ Pmf=$null; Basis='No AKM suite could be read from netsh wlan show interfaces. netsh does not expose the RSN capability bits (MFPC/MFPR), so management-frame protection is not determined.' }
    }
    $label = if ($names.ContainsKey($akm)) { $names[$akm] } else { 'unlisted suite' }
    $sel = ('00-0f-ac:{0:D2}' -f $akm)
    if ($mandating -contains $akm) {
        return [pscustomobject]@{ Pmf=$true; Basis="Negotiated AKM suite $sel ($label) mandates protected management frames." }
    }
    return [pscustomobject]@{ Pmf=$null; Basis="Negotiated AKM suite $sel ($label) does not itself mandate protected management frames. netsh does not expose the RSN capability bits (MFPC/MFPR), so the absence of a mandating suite is not proof that PMF is off; not determined." }
}

function Test-WlanConnected {
    # True only when the netsh State field is exactly "connected" (surrounding whitespace ignored).
    param([AllowNull()][string]$State)
    if ($null -eq $State) { return $false }
    return (([string]$State).Trim() -eq 'connected')
}

function ConvertFrom-CorporateSsidList {
    # Semicolon-separated corporate SSID list from the launcher environment. $null when absent or empty.
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in ([string]$Text).Split(';')) { $t = $part.Trim(); if ($t -ne '') { [void]$items.Add($t) } }
    if ($items.Count -eq 0) { return $null }
    return @($items.ToArray())
}

function Get-CorporatePskCount {
    # Saved Personal (PSK) profiles whose name is on the corporate SSID list; $null when no list was supplied.
    param([AllowNull()][object[]]$Profiles, [AllowNull()][string[]]$CorporateSsids)
    if ($null -eq $CorporateSsids -or @($CorporateSsids).Count -eq 0) { return $null }
    $set = @{}
    foreach ($s in $CorporateSsids) { $set[([string]$s).Trim().ToLowerInvariant()] = $true }
    $n = 0
    if ($null -ne $Profiles) {
        foreach ($p in $Profiles) {
            $auth = ''; $name = ''
            if ($p.PSObject.Properties['Authentication'] -and $null -ne $p.Authentication) { $auth = [string]$p.Authentication }
            if ($p.PSObject.Properties['Name'] -and $null -ne $p.Name) { $name = [string]$p.Name }
            if ($auth -match 'Personal' -and $set.ContainsKey($name.Trim().ToLowerInvariant())) { $n++ }
        }
    }
    return $n
}

function Resolve-EnterpriseValidationCounts {
    # Counts over the 802.1X profiles: NoValidation counts only ServerCertValidation exactly
    # $false; Unknown counts $null. When Unknown is above zero and no profile is known-false,
    # NoValidation is emitted as $null so the WLAN04 rule records Unknown rather than Pass.
    param([AllowNull()][object[]]$Profiles)
    $ent = 0; $noVal = 0; $unknown = 0
    if ($null -ne $Profiles) {
        foreach ($p in $Profiles) {
            $dot1x = $false
            if ($p.PSObject.Properties['Dot1X'] -and $null -ne $p.Dot1X) { $dot1x = [bool]$p.Dot1X }
            if (-not $dot1x) { continue }
            $ent++
            $v = $null
            if ($p.PSObject.Properties['ServerCertValidation']) { $v = $p.ServerCertValidation }
            if ($null -eq $v) { $unknown++ }
            elseif ($v -is [bool] -and $v -eq $false) { $noVal++ }
        }
    }
    $emit = if ($unknown -gt 0 -and $noVal -eq 0) { $null } else { $noVal }
    return [pscustomobject]@{ EnterpriseNetworkCount=$ent; EnterpriseNoServerValidationCount=$emit; EnterpriseServerValidationUnknownCount=$unknown; KnownNoValidation=$noVal }
}

function Resolve-OpenNetworkCounts {
    # Open-network counts. A profile is Open only when its Authentication says so; a profile
    # whose Authentication could not be read (null or empty) is Unreadable, never Open. When
    # any profile is unreadable and no profile is known to be open, both open counts are
    # emitted as $null so WLAN01 and WLAN06 record Unknown rather than a false Pass.
    param([AllowNull()][object[]]$Profiles)
    $open = 0; $openAuto = 0
    $unreadable = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $Profiles) {
        foreach ($p in $Profiles) {
            $auth = $null; $mode = ''; $name = ''
            if ($p.PSObject.Properties['Authentication']) { $auth = $p.Authentication }
            if ($p.PSObject.Properties['ConnectionMode'] -and $null -ne $p.ConnectionMode) { $mode = [string]$p.ConnectionMode }
            if ($p.PSObject.Properties['Name'] -and $null -ne $p.Name) { $name = [string]$p.Name }
            if ($null -eq $auth -or [string]::IsNullOrWhiteSpace([string]$auth)) { [void]$unreadable.Add($name); continue }
            if ([string]$auth -match 'Open') {
                $open++
                if ($mode -match 'auto') { $openAuto++ }
            }
        }
    }
    $emitOpen = $open; $emitAuto = $openAuto
    if ($unreadable.Count -gt 0 -and $open -eq 0) { $emitOpen = $null; $emitAuto = $null }
    return [pscustomobject]@{ OpenNetworkCount=$emitOpen; OpenAutoConnectCount=$emitAuto; UnreadableProfileCount=$unreadable.Count;
                              UnreadableProfileNames=@($unreadable.ToArray()); KnownOpen=$open; KnownOpenAuto=$openAuto }
}
# ---- END WIRELESS HELPERS ----

$wlanPresence = $null; $wlanIface = $null; $wlanProfiles = @(); $wlanAdapter = $null
$wlanProfilesStatus = 'NotAttempted'; $wlanProfilesError = $null; $wlanProfileListBasis = $null
# Corporate SSID list (semicolon separated). Precedence: the collector parameter filled by
# Run.ps1 (from the scope document or its -CorporateSsids switch), then the POSTUREKIT_CORPORATE_SSIDS
# environment variable (Local mode only; it does not cross WinRM), else null, in which case no
# attribution is possible and the corporate PSK count is emitted as null.
$wlanCorporateSsids = $null; $wlanCorporateSsidSource = $null
if (-not [string]::IsNullOrWhiteSpace($CorporateSsids)) {
    $wlanCorporateSsids = ConvertFrom-CorporateSsidList $CorporateSsids
    if ($null -ne $wlanCorporateSsids) {
        $wlanCorporateSsidSource = if ($CorporateSsidSource -in @('scope','parameter')) { $CorporateSsidSource } else { 'parameter' }
    }
}
if ($null -eq $wlanCorporateSsids) {
    $wlanCorporateSsids = ConvertFrom-CorporateSsidList $env:POSTUREKIT_CORPORATE_SSIDS
    if ($null -ne $wlanCorporateSsids) { $wlanCorporateSsidSource = 'environment' }
}
# The adapter list corroborates a negative netsh result. $null means it could not be read.
$netAdapters = $null
try { $netAdapters = @(Get-NetAdapter -ErrorAction Stop | Select-Object Name,InterfaceDescription,InterfaceType,PhysicalMediaType) } catch { $netAdapters = $null }
# netsh writes UTF-8 bytes for profile names; PowerShell decodes native output with the console
# encoding, so a name with a non-ASCII character is mangled under the OEM code page and the
# profile can then not be read back by name. Switch the console to UTF-8 for the netsh wlan
# calls only and restore it afterwards. In a session without a console the setter can throw;
# that is tolerated and the previous behaviour applies.
$prevConsoleEncoding = $null; $wlanUtf8Console = $false
try { $prevConsoleEncoding = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $wlanUtf8Console = $true } catch { $wlanUtf8Console = $false }
try {
$ifaceText = ''
try { $ifaceText = (& netsh wlan show interfaces 2>&1 | Out-String) } catch { $ifaceText = 'netsh wlan show interfaces failed: ' + $_.Exception.Message }
$wlanPresence = Resolve-WirelessPresence -InterfaceText $ifaceText -Adapters $netAdapters
if ($wlanPresence.Present -eq 1) {
    try {
        $wlanIface = [pscustomobject]@{
            State=Get-NetshField $ifaceText 'State'; Ssid=Get-NetshField $ifaceText 'SSID';
            Authentication=Get-NetshField $ifaceText 'Authentication'; Cipher=Get-NetshField $ifaceText 'Cipher';
            Band=Get-NetshField $ifaceText 'Band'; RadioType=Get-NetshField $ifaceText 'Radio type'; AkmSuite=(Get-AkmSuite $ifaceText) }
        $drvText = (& netsh wlan show drivers 2>&1 | Out-String)
        $wlanAdapter = [pscustomobject]@{
            RadioTypesSupported=Get-NetshField $drvText 'Radio types supported';
            HostedNetworkSupported=Get-NetshField $drvText 'Hosted network supported' }
    } catch {}
}
if ($null -ne $wlanPresence.Present -and $wlanPresence.Present -eq 0) {
    $wlanProfilesStatus = 'Skipped'
    $wlanProfileListBasis = 'Profile enumeration not attempted: ' + $wlanPresence.Basis
} else {
    # Attempted whenever presence is 1 or undetermined, so a failed or non-understood
    # enumeration is recorded as an Error on the wirelessprofiles source, never as an
    # empty Collected list.
    try {
        $profText = (& netsh wlan show profiles 2>&1 | Out-String)
        $list = Resolve-WirelessProfileList $profText
        if (-not $list.Understood) { throw $list.Error }
        $wlanProfileListBasis = $list.Basis
        foreach ($n in $list.Names) {
            $p = (& netsh wlan show profile name="$n" 2>&1 | Out-String)
            $onex = [bool]($p -match '(?im)802\.1X\s*:\s*Enabled')
            $eap = [pscustomobject]@{ ServerCertValidation=$null; ServerCertValidationBasis='Not an 802.1X profile.'; EapType=$null; TrustedRootCount=$null; ServerNamesPresent=$null }
            if ($onex) {
                $xt = $null
                try {
                    $tmp = Join-Path $env:TEMP ('pkwlan_' + [guid]::NewGuid().ToString('N'))
                    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
                    & netsh wlan export profile name="$n" folder="$tmp" | Out-Null   # no key=clear: no secret exported
                    $xf = Get-ChildItem -LiteralPath $tmp -Filter *.xml -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($xf) { $xt = Get-Content -LiteralPath $xf.FullName -Raw }
                    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
                } catch { $xt = $null }
                $eap = Resolve-EapServerValidation $xt
            }
            $wlanProfiles += [pscustomobject]@{ Name=$n; ProfileScope='AllUser'; Authentication=(Get-NetshField $p 'Authentication');
                Cipher=(Get-NetshField $p 'Cipher'); ConnectionMode=(Get-NetshField $p 'Connection mode');
                Dot1X=$onex; ServerCertValidation=$eap.ServerCertValidation; ServerCertValidationBasis=$eap.ServerCertValidationBasis;
                TrustedRootCount=$eap.TrustedRootCount; ServerNamesPresent=$eap.ServerNamesPresent }
        }
        $wlanProfilesStatus = 'Collected'
    } catch { $wlanProfilesStatus = 'Error'; $wlanProfilesError = $_.Exception.Message; $wlanProfiles = @() }
}
} finally {
    # End of the netsh wlan calls: restore the console encoding that was in force before.
    if ($wlanUtf8Console -and $null -ne $prevConsoleEncoding) { try { [Console]::OutputEncoding = $prevConsoleEncoding } catch {} }
}

Capture 'wirelessadapters' @('netsh') {
    if ($wlanPresence.Present -eq 1 -and $wlanAdapter) { $wlanAdapter } else { }
} 'Wireless adapter capability from netsh wlan show drivers. HostedNetworkSupported=No means this built-in adapter cannot perform over-the-air (monitor/AP) testing.'
Capture 'wirelessinterface' @('netsh') {
    if ($wlanPresence.Present -eq 1 -and $wlanIface) { $wlanIface } else { }
} 'Currently connected wireless network security (netsh wlan show interfaces). Absent when disconnected or no wireless adapter is present.'
Capture 'wirelessprofiles' @('netsh') {
    if ($wlanProfilesStatus -eq 'Error') { throw $wlanProfilesError }
    $wlanProfiles
} 'Saved all-user wireless profiles (ProfileScope AllUser) with their authentication, cipher, auto-connect mode, 802.1X flag and the server-certificate validation read from the exported profile XML. Per-user profiles are not read. Pre-shared keys are never read or exported. Recorded as an Error when the profile list could not be enumerated or understood.'
Capture 'wirelessposture' @('netsh') {
    $openCounts = Resolve-OpenNetworkCounts $wlanProfiles
    $legacy=@($wlanProfiles | Where-Object { ($_.Authentication -match 'WPA-') -or ($_.Authentication -match 'WEP') -or ($_.Cipher -match 'WEP') })
    $tkip=@($wlanProfiles | Where-Object { $_.Cipher -match 'TKIP' })
    $entCounts = Resolve-EnterpriseValidationCounts $wlanProfiles
    $psk=@($wlanProfiles | Where-Object { $_.Authentication -match 'Personal' })
    $connOk=$null; $connPmf=$null; $connPmfBasis=$null
    if ($wlanIface -and (Test-WlanConnected $wlanIface.State)) {
        $connOk=[bool]($wlanIface.Authentication -match 'WPA2|WPA3')
        $pmf = Resolve-Pmf $wlanIface.AkmSuite
        $connPmf = $pmf.Pmf; $connPmfBasis = $pmf.Basis
    } elseif ($wlanIface) {
        $connPmfBasis = 'The wireless interface is not associated (State is not "connected"), so no negotiated AKM suite exists to evaluate.'
    } else {
        $connPmfBasis = 'No wireless interface detail was read, so no negotiated AKM suite exists to evaluate.'
    }
    [pscustomobject]@{
        WirelessPresent=$wlanPresence.Present
        WirelessPresenceBasis=$wlanPresence.Basis
        ProfilesTotal=@($wlanProfiles).Count
        OpenNetworkCount=$openCounts.OpenNetworkCount
        OpenAutoConnectCount=$openCounts.OpenAutoConnectCount
        UnreadableProfileCount=$openCounts.UnreadableProfileCount
        UnreadableProfileNames=@($openCounts.UnreadableProfileNames)
        LegacyEncryptionCount=$legacy.Count
        TkipCipherCount=$tkip.Count
        EnterpriseNetworkCount=$entCounts.EnterpriseNetworkCount
        EnterpriseNoServerValidationCount=$entCounts.EnterpriseNoServerValidationCount
        EnterpriseServerValidationUnknownCount=$entCounts.EnterpriseServerValidationUnknownCount
        PskNetworkCount=$psk.Count
        CorporatePskNetworkCount=(Get-CorporatePskCount $wlanProfiles $wlanCorporateSsids)
        CorporateSsidSource=$wlanCorporateSsidSource
        ConnectedAuthWpa2OrBetter=$connOk
        ConnectedManagementFrameProtection=$connPmf
        ConnectedPmfBasis=$connPmfBasis
    }
} 'Aggregated host-side wireless posture used by the WLAN rules. WirelessPresent is 1 when netsh reports an interface, 0 when netsh reports none and no 802.11 adapter is listed, and null otherwise (another display language, service not running, access denied); WirelessPresenceBasis states which. A null value makes the wireless rules record Unknown. A profile whose authentication could not be read is counted in UnreadableProfileCount, never as Open; when any profile is unreadable and none is known to be open, OpenNetworkCount and OpenAutoConnectCount are null. EnterpriseNoServerValidationCount is null when some 802.1X profile could not be classified and none is known to skip validation. CorporatePskNetworkCount is null when no corporate SSID list was supplied. ConnectedManagementFrameProtection is true only when the negotiated AKM suite mandates it and null otherwise. Over-the-air, rogue-AP and evil-twin testing require a monitor-mode adapter and physical presence, and are a separate layer.'

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
    limitations=@('Lab version, not validated on the five target Windows platforms.',
      'Missing-patch and CVE determination is performed off-host from the recorded servicing level against vendor data; this collector makes no vulnerability claim itself.',
      'Directory evidence covers identity, policy, privileged group membership, trusts and applied policy objects. It does NOT perform attack-path analysis, expand nested group membership, or assess packet capture, application or cloud.',
      'Wireless assessment is host-side 802.11 configuration only (saved all-user profiles, encryption, auto-join, 802.1X server-certificate validation) parsed from netsh with English labels; per-user profiles are not read. It does NOT include over-the-air, rogue-AP, evil-twin or controller-side testing, which require a monitor-mode adapter and physical presence.',
      'Collection can trigger normal OS, security and domain-resolution activity; not zero network traffic.',
      'MaxItems bounds retained rows, not all provider enumeration work. Run.ps1 bounds its wait, but cancellation/cleanup require Windows validation.',
      'Read-only target intent: evidence files and OS execution logs are expected side effects.')
}
$result | ConvertTo-Json -Depth 12
