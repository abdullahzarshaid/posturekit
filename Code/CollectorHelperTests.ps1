#requires -Version 5.1
<#
PostureKit | version 0.6
Executable fixture tests for the pure wireless helpers in Collect.ps1.
The helpers are loaded by reading Collect.ps1 and extracting the text between the
"# ---- BEGIN WIRELESS HELPERS ----" and "# ---- END WIRELESS HELPERS ----" markers, so
the code under test is byte-identical to the shipped collector. No external modules,
no Wi-Fi adapter, no netsh call and no pre-shared key is involved.
Run: powershell -NoProfile -ExecutionPolicy Bypass -File Code\CollectorHelperTests.ps1
Prints one PASS/FAIL line per fixture and exits 1 on any failure.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSCommandPath
$collector = Join-Path $root 'Collect.ps1'
$source = Get-Content -LiteralPath $collector -Raw -ErrorAction Stop
$beginMarker = '# ---- BEGIN WIRELESS HELPERS ----'
$endMarker = '# ---- END WIRELESS HELPERS ----'
$begin = $source.IndexOf($beginMarker)
$end = $source.IndexOf($endMarker)
if ($begin -lt 0 -or $end -le $begin) { Write-Host 'FAIL  helper region markers not found in Collect.ps1'; exit 1 }
$region = $source.Substring($begin, $end - $begin)
if ($region -match '(?m)^\s*(&\s*)?(netsh|Get-NetAdapter|Get-Content|Get-ChildItem|New-Item|Remove-Item)\b') {
    Write-Host 'FAIL  helper region contains a side-effecting command; the helpers must stay pure'; exit 1
}
Invoke-Expression $region
Write-Host ("Loaded helper region from Collect.ps1 ({0} characters)." -f $region.Length)

$script:Pass = 0; $script:Fail = 0
function Check {
    param([string]$Label, [scriptblock]$Body)
    $ok = $false; $detail = ''
    try { $ok = [bool](& $Body) } catch { $ok = $false; $detail = ' (' + $_.Exception.Message + ')' }
    if ($ok) { $script:Pass++; Write-Host ('PASS  ' + $Label) }
    else { $script:Fail++; Write-Host ('FAIL  ' + $Label + $detail) }
}
function Adapter { param([string]$Name, [string]$Desc, [int]$Type, [string]$Media)
    [pscustomobject]@{ Name=$Name; InterfaceDescription=$Desc; InterfaceType=$Type; PhysicalMediaType=$Media } }
$wifiAdapters = @(
    (Adapter 'Wi-Fi' 'Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter' 71 'Native 802.11'),
    (Adapter 'Ethernet' 'Realtek PCIe GbE Family Controller' 6 '802.3'))
$wiredOnly = @(
    (Adapter 'Ethernet' 'Intel(R) I219-LM' 6 '802.3'),
    (Adapter 'vEthernet (Default Switch)' 'Hyper-V Virtual Ethernet Adapter' 6 'Unspecified'))

# ---------------------------------------------------------------- netsh texts
$ifaceEnglishOne = @"

There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter
    State                  : connected
    SSID                   : CORP-WIFI
    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher =  00-0f-ac:04 ]
    Authentication         : WPA2-Personal
    Cipher                 : CCMP

"@
$ifaceEnglishTwo = "`r`nThere are 2 interfaces on the system:`r`n`r`n    Name : Wi-Fi`r`n"
$ifaceEnglishNone = "`r`nThere is no wireless interface on the system.`r`n`r`n"
$ifaceGerman = "`r`nEs ist 1 Schnittstelle auf dem System vorhanden:`r`n`r`n    Name                   : WLAN`r`n    Status                 : Verbunden`r`n"
$ifaceSvcDown = "`r`nThe Wireless AutoConfig Service (wlansvc) is not running.`r`n`r`n"
$ifaceDenied = "`r`nAccess is denied.`r`n`r`n"

$profilesNormal = @"

Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : CORP-WIFI
    All User Profile     : Coffee Bean

"@
# The third name carries a trailing space, as netsh prints it. It is appended here explicitly so
# that no editor can strip the whitespace from a here-string line.
$profilesNormal = $profilesNormal.TrimEnd("`r", "`n") + "`r`n" + '    All User Profile     : GDA CONTROL ' + "`r`n`r`n"
$profilesEmptyMessage = "`r`nThere is no profile assigned to the specified interface.`r`n`r`n"
$profilesEmptySection = "`r`nProfiles on interface Wi-Fi:`r`n`r`nGroup policy profiles (read only)`r`n---------------------------------`r`n    <None>`r`n`r`nUser profiles`r`n-------------`r`n    <None>`r`n`r`n"
$profilesFailed = "`r`nThe Wireless AutoConfig Service (wlansvc) is not running.`r`n`r`n"
$profilesGerman = "`r`nProfile auf Schnittstelle WLAN:`r`n`r`nBenutzerprofile`r`n---------------`r`n    Profil fuer alle Benutzer     : CORP-WIFI`r`n"

# ---------------------------------------------------------------- profile XML
# Exported profile layout per the Microsoft WLAN profile / EapHostConfig schemas. No key material.
function Wrap-Profile { param([string]$EapMethodType, [string]$ConfigInner)
@"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>CORP-WIFI</name>
  <SSIDConfig><SSID><name>CORP-WIFI</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption><authentication>WPA2</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>machineOrUser</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">$EapMethodType</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
            </EapMethod>
            <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
$ConfigInner
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
"@
}
function Peap-Config { param([string]$Perform, [string]$Root = 'ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01', [string]$Names = 'radius.corp.example')
    $psv = if ($null -ne $Perform -and $Perform -ne '') { "<PerformServerValidation xmlns=`"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2`">$Perform</PerformServerValidation>" } else { '' }
@"
              <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                <Type>25</Type>
                <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
                  <ServerValidation>
                    <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                    <ServerNames>$Names</ServerNames>
                    <TrustedRootCA>$Root</TrustedRootCA>
                  </ServerValidation>
                  <FastReconnect>true</FastReconnect>
                  <InnerEapOptional>false</InnerEapOptional>
                  <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                    <Type>26</Type>
                    <EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType>
                  </Eap>
                  <EnableQuarantineChecks>false</EnableQuarantineChecks>
                  <RequireCryptoBinding>false</RequireCryptoBinding>
                  <PeapExtensions>
                    $psv
                    <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</AcceptServerName>
                  </PeapExtensions>
                </EapType>
              </Eap>
"@
}
function Tls-Config { param([string]$Prompt, [string[]]$Roots, [string]$Names = '')
    $rootXml = ''
    foreach ($r in @($Roots)) { if ($null -ne $r) { $rootXml += "<TrustedRootCA>$r</TrustedRootCA>" } }
    $promptXml = if ($null -ne $Prompt -and $Prompt -ne '') { "<DisableUserPromptForServerValidation>$Prompt</DisableUserPromptForServerValidation>" } else { '' }
@"
              <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                <Type>13</Type>
                <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                  <CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>
                  <ServerValidation>
                    $promptXml
                    <ServerNames>$Names</ServerNames>
                    $rootXml
                  </ServerValidation>
                  <DifferentUsername>false</DifferentUsername>
                </EapType>
              </Eap>
"@
}
function Ttls-Config { param([string]$Prompt, [string[]]$Hashes, [string]$Names = '', [bool]$Block = $true)
    $hashXml = ''
    foreach ($h in @($Hashes)) { if ($null -ne $h) { $hashXml += "<TrustedRootCAHash>$h</TrustedRootCAHash>" } }
    $promptXml = if ($null -ne $Prompt -and $Prompt -ne '') { "<DisablePrompt>$Prompt</DisablePrompt>" } else { '' }
    $sv = if ($Block) { "<ServerValidation><ServerNames>$Names</ServerNames>$hashXml$promptXml</ServerValidation>" } else { '' }
    # EAP-TTLS writes its configuration element directly under Config, not inside a BaseEap wrapper.
@"
              <EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">
                $sv
                <Phase2Authentication><PAPAuthentication /></Phase2Authentication>
                <Phase1Identity><IdentityPrivacy>false</IdentityPrivacy></Phase1Identity>
              </EapTtls>
"@
}
$rootA = '01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67'
$hashA = '0123456789abcdef0123456789abcdef01234567'
$xmlTtlsTrue = Wrap-Profile 21 (Ttls-Config 'true' @($hashA))
$xmlTtlsPromptAllowed = Wrap-Profile 21 (Ttls-Config 'false' @($hashA))
$xmlTtlsNoRoot = Wrap-Profile 21 (Ttls-Config 'true' @())
$xmlTtlsNoBlock = Wrap-Profile 21 (Ttls-Config '' @() '' $false)
$xmlTtlsNamesOnly = Wrap-Profile 21 (Ttls-Config 'true' @() 'radius.corp.example')
$xmlPeapTrue = Wrap-Profile 25 (Peap-Config 'true')
$xmlPeapFalse = Wrap-Profile 25 (Peap-Config 'false')
$xmlPeapMissingElement = Wrap-Profile 25 (Peap-Config '')
$xmlTlsRootNoPrompt = Wrap-Profile 13 (Tls-Config 'true' @($rootA))
$xmlTlsPromptAllowed = Wrap-Profile 13 (Tls-Config 'false' @($rootA))
$xmlTlsNoRoot = Wrap-Profile 13 (Tls-Config 'true' @())
$xmlTlsTwoRootsNames = Wrap-Profile 13 (Tls-Config 'true' @($rootA, 'ff ee dd cc bb aa 99 88 77 66 55 44 33 22 11 00 ff ee dd cc') 'nps.corp.example')
$xmlMalformed = '<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>Broken</name><MSM><security>'
# Same PEAP content written with explicit namespace prefixes instead of default namespaces.
$xmlNamespaced = @"
<?xml version="1.0"?>
<w:WLANProfile xmlns:w="http://www.microsoft.com/networking/WLAN/profile/v1" xmlns:x="http://www.microsoft.com/networking/OneX/v1" xmlns:h="http://www.microsoft.com/provisioning/EapHostConfig" xmlns:c="http://www.microsoft.com/provisioning/EapCommon" xmlns:b="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1" xmlns:p="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1" xmlns:q="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">
  <w:name>CORP-WIFI</w:name>
  <w:MSM><w:security>
    <x:OneX>
      <x:EAPConfig>
        <h:EapHostConfig>
          <h:EapMethod><c:Type>25</c:Type><c:VendorId>0</c:VendorId><c:VendorType>0</c:VendorType><c:AuthorId>0</c:AuthorId></h:EapMethod>
          <h:Config>
            <b:Eap>
              <b:Type>25</b:Type>
              <p:EapType>
                <p:ServerValidation>
                  <p:DisableUserPromptForServerValidation>true</p:DisableUserPromptForServerValidation>
                  <p:ServerNames></p:ServerNames>
                </p:ServerValidation>
                <p:PeapExtensions>
                  <q:PerformServerValidation>false</q:PerformServerValidation>
                </p:PeapExtensions>
              </p:EapType>
            </b:Eap>
          </h:Config>
        </h:EapHostConfig>
      </x:EAPConfig>
    </x:OneX>
  </w:security></w:MSM>
</w:WLANProfile>
"@
# A regular expression would be fooled by this: the word PerformServerValidation appears only inside a comment.
$xmlCommentTrap = Wrap-Profile 25 ((Peap-Config '') + "`n<!-- <PerformServerValidation>true</PerformServerValidation> -->")

# ================================================================ presence
Check 'presence: English one interface + Wi-Fi adapter -> 1' {
    $r = Resolve-WirelessPresence $ifaceEnglishOne $wifiAdapters
    $r.Present -eq 1 -and $r.InterfaceCount -eq 1 -and $r.NetshUnderstood -and $r.Basis -match 'reports 1 wireless interface' }
Check 'presence: English two interfaces + no adapter list -> 1 (netsh is positive evidence)' {
    $r = Resolve-WirelessPresence $ifaceEnglishTwo $null
    $r.Present -eq 1 -and $r.InterfaceCount -eq 2 }
Check 'presence: English "no wireless interface" + wired-only adapters -> 0' {
    $r = Resolve-WirelessPresence $ifaceEnglishNone $wiredOnly
    ($null -ne $r.Present) -and $r.Present -eq 0 -and $r.NetshUnderstood -and $r.Basis -match 'no 802.11 adapter listed' }
Check 'presence: English "no wireless interface" + Wi-Fi adapter listed -> null (contradiction)' {
    $r = Resolve-WirelessPresence $ifaceEnglishNone $wifiAdapters
    ($null -eq $r.Present) -and $r.Basis -match 'lists an 802.11 adapter \(Wi-Fi\)' }
Check 'presence: English "no wireless interface" + adapter list unavailable -> null' {
    $r = Resolve-WirelessPresence $ifaceEnglishNone $null
    ($null -eq $r.Present) -and $r.Basis -match 'unavailable' }
Check 'presence: German "Es ist 1 Schnittstelle..." + Wi-Fi adapter -> null (not understood, never 0)' {
    $r = Resolve-WirelessPresence $ifaceGerman $wifiAdapters
    ($null -eq $r.Present) -and (-not $r.NetshUnderstood) -and $r.Basis -match 'not understood' -and $r.Basis -match 'Es ist 1 Schnittstelle' }
Check 'presence: German text + adapter list unavailable -> null' {
    $r = Resolve-WirelessPresence $ifaceGerman $null
    ($null -eq $r.Present) -and $r.Basis -match 'not understood' }
Check 'presence: German text + wired-only adapters -> 0 (adapter list proves absence)' {
    $r = Resolve-WirelessPresence $ifaceGerman $wiredOnly
    ($null -ne $r.Present) -and $r.Present -eq 0 -and $r.Basis -match 'not understood' -and $r.Basis -match 'no 802.11 adapter listed' }
Check 'presence: service not running + Wi-Fi adapter listed -> null' {
    $r = Resolve-WirelessPresence $ifaceSvcDown $wifiAdapters
    ($null -eq $r.Present) -and $r.Basis -match 'wlansvc\) is not running' -and $r.Basis -match 'Wi-Fi' }
Check 'presence: service not running + wired-only adapters -> 0 with basis "no 802.11 adapter listed"' {
    $r = Resolve-WirelessPresence $ifaceSvcDown $wiredOnly
    ($null -ne $r.Present) -and $r.Present -eq 0 -and $r.Basis -match 'no 802.11 adapter listed' }
Check 'presence: service not running + adapter list unavailable -> null' {
    $r = Resolve-WirelessPresence $ifaceSvcDown $null
    ($null -eq $r.Present) }
Check 'presence: access denied + Wi-Fi adapter -> null' {
    $r = Resolve-WirelessPresence $ifaceDenied $wifiAdapters
    ($null -eq $r.Present) -and $r.Basis -match 'access denied' }
Check 'presence: empty netsh output + adapter list unavailable -> null' {
    $r = Resolve-WirelessPresence '' $null
    ($null -eq $r.Present) -and $r.Basis -match 'no output' }
Check 'presence: null netsh output -> null, no exception' {
    $r = Resolve-WirelessPresence $null $null
    ($null -eq $r.Present) }
Check 'adapter: PhysicalMediaType "Native 802.11" alone is enough' {
    Test-WirelessAdapter (Adapter 'LAN 3' 'Vendor NIC' 6 'Native 802.11') }
Check 'adapter: InterfaceType 71 alone is enough' {
    Test-WirelessAdapter (Adapter 'LAN 3' 'Vendor NIC' 71 '') }
Check 'adapter: description containing "Wireless" alone is enough' {
    Test-WirelessAdapter (Adapter 'LAN 3' 'Qualcomm Atheros Wireless Network Adapter' 6 '') }
Check 'adapter: name "WiFi" (no hyphen) matches' {
    Test-WirelessAdapter (Adapter 'WiFi' 'x' 6 '') }
Check 'adapter: plain Ethernet is not wireless' {
    -not (Test-WirelessAdapter (Adapter 'Ethernet' 'Realtek PCIe GbE Family Controller' 6 '802.3')) }
Check 'adapter: object missing properties does not throw under StrictMode' {
    -not (Test-WirelessAdapter ([pscustomobject]@{ Name='Ethernet' })) }
Check 'adapter: Get-WirelessAdapterNames returns only the 802.11 names' {
    $n = @(Get-WirelessAdapterNames $wifiAdapters); $n.Count -eq 1 -and $n[0] -eq 'Wi-Fi' }

# ================================================================ profile list
Check 'profiles: normal list -> understood, 3 names' {
    $r = Resolve-WirelessProfileList $profilesNormal
    $r.Understood -and @($r.Names).Count -eq 3 -and $r.Names[0] -eq 'CORP-WIFI' -and $r.Names[1] -eq 'Coffee Bean' }
Check 'profiles: a trailing space in a profile name is preserved (netsh needs the exact name)' {
    $r = Resolve-WirelessProfileList $profilesNormal
    $r.Names[2] -ceq 'GDA CONTROL ' }
Check 'profiles: "There is no profile" message -> understood, empty' {
    $r = Resolve-WirelessProfileList $profilesEmptyMessage
    $r.Understood -and @($r.Names).Count -eq 0 -and $null -eq $r.Error }
Check 'profiles: User profiles section with <None> -> understood, empty' {
    $r = Resolve-WirelessProfileList $profilesEmptySection
    $r.Understood -and @($r.Names).Count -eq 0 }
Check 'profiles: failed command text (service not running) -> not understood, Error set' {
    $r = Resolve-WirelessProfileList $profilesFailed
    (-not $r.Understood) -and @($r.Names).Count -eq 0 -and $r.Error -match 'not understood' -and $r.Error -match 'wlansvc' }
Check 'profiles: German list -> not understood (not an empty Collected list)' {
    $r = Resolve-WirelessProfileList $profilesGerman
    (-not $r.Understood) -and $r.Error -match 'not understood' }
Check 'profiles: empty text -> not understood' {
    $r = Resolve-WirelessProfileList ''
    (-not $r.Understood) -and $r.Error -match 'no output' }

# ================================================================ EAP server validation
Check 'eap: PEAP PerformServerValidation true -> true, root count 1, names present' {
    $r = Resolve-EapServerValidation $xmlPeapTrue
    ($r.ServerCertValidation -is [bool]) -and $r.ServerCertValidation -and $r.EapType -eq 25 -and $r.TrustedRootCount -eq 1 -and $r.ServerNamesPresent -and $r.ServerCertValidationBasis -match 'PerformServerValidation is true' }
Check 'eap: PEAP PerformServerValidation false -> false (root list does not override)' {
    $r = Resolve-EapServerValidation $xmlPeapFalse
    ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) -and $r.TrustedRootCount -eq 1 -and $r.ServerCertValidationBasis -match 'PerformServerValidation is false' }
Check 'eap: PEAP missing PerformServerValidation element -> null with basis' {
    $r = Resolve-EapServerValidation $xmlPeapMissingElement
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'PerformServerValidation element is missing' }
Check 'eap: PEAP element only inside an XML comment -> null (namespace navigation, not regex)' {
    $r = Resolve-EapServerValidation $xmlCommentTrap
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'missing' }
Check 'eap: EAP-TLS trusted root pinned and user prompt disabled -> true' {
    $r = Resolve-EapServerValidation $xmlTlsRootNoPrompt
    ($r.ServerCertValidation -is [bool]) -and $r.ServerCertValidation -and $r.EapType -eq 13 -and $r.TrustedRootCount -eq 1 -and (-not $r.ServerNamesPresent) }
Check 'eap: EAP-TLS user prompt allowed -> false' {
    $r = Resolve-EapServerValidation $xmlTlsPromptAllowed
    ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'user can accept any server' }
Check 'eap: EAP-TLS block without trusted root or server names -> null with basis' {
    $r = Resolve-EapServerValidation $xmlTlsNoRoot
    ($null -eq $r.ServerCertValidation) -and $r.TrustedRootCount -eq 0 -and (-not $r.ServerNamesPresent) -and $r.ServerCertValidationBasis -match 'no trusted root CA and no server names' }
Check 'eap: EAP-TLS two roots and server names -> true, TrustedRootCount 2, ServerNamesPresent true' {
    $r = Resolve-EapServerValidation $xmlTlsTwoRootsNames
    $r.ServerCertValidation -and $r.TrustedRootCount -eq 2 -and $r.ServerNamesPresent }
Check 'eap: EAP-TTLS DisablePrompt true with a root hash -> true, TrustedRootCount 1' {
    $r = Resolve-EapServerValidation $xmlTtlsTrue
    ($r.ServerCertValidation -is [bool]) -and $r.ServerCertValidation -and $r.EapType -eq 21 -and $r.TrustedRootCount -eq 1 -and (-not $r.ServerNamesPresent) -and $r.ServerCertValidationBasis -match 'DisablePrompt is true' }
Check 'eap: EAP-TTLS prompt allowed (DisablePrompt false) -> false' {
    $r = Resolve-EapServerValidation $xmlTtlsPromptAllowed
    ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'user can accept any server' }
Check 'eap: EAP-TTLS block without root hash or server names -> null with basis' {
    $r = Resolve-EapServerValidation $xmlTtlsNoRoot
    ($null -eq $r.ServerCertValidation) -and $r.TrustedRootCount -eq 0 -and $r.ServerCertValidationBasis -match 'no trusted root CA hash and no server names' }
Check 'eap: EAP-TTLS ServerValidation block absent -> null with basis' {
    $r = Resolve-EapServerValidation $xmlTtlsNoBlock
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'ServerValidation block is missing' }
Check 'eap: EAP-TTLS server names only, no root hash -> null, ServerNamesPresent true' {
    $r = Resolve-EapServerValidation $xmlTtlsNamesOnly
    ($null -eq $r.ServerCertValidation) -and $r.ServerNamesPresent -and $r.TrustedRootCount -eq 0 -and $r.ServerCertValidationBasis -match 'server names only' }
Check 'eap: PerformServerValidation inside a TTLS profile is ignored (PEAP rule only)' {
    $x = Wrap-Profile 21 ((Ttls-Config 'false' @($hashA)) + '<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>')
    $r = Resolve-EapServerValidation $x
    ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) }
Check 'eap: malformed XML -> null with parse basis' {
    $r = Resolve-EapServerValidation $xmlMalformed
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'could not be parsed' }
Check 'eap: explicitly prefixed namespaces resolve the same elements (PEAP false)' {
    $r = Resolve-EapServerValidation $xmlNamespaced
    ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) -and $r.EapType -eq 25 -and $r.TrustedRootCount -eq 0 -and (-not $r.ServerNamesPresent) }
Check 'eap: missing XML (null) -> null with basis' {
    $r = Resolve-EapServerValidation $null
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'No profile XML' }
Check 'eap: profile without EapHostConfig (not 802.1X) -> null with basis' {
    $r = Resolve-EapServerValidation '<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>Home</name></WLANProfile>'
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'EapHostConfig/EapMethod/Type' }
Check 'eap: unsupported EAP type (43) -> null with basis naming the type' {
    $r = Resolve-EapServerValidation (Wrap-Profile 43 '<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>43</Type></Eap>')
    ($null -eq $r.ServerCertValidation) -and $r.EapType -eq 43 -and $r.ServerCertValidationBasis -match 'EAP type 43' }

# ================================================================ PMF
Check 'pmf: AKM 2 (WPA2-PSK) -> null, basis names the suite and the RSN-bits limitation' {
    $r = Resolve-Pmf 2
    ($null -eq $r.Pmf) -and $r.Basis -match '00-0f-ac:02 \(PSK\)' -and $r.Basis -match 'RSN capability bits' -and $r.Basis -match 'not proof' }
Check 'pmf: AKM 6 (PSK-SHA256) -> true' { $r = Resolve-Pmf 6; ($r.Pmf -is [bool]) -and $r.Pmf -and $r.Basis -match 'PSK-SHA256' }
Check 'pmf: AKM 8 (SAE) -> true' { $r = Resolve-Pmf 8; ($r.Pmf -is [bool]) -and $r.Pmf -and $r.Basis -match 'SAE' }
Check 'pmf: AKM 5 (802.1X-SHA256) -> true' { $r = Resolve-Pmf 5; ($r.Pmf -is [bool]) -and $r.Pmf }
Check 'pmf: AKM 1 (802.1X SHA-1) -> null, never false' { $r = Resolve-Pmf 1; ($null -eq $r.Pmf) -and ($r.Pmf -isnot [bool]) }
Check 'pmf: no AKM suite -> null with basis' { $r = Resolve-Pmf $null; ($null -eq $r.Pmf) -and $r.Basis -match 'No AKM suite' }
Check 'pmf: AKM suite parsed from the netsh text (00-0f-ac:02 -> 2)' { (Get-AkmSuite $ifaceEnglishOne) -eq 2 }
Check 'pmf: AKM suite absent from text -> null' { $null -eq (Get-AkmSuite $ifaceEnglishNone) }

# ================================================================ connected state
Check 'connected: "connected" -> true' { Test-WlanConnected 'connected' }
Check 'connected: "disconnected" -> false' { -not (Test-WlanConnected 'disconnected') }
Check 'connected: surrounding whitespace tolerated' { Test-WlanConnected '  connected ' }
Check 'connected: null -> false' { -not (Test-WlanConnected $null) }
Check 'connected: German "Verbunden" -> false (only the English word is recognised)' { -not (Test-WlanConnected 'Verbunden') }

# ================================================================ posture aggregate
function Prof { param([string]$Name, [string]$Auth, [bool]$Dot1X, [object]$Val)
    [pscustomobject]@{ Name=$Name; Authentication=$Auth; Dot1X=$Dot1X; ServerCertValidation=$Val } }
Check 'aggregate: one false, one true -> NoValidation 1, Unknown 0' {
    $r = Resolve-EnterpriseValidationCounts @((Prof 'A' 'WPA2-Enterprise' $true $false), (Prof 'B' 'WPA2-Enterprise' $true $true))
    $r.EnterpriseNetworkCount -eq 2 -and $r.EnterpriseNoServerValidationCount -eq 1 -and $r.EnterpriseServerValidationUnknownCount -eq 0 }
Check 'aggregate: one null, one true -> NoValidation emitted as null, Unknown 1' {
    $r = Resolve-EnterpriseValidationCounts @((Prof 'A' 'WPA2-Enterprise' $true $null), (Prof 'B' 'WPA2-Enterprise' $true $true))
    ($null -eq $r.EnterpriseNoServerValidationCount) -and $r.EnterpriseServerValidationUnknownCount -eq 1 }
Check 'aggregate: one null, one false -> NoValidation 1 (known false wins), Unknown 1' {
    $r = Resolve-EnterpriseValidationCounts @((Prof 'A' 'WPA2-Enterprise' $true $null), (Prof 'B' 'WPA2-Enterprise' $true $false))
    $r.EnterpriseNoServerValidationCount -eq 1 -and $r.EnterpriseServerValidationUnknownCount -eq 1 }
Check 'aggregate: PSK profiles are not enterprise; no 802.1X -> 0 / 0' {
    $r = Resolve-EnterpriseValidationCounts @((Prof 'A' 'WPA2-Personal' $false $null))
    $r.EnterpriseNetworkCount -eq 0 -and $r.EnterpriseNoServerValidationCount -eq 0 -and $r.EnterpriseServerValidationUnknownCount -eq 0 }
Check 'aggregate: empty profile list -> 0 / 0' {
    $r = Resolve-EnterpriseValidationCounts @()
    $r.EnterpriseNoServerValidationCount -eq 0 -and $r.EnterpriseServerValidationUnknownCount -eq 0 }

# ================================================================ open / unreadable aggregate
function OProf { param([string]$Name, [object]$Auth, [string]$Mode = 'Connect automatically')
    [pscustomobject]@{ Name=$Name; Authentication=$Auth; ConnectionMode=$Mode } }
Check 'open: one null-auth profile only -> OpenNetworkCount null, OpenAutoConnectCount null, Unreadable 1 with name' {
    $r = Resolve-OpenNetworkCounts @((OProf 'Mangled' $null), (OProf 'Home' 'WPA2-Personal'))
    ($null -eq $r.OpenNetworkCount) -and ($null -eq $r.OpenAutoConnectCount) -and $r.UnreadableProfileCount -eq 1 -and @($r.UnreadableProfileNames)[0] -eq 'Mangled' }
Check 'open: one open plus one null -> OpenNetworkCount 1, OpenAutoConnectCount 1, Unreadable 1' {
    $r = Resolve-OpenNetworkCounts @((OProf 'Cafe' 'Open'), (OProf 'Mangled' $null))
    $r.OpenNetworkCount -eq 1 -and $r.OpenAutoConnectCount -eq 1 -and $r.UnreadableProfileCount -eq 1 }
Check 'open: empty-string auth counts as unreadable, not open' {
    $r = Resolve-OpenNetworkCounts @((OProf 'Blank' ''))
    ($null -eq $r.OpenNetworkCount) -and $r.UnreadableProfileCount -eq 1 }
Check 'open: open profile with manual connection -> OpenNetworkCount 1, OpenAutoConnectCount 0' {
    $r = Resolve-OpenNetworkCounts @((OProf 'Cafe' 'Open' 'Connect manually'))
    $r.OpenNetworkCount -eq 1 -and $r.OpenAutoConnectCount -eq 0 -and $r.UnreadableProfileCount -eq 0 }
Check 'open: all readable, none open -> 0 / 0 (integers, not null)' {
    $r = Resolve-OpenNetworkCounts @((OProf 'Home' 'WPA2-Personal'), (OProf 'Work' 'WPA2-Enterprise'))
    ($r.OpenNetworkCount -is [int]) -and $r.OpenNetworkCount -eq 0 -and $r.OpenAutoConnectCount -eq 0 -and $r.UnreadableProfileCount -eq 0 }
Check 'open: empty list -> 0 / 0 / 0' {
    $r = Resolve-OpenNetworkCounts @()
    $r.OpenNetworkCount -eq 0 -and $r.OpenAutoConnectCount -eq 0 -and $r.UnreadableProfileCount -eq 0 }

# ================================================================ corporate PSK
$pskProfiles = @((Prof 'CORP-WIFI' 'WPA2-Personal' $false $null), (Prof 'Coffee Bean' 'WPA2-Personal' $false $null),
                 (Prof 'CORP-SECURE' 'WPA2-Enterprise' $true $true), (Prof 'GDA CONTROL ' 'WPA2-Personal' $false $null))
Check 'corporate: no SSID list supplied -> null' { $null -eq (Get-CorporatePskCount $pskProfiles $null) }
Check 'corporate: list "CORP-WIFI;CORP-SECURE" -> 1 (enterprise profile excluded)' {
    (Get-CorporatePskCount $pskProfiles (ConvertFrom-CorporateSsidList 'CORP-WIFI;CORP-SECURE')) -eq 1 }
Check 'corporate: name match is case-insensitive and ignores trailing spaces' {
    (Get-CorporatePskCount $pskProfiles (ConvertFrom-CorporateSsidList 'corp-wifi; gda control')) -eq 2 }
Check 'corporate: list with no matching profile -> 0 (an integer, not null)' {
    $v = Get-CorporatePskCount $pskProfiles (ConvertFrom-CorporateSsidList 'Other'); ($v -is [int]) -and $v -eq 0 }
Check 'corporate: env text absent / empty / only separators -> null list' {
    ($null -eq (ConvertFrom-CorporateSsidList $null)) -and ($null -eq (ConvertFrom-CorporateSsidList '')) -and ($null -eq (ConvertFrom-CorporateSsidList ' ; ;')) }
Check 'corporate: env text "A; B;" -> two trimmed entries' {
    $l = @(ConvertFrom-CorporateSsidList 'A; B;'); $l.Count -eq 2 -and $l[0] -eq 'A' -and $l[1] -eq 'B' }

# ================================================================ netsh field reader
Check 'field: Get-NetshField reads State from the interface text' { (Get-NetshField $ifaceEnglishOne 'State') -eq 'connected' }
Check 'field: Get-NetshField returns null for an absent key' { $null -eq (Get-NetshField $ifaceEnglishOne 'Nonexistent') }

Write-Host ''
Write-Host ("RESULT  passed={0} failed={1}" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 }
exit 0
