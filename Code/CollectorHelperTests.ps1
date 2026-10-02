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
# EAP-TLS profile shapes. The V1 schema (EapTlsConnectionPropertiesV1) holds only the ServerValidation
# block: DisableUserPromptForServerValidation (the prompt policy), ServerNames and TrustedRootCA. The
# enablement element PerformServerValidation lives in the V2 namespace
# (EapTlsConnectionPropertiesV2) as a child of EapType next to AcceptServerName. Microsoft's own
# WPA3-Enterprise 192-bit TLS sample has PerformServerValidation true together with
# DisableUserPromptForServerValidation false, which shows the two settings are independent:
#   https://learn.microsoft.com/en-us/windows/win32/nativewifi/wpa3-enterprise-192bit-with-tls-profile-sample
#   https://learn.microsoft.com/en-us/windows/win32/eaphost/eaptlsconnectionpropertiesv1schema-disableuserpromptforservervalidation-servervalidationparameters-element
# $Perform '' produces a V1-only profile (no V2 element); 'true' / 'false' add the V2 element.
function Tls-Config { param([string]$Prompt, [string[]]$Roots, [string]$Names = '', [string]$Perform = '')
    $rootXml = ''
    foreach ($r in @($Roots)) { if ($null -ne $r) { $rootXml += "<TrustedRootCA>$r</TrustedRootCA>" } }
    $promptXml = if ($null -ne $Prompt -and $Prompt -ne '') { "<DisableUserPromptForServerValidation>$Prompt</DisableUserPromptForServerValidation>" } else { '' }
    $v2Xml = ''
    if ($null -ne $Perform -and $Perform -ne '') {
        $v2Xml = "<PerformServerValidation xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`">$Perform</PerformServerValidation>" +
                 "<AcceptServerName xmlns=`"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2`">false</AcceptServerName>"
    }
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
                  $v2Xml
                </EapType>
              </Eap>
"@
}
# The Microsoft WPA3-Enterprise 192-bit TLS sample (first page above), transcribed as published
# on 2025-05-14: a V1 ServerValidation block with DisableUserPromptForServerValidation false,
# empty ServerNames and one placeholder TrustedRootCA, then the V2 PerformServerValidation true
# and AcceptServerName true. The sample's element text carries a line break before the closing
# tag, which is kept here because the reader must trim it.
$xmlTlsMicrosoftSample = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>WPA3Enterprise192BitMode</name>
    <SSIDConfig>
        <SSID>
            <name>WPA3Enterprise192BitMode</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA3ENT192</authentication>
                <encryption>GCMP256</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <authMode>user</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13
                            </Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0
                            </VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0
                            </VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0
                            </AuthorId>
                        </EapMethod>
                        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                <Type>13</Type>
                                <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
                                    <CredentialsSource>
                                        <CertificateStore>
                                            <SimpleCertSelection>true</SimpleCertSelection>
                                        </CertificateStore>
                                    </CredentialsSource>
                                    <ServerValidation>
                                        <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
                                        <ServerNames></ServerNames>
                                        <TrustedRootCA>00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 </TrustedRootCA>
                                    </ServerValidation>
                                    <DifferentUsername>false</DifferentUsername>
                                    <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true
                                    </PerformServerValidation>
                                    <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true
                                    </AcceptServerName>
                                </EapType>
                            </Eap>
                        </Config>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
    </MSM>
</WLANProfile>
"@
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
$xmlTlsV2FalseNoPromptRoot = Wrap-Profile 13 (Tls-Config 'true' @($rootA) '' 'false')
$xmlTlsV2TruePromptAllowed = Wrap-Profile 13 (Tls-Config 'false' @($rootA) '' 'true')
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
# PEAP prompt policy: Peap-Config writes DisableUserPromptForServerValidation true, so override is false.
Check 'eap: PEAP prompt disabled -> UserOverrideAllowed false (separate from PerformServerValidation)' {
    $r = Resolve-EapServerValidation $xmlPeapFalse
    ($r.UserOverrideAllowed -is [bool]) -and (-not $r.UserOverrideAllowed) -and $r.UserOverrideBasis -match 'DisableUserPromptForServerValidation is true' -and ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) }
# EAP-TLS. The prompt policy never decides ServerCertValidation; only the V2 PerformServerValidation does.
Check 'eap: EAP-TLS V1 only (root pinned, prompt disabled) -> ServerCertValidation null, UserOverrideAllowed false, root count 1' {
    $r = Resolve-EapServerValidation $xmlTlsRootNoPrompt
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'V1 profile, enablement not stated' -and $r.EapType -eq 13 -and $r.TrustedRootCount -eq 1 -and (-not $r.ServerNamesPresent) -and ($r.UserOverrideAllowed -is [bool]) -and (-not $r.UserOverrideAllowed) }
Check 'eap: EAP-TLS prompt allowed -> UserOverrideAllowed true, ServerCertValidation null (no V2 element)' {
    $r = Resolve-EapServerValidation $xmlTlsPromptAllowed
    ($r.UserOverrideAllowed -is [bool]) -and $r.UserOverrideAllowed -and $r.UserOverrideBasis -match 'DisableUserPromptForServerValidation is false' -and ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'V1 profile, enablement not stated' }
Check 'eap: EAP-TLS V1 block without trusted root or server names -> null, root count 0, names absent' {
    $r = Resolve-EapServerValidation $xmlTlsNoRoot
    ($null -eq $r.ServerCertValidation) -and $r.TrustedRootCount -eq 0 -and (-not $r.ServerNamesPresent) -and $r.ServerCertValidationBasis -match 'enablement not stated' }
Check 'eap: EAP-TLS V1 two roots and server names -> null, TrustedRootCount 2, ServerNamesPresent true' {
    $r = Resolve-EapServerValidation $xmlTlsTwoRootsNames
    ($null -eq $r.ServerCertValidation) -and $r.TrustedRootCount -eq 2 -and $r.ServerNamesPresent }
Check 'eap: EAP-TLS V2 PerformServerValidation false, prompt disabled, root present -> false, override false, root count 1' {
    $r = Resolve-EapServerValidation $xmlTlsV2FalseNoPromptRoot
    ($r.ServerCertValidation -is [bool]) -and (-not $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'PerformServerValidation \(V2\) is false' -and ($r.UserOverrideAllowed -is [bool]) -and (-not $r.UserOverrideAllowed) -and $r.TrustedRootCount -eq 1 }
Check 'eap: EAP-TLS V2 PerformServerValidation true with prompt allowed -> true and UserOverrideAllowed true' {
    $r = Resolve-EapServerValidation $xmlTlsV2TruePromptAllowed
    ($r.ServerCertValidation -is [bool]) -and $r.ServerCertValidation -and $r.ServerCertValidationBasis -match 'PerformServerValidation \(V2\) is true' -and ($r.UserOverrideAllowed -is [bool]) -and $r.UserOverrideAllowed }
Check 'eap: Microsoft WPA3-Enterprise TLS sample shape -> true, override true, root count 1, no names' {
    $r = Resolve-EapServerValidation $xmlTlsMicrosoftSample
    ($r.ServerCertValidation -is [bool]) -and $r.ServerCertValidation -and $r.EapType -eq 13 -and ($r.UserOverrideAllowed -is [bool]) -and $r.UserOverrideAllowed -and $r.TrustedRootCount -eq 1 -and (-not $r.ServerNamesPresent) }
Check 'eap: EAP-TLS PerformServerValidation in the PEAP V2 namespace is not the TLS enablement element -> null' {
    $x = Wrap-Profile 13 ((Tls-Config 'true' @($rootA)) + '<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>')
    $r = Resolve-EapServerValidation $x
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'enablement not stated' }
# EAP-TTLS has no enablement element: ServerCertValidation is always null; the override policy and roots are recorded.
Check 'eap: EAP-TTLS DisablePrompt true with a root hash -> ServerCertValidation null (TTLS has no enablement element), override false, TrustedRootCount 1' {
    $r = Resolve-EapServerValidation $xmlTtlsTrue
    ($null -eq $r.ServerCertValidation) -and $r.ServerCertValidationBasis -match 'TTLS has no enablement element' -and $r.EapType -eq 21 -and $r.TrustedRootCount -eq 1 -and (-not $r.ServerNamesPresent) -and ($r.UserOverrideAllowed -is [bool]) -and (-not $r.UserOverrideAllowed) -and $r.UserOverrideBasis -match 'DisablePrompt is true' }
Check 'eap: EAP-TTLS prompt allowed (DisablePrompt false) -> UserOverrideAllowed true, ServerCertValidation null' {
    $r = Resolve-EapServerValidation $xmlTtlsPromptAllowed
    ($null -eq $r.ServerCertValidation) -and ($r.UserOverrideAllowed -is [bool]) -and $r.UserOverrideAllowed -and $r.UserOverrideBasis -match 'DisablePrompt is false' }
Check 'eap: EAP-TTLS block without root hash or server names -> null, root count 0' {
    $r = Resolve-EapServerValidation $xmlTtlsNoRoot
    ($null -eq $r.ServerCertValidation) -and $r.TrustedRootCount -eq 0 -and (-not $r.ServerNamesPresent) -and $r.ServerCertValidationBasis -match 'TTLS has no enablement element' }
Check 'eap: EAP-TTLS ServerValidation block absent -> null, UserOverrideAllowed null with basis' {
    $r = Resolve-EapServerValidation $xmlTtlsNoBlock
    ($null -eq $r.ServerCertValidation) -and ($null -eq $r.UserOverrideAllowed) -and $r.UserOverrideBasis -match 'ServerValidation block is missing' -and $r.TrustedRootCount -eq 0 }
Check 'eap: EAP-TTLS server names only, no root hash -> null, ServerNamesPresent true, override false' {
    $r = Resolve-EapServerValidation $xmlTtlsNamesOnly
    ($null -eq $r.ServerCertValidation) -and $r.ServerNamesPresent -and $r.TrustedRootCount -eq 0 -and ($r.UserOverrideAllowed -is [bool]) -and (-not $r.UserOverrideAllowed) }
Check 'eap: PerformServerValidation inside a TTLS profile is ignored (TTLS stays null, override true)' {
    $x = Wrap-Profile 21 ((Ttls-Config 'false' @($hashA)) + '<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>')
    $r = Resolve-EapServerValidation $x
    ($null -eq $r.ServerCertValidation) -and ($r.UserOverrideAllowed -is [bool]) -and $r.UserOverrideAllowed }
Check 'eap: PEAP ServerValidation block absent -> UserOverrideAllowed null, PerformServerValidation still read' {
    $x = Wrap-Profile 25 ('<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"><PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation></PeapExtensions></EapType></Eap>')
    $r = Resolve-EapServerValidation $x
    ($null -eq $r.UserOverrideAllowed) -and $r.UserOverrideBasis -match 'ServerValidation block is missing' -and ($r.ServerCertValidation -is [bool]) -and $r.ServerCertValidation }
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
    $r.EnterpriseNoServerValidationCount -eq 0 -and $r.EnterpriseServerValidationUnknownCount -eq 0 -and $r.EnterpriseUserOverrideAllowedCount -eq 0 }
function OvProf { param([string]$Name, [bool]$Dot1X, [object]$Val, [object]$Override)
    [pscustomobject]@{ Name=$Name; Authentication='WPA2-Enterprise'; Dot1X=$Dot1X; ServerCertValidation=$Val; UserOverrideAllowed=$Override } }
Check 'aggregate: UserOverrideAllowed true on two of three 802.1X profiles -> OverrideAllowed 2, validation counts untouched' {
    $r = Resolve-EnterpriseValidationCounts @((OvProf 'A' $true $true $true), (OvProf 'B' $true $null $true), (OvProf 'C' $true $true $false), (OvProf 'D' $false $null $true))
    $r.EnterpriseNetworkCount -eq 3 -and $r.EnterpriseUserOverrideAllowedCount -eq 2 -and ($null -eq $r.EnterpriseNoServerValidationCount) -and $r.EnterpriseServerValidationUnknownCount -eq 1 }
Check 'aggregate: profiles without a UserOverrideAllowed property -> OverrideAllowed 0, no exception' {
    $r = Resolve-EnterpriseValidationCounts @((Prof 'A' 'WPA2-Enterprise' $true $true))
    $r.EnterpriseUserOverrideAllowedCount -eq 0 }

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

# ================================================================ posture (inventory status propagation)
function PProf { param([string]$Name, [object]$Auth, [string]$Cipher = 'CCMP', [string]$Mode = 'Connect automatically', [bool]$Dot1X = $false, [object]$Val = $null, [object]$Override = $null)
    [pscustomobject]@{ Name=$Name; ProfileScope='AllUser'; Authentication=$Auth; Cipher=$Cipher; ConnectionMode=$Mode; Dot1X=$Dot1X;
                       ServerCertValidation=$Val; UserOverrideAllowed=$Override; TrustedRootCount=$null; ServerNamesPresent=$null } }
$ifaceConnected = [pscustomobject]@{ State='connected'; Ssid='CORP-WIFI'; Authentication='WPA2-Personal'; Cipher='CCMP'; Band='5 GHz'; RadioType='802.11ax'; AkmSuite=6 }
$presenceOne = [pscustomobject]@{ Present=1; Basis='netsh wlan show interfaces reports 1 wireless interface(s) on the system.' }
$profileCountFields = @('ProfilesTotal','OpenNetworkCount','OpenAutoConnectCount','LegacyEncryptionCount','TkipCipherCount','EnterpriseNetworkCount',
                        'EnterpriseNoServerValidationCount','EnterpriseServerValidationUnknownCount','EnterpriseUserOverrideAllowedCount',
                        'PskNetworkCount','CorporatePskNetworkCount','UnreadableProfileCount')
Check 'posture: whole-list failure (Error) -> every profile-derived count null, connection fields intact' {
    $r = Resolve-WirelessPosture -Profiles @() -InventoryStatus 'Error' -InventoryBasis 'netsh wlan show profiles output was not understood.' `
        -Interface $ifaceConnected -CorporateSsids (ConvertFrom-CorporateSsidList 'CORP-WIFI') -Presence $presenceOne -CorporateSsidSource 'scope'
    $allNull = $true
    foreach ($f in $profileCountFields) { if ($null -ne $r.$f) { $allNull = $false } }
    $allNull -and $r.ProfileInventoryStatus -eq 'Error' -and $r.ProfileInventoryBasis -match 'not understood' -and $r.WirelessPresent -eq 1 -and
        ($r.ConnectedAuthWpa2OrBetter -is [bool]) -and $r.ConnectedAuthWpa2OrBetter -and ($r.ConnectedManagementFrameProtection -is [bool]) -and $r.ConnectedManagementFrameProtection -and
        $r.ConnectedPmfBasis -match 'PSK-SHA256' -and $r.CorporateSsidSource -eq 'scope' }
Check 'posture: Error ignores any profile records that were passed in' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Cafe' 'Open')) -InventoryStatus 'Error' -InventoryBasis 'x' -Interface $null -CorporateSsids $null
    ($null -eq $r.OpenNetworkCount) -and ($null -eq $r.ProfilesTotal) -and ($null -eq $r.ConnectedAuthWpa2OrBetter) -and $r.ConnectedPmfBasis -match 'No wireless interface detail' }
Check 'posture: empty successful list (Collected) -> zeros, not nulls' {
    $r = Resolve-WirelessPosture -Profiles @() -InventoryStatus 'Collected' -InventoryBasis 'netsh wlan show profiles reports that no profile is saved.' `
        -Interface $null -CorporateSsids (ConvertFrom-CorporateSsidList 'CORP-WIFI') -Presence $presenceOne
    $allZero = $true
    foreach ($f in $profileCountFields) { if (-not ($r.$f -is [int]) -or $r.$f -ne 0) { $allZero = $false } }
    $allZero -and $r.ProfileInventoryStatus -eq 'Collected' -and $r.ProfileInventoryBasis -match 'no profile is saved' }
Check 'posture: Collected with no corporate list -> CorporatePskNetworkCount null, other counts integers' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Home' 'WPA2-Personal')) -InventoryStatus 'Collected' -InventoryBasis 'listed 1' -Interface $null -CorporateSsids $null
    ($null -eq $r.CorporatePskNetworkCount) -and $r.PskNetworkCount -eq 1 -and $r.ProfilesTotal -eq 1 -and $r.OpenNetworkCount -eq 0 -and $r.LegacyEncryptionCount -eq 0 }
Check 'posture: one unreadable plus one open profile -> Partial, OpenNetworkCount 1, clean counts null' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Mangled' $null), (PProf 'Cafe' 'Open')) -InventoryStatus 'Collected' -InventoryBasis 'listed 2' `
        -Interface $null -CorporateSsids (ConvertFrom-CorporateSsidList 'CORP-WIFI')
    $r.ProfileInventoryStatus -eq 'Partial' -and $r.ProfileInventoryBasis -match '1 profile\(s\) could not be read \(Mangled\)' -and
        $r.OpenNetworkCount -eq 1 -and $r.OpenAutoConnectCount -eq 1 -and $r.ProfilesTotal -eq 2 -and $r.UnreadableProfileCount -eq 1 -and
        ($null -eq $r.LegacyEncryptionCount) -and ($null -eq $r.TkipCipherCount) -and ($null -eq $r.EnterpriseNoServerValidationCount) -and ($null -eq $r.CorporatePskNetworkCount) -and
        $r.EnterpriseNetworkCount -eq 0 -and $r.PskNetworkCount -eq 0 }
Check 'posture: Partial keeps a known legacy count (a known-bad profile is still a Fail)' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Mangled' $null), (PProf 'Old' 'WPA-Personal' 'TKIP')) -InventoryStatus 'Collected' -InventoryBasis 'listed 2' -Interface $null -CorporateSsids $null
    $r.ProfileInventoryStatus -eq 'Partial' -and $r.LegacyEncryptionCount -eq 1 -and $r.TkipCipherCount -eq 1 -and ($null -eq $r.OpenNetworkCount) -and ($null -eq $r.OpenAutoConnectCount) }
Check 'posture: Partial passed in explicitly with all profiles readable -> stays Partial, zero counts null' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Home' 'WPA2-Personal')) -InventoryStatus 'Partial' -InventoryBasis 'one profile skipped' -Interface $null -CorporateSsids $null
    $r.ProfileInventoryStatus -eq 'Partial' -and ($null -eq $r.LegacyEncryptionCount) -and ($null -eq $r.OpenNetworkCount) -and $r.PskNetworkCount -eq 1 }
Check 'posture: Collected with 802.1X profiles -> enterprise counts carried through, override counted' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Corp' 'WPA2-Enterprise' 'CCMP' 'Connect automatically' $true $false $true), (PProf 'Corp2' 'WPA2-Enterprise' 'CCMP' 'Connect automatically' $true $true $false)) `
        -InventoryStatus 'Collected' -InventoryBasis 'listed 2' -Interface $null -CorporateSsids $null
    $r.EnterpriseNetworkCount -eq 2 -and $r.EnterpriseNoServerValidationCount -eq 1 -and $r.EnterpriseServerValidationUnknownCount -eq 0 -and $r.EnterpriseUserOverrideAllowedCount -eq 1 }
Check 'posture: disconnected interface -> connection fields null with the not-associated basis' {
    $r = Resolve-WirelessPosture -Profiles @() -InventoryStatus 'Collected' -InventoryBasis 'x' -Interface ([pscustomobject]@{ State='disconnected'; Authentication=$null; AkmSuite=$null }) -CorporateSsids $null
    ($null -eq $r.ConnectedAuthWpa2OrBetter) -and ($null -eq $r.ConnectedManagementFrameProtection) -and $r.ConnectedPmfBasis -match 'not associated' }
Check 'posture: unrecognised inventory status is treated as Error' {
    $r = Resolve-WirelessPosture -Profiles @((PProf 'Home' 'WPA2-Personal')) -InventoryStatus 'Whatever' -InventoryBasis $null -Interface $null -CorporateSsids $null
    $r.ProfileInventoryStatus -eq 'Error' -and ($null -eq $r.ProfilesTotal) -and $r.ProfileInventoryBasis -match 'could not be enumerated' }

# ================================================================ netsh field reader
Check 'field: Get-NetshField reads State from the interface text' { (Get-NetshField $ifaceEnglishOne 'State') -eq 'connected' }
Check 'field: Get-NetshField returns null for an absent key' { $null -eq (Get-NetshField $ifaceEnglishOne 'Nonexistent') }

Write-Host ''
Write-Host ("RESULT  passed={0} failed={1}" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 }
exit 0
