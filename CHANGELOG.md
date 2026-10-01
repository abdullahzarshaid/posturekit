# Changelog

All notable changes to PostureKit. The schema version of the evidence files is unchanged (1.0), so batches collected with earlier 0.6 builds still analyze.

## 0.6, build 2026-10-01 release candidate 2

Corrections from an independent review of the 1 October build. The Python suite is now 182 tests, and a PowerShell fixture suite (`Code/CollectorHelperTests.ps1`, 79 checks) exercises the pure wireless helpers of the collector under Windows PowerShell 5.1 with no adapter, no `netsh` call and no pre-shared key involved. Schema version 1.0, tool version 0.6, the 45 sources and the 45 rules are unchanged.

### Shared evidence gate (`Code/EvidenceGate.py`)
- One verification entry point (scope, ledger, digests) is used by `Analyze.py`, `PatchCheck.py` and `SoftwareCheck.py`. A folder without `Batch.json` and `Scope.json` is refused by all three.
- Every enabled target in the scope is accounted for by the patch and software engines: NotAttempted, Excluded and EvidenceRejected hosts appear in the `hosts` list with the reason.
- `ToFindings.py` builds asset coverage gaps from `Coverage.csv` and `Evidence.json`, so a scoped host with no rule rows still appears as a gap and a Partial host lists the sources that were not usable. An explicitly supplied `--patch` or `--software` path that does not exist is recorded as a required-input gap and the run exits 4.

### Collector, wireless states (`Code/Collect.ps1`)
- Wireless presence is decided from the `netsh` text and the adapter list together: 1 when `netsh` reports an interface, 0 only when no 802.11 adapter is listed, otherwise null with `WirelessPresenceBasis` stating why. A stopped WLAN service or non-English text is not treated as proof of absence; null makes the eight WLAN rules Unknown.
- Profile enumeration that fails or is not understood records the `wirelessprofiles` source as Error, never as an empty list. Profile names are used exactly as `netsh` prints them (a trailing space was previously trimmed and the profile read as open), and console output is UTF-8 around the `netsh` calls. A profile whose settings could not be read is counted in `UnreadableProfileCount` (names listed) and never as Open; when any profile is unreadable and no open profile was found, `OpenNetworkCount` and `OpenAutoConnectCount` are null so WLAN01 and WLAN06 record Unknown.
- 802.1X server-certificate validation is parsed from the profile XML by EAP method (PEAP: `PerformServerValidation`; EAP-TLS and EAP-TTLS: the `ServerValidation` block with its prompt flag and trusted roots) with three states and a stated basis. `TrustedRootCount` and `ServerNamesPresent` are recorded separately. Only a profile whose validation is exactly false counts as unvalidated; unknown ones are counted in `EnterpriseServerValidationUnknownCount`, and WLAN04 records Unknown when only unknowns exist.
- Management-frame protection is true only for an AKM suite that mandates it (5, 6, 8, 9, 11, 12, 13, 18, 19, 20); any other suite gives null with `ConnectedPmfBasis`, because `netsh` does not expose the RSN capability bits. WLAN08 records Unknown on plain WPA2-PSK.
- WLAN07 evaluates `CorporatePskNetworkCount`, the saved pre-shared-key profiles whose SSID is on the engagement's corporate list. The list comes from the scope (`wireless.corporate_ssids`), the launcher parameter `-CorporateSsids` or the `POSTUREKIT_CORPORATE_SSIDS` environment variable, in that order, and is passed to the collector as an argument so it also works over WinRM; `CorporateSsidSource` is recorded. Without a list WLAN07 records Unknown and the total PSK count stays an observation.

### Patch findings (`Extensions/PatchCheck.py`, `Extensions/ToFindings.py`)
- The remediation names the highest fixed build on the host's own servicing branch found in the result, with the vendor-data date, and states that the applicable current update and supersedence must be confirmed from the vendor catalogue; it no longer names the build of the worst-scoring CVE. KB references are listed as references, not as required packages, and the description counts the CVEs carried by the outstanding cumulative-update stream rather than "security updates".
- When the CISA catalogue was unavailable the exploitability text says so; when it was available the text carries the snapshot date. Each patch finding points to its own host block (`hosts[n]`) with the host build and the feed date, and the window limitation is carried into the finding.

### Importer completeness
- Greenbone `scan_complete` is tri-state: true only for Done with an end time, false for Running and similar, null when the export carries no status. The analyzer emits a `VULN.SCAN` row (Observation, Inconclusive or Not tested) so the findings draft carries scan completeness as a coverage gap and a review item.
- Controller intake accepts `unknown` and `not_supported` for rogue detection, WIPS, client isolation and PMF, plus field notes; unknown values give Unknown results, never Fail.
- Air import records the bands observed per channel and a limitation when only one band was captured.

### Analyst dispositions and sealing
- `ToFindings.py --dispositions <csv>` (template `Templates/ReviewDispositions.csv`) records ConfirmedFinding, RejectedCandidate, EvidenceGap, ApprovedException or Pending against every review-queue row, with reviewer, timestamp and hashed evidence; counts carry `dispositions_recorded` and `pending`.
- `Code/SealDerived.py` regenerates `Manifest.txt` for a derived output folder after all post-processing, so `findings.json` and the review files are covered; it refuses a raw batch folder.

## 0.6, build 2026-10-01

Found on a German-language Windows 11 host in the same lab.

### Collector (`Code/Collect.ps1`)
- The local account password and lockout policy (`passwordpolicy`) was parsed from the `net accounts` text, so on any non-English display language every value was null and the two account-policy rules recorded Unknown. The collector now reads the policy through the `NetUserModalsGet` API, the same source `net accounts` prints from: integer values, no language dependency, no elevation required. Password ages are recorded in days, lockout values in minutes, and -1 means never. Two fields were added, `LockoutDurationMinutes` and `LockoutWindowMinutes`. The text parse remains as the fallback only and now maps the English words Never and None to 0 and Unlimited to -1, so a lockout threshold shown as "Never" is recorded as 0 (a Fail) instead of Unknown.

### Rules (`Code/Rules.json`, still 45 rules)
- PWD01 and PWD02 wording updated to match; no schema change.
- LOG03 (PowerShell 7 script block logging) is gated on `PowerShellCoreInstalled` (now 0/1), so a host without PowerShell 7 records Not applicable instead of Unknown.

### Independent review fixes (same day, 155 tests)
- Collector: 802.1X server-certificate validation is read from `PerformServerValidation` (PEAP, TTLS) or the EAP-TLS `ServerValidation` block with a trusted root, never inferred from substrings; the connected state must equal "connected"; management-frame protection is decided from the negotiated AKM suite only (null when unknown); new `WsusInEffect` flag.
- Rules: UPD01 and UPD02 gated on `WsusInEffect`; CRED02 absent value is Unknown (Windows 11 22H2 and later can enable LSA protection without the registry value).
- PatchCheck: every host in the batch is assessed (`hosts` list); each host must match the evidence digest in Batch.json or is EvidenceRejected; fixed builds compared on the host's own servicing branch and UBR only (no more false cleans on Server 2012 R2 or Server 2022 23H2); an edition-only product variant is never selected by default; CVSS taken from the score set naming the matched product (`cvss_source`); architecture spelling normalised; `known_exploited` null when the CISA catalogue is unavailable; cached feed documents carry fetch times, are refreshed after 35 days, and the output records `feed_fetched_utc` and `feed_age_days`; fetch failures write Unknown and exit 2.
- SoftwareCheck: an absent or errored inventory is Unknown, never clean; KB exclusion matches KB numbers only; every host assessed; `catalog_warning` added.
- GreenboneImport: requires a GVM report root; records scan status, progress, start and end, task name, host and result counts, filter text and per-result QoD; `scan_complete` false with a limitation when the export predates completion; heuristic credentialed indicator.
- Controller: guest VLAN separation is Unknown when no corporate VLAN is recorded; shared-key guest WLANs recorded as observations.
- Wireless air: `wps_enabled` null without a wash listing; CSV parsing tolerates commas; null-byte hidden SSIDs; look-alike corporate ESSIDs classified and failed; rogue interpretation requires a complete allowlist.
- Analyze: multi-batch metadata reports the distinct enabled assets, batch ids and per-asset source coverage.
- ToFindings: `review_queue` of every undetermined or candidate row, coverage gaps per asset and category, per-host patch and software blocks, non-host findings carry their site and control references.

### Collector, wireless presence
- `WirelessPresent` is now tri-state: 1 or 0 only when the `netsh wlan` text was understood (English), null otherwise (another display language, an unexpected message). The eight WLAN rules then record Unknown instead of a false "no wireless adapter".

## 0.6, build 2026-09-29

Fixes found by running the tool in a six-machine virtual lab (Windows 10, Windows 11, Server 2016, Server 2019, Server 2022 and a domain controller). Each fix carries a regression test; the suite is now 102 tests.

### Collector (`Code/Collect.ps1`)
- `full_build` and `display_version` were empty on Server 2016 and Server 2019. `DisplayVersion` does not exist in the registry before Windows 10 20H2 and Server 2022, and reading it under StrictMode aborted the block before `full_build` was set. The build is now computed first, `DisplayVersion` is read guarded, and `ReleaseId` (for example 1809) is the fallback.
- The three domain-level directory sources (`domainpolicy`, `domainprivilegedgroups`, `kerberospolicy`) failed with "Cannot index into a null array" on every member server collected through a remote session (credential second hop). They are now read once from the domain controller and recorded as NotApplicable, with the reason, on member hosts inside a remote session.
- `domainprivilegedgroups` returned an empty list. The LDAP filter used a wildcard on `objectSid`, which is binary and never matches. The exact SID is now built (domain SID plus RID, `S-1-5-32` for the built-in operator groups) and recorded in a new `Sid` field.
- `domainpolicy` interval attributes (password ages, lockout duration and window) arrive as `IADsLargeInteger` COM objects; the conversion now uses the directory entry's own `ConvertLargeIntegerToInt64` with a reflection fallback.
- `kerberospolicy` now parses the real ticket policy (`MaxTicketAge`, `MaxRenewAge`, `MaxServiceAge`, `MaxClockSkew`, `TicketValidateClient`) from the Default Domain Policy security template in SYSVOL when readable, and records the source path.
- `WirelessPresent` reported 1 on servers with no wireless adapter because an unrecognised `netsh` error fell through to "present". Presence now requires `netsh` to report at least one interface.
- `nameresolution` gains `NetbiosEnabledCount`; `pointandprint` gains `SpoolerRunning`.

### Rules (`Code/Rules.json`, still 45 rules)
- NET02 evaluates `NetbiosEnabledCount` (integer, expected 0) instead of comparing an array to a string, which always produced Unknown.
- PRN01 is gated on `SpoolerRunning`, so a host with the spooler stopped records Not applicable instead of Fail.

### Network tester (`Code/Network.ps1`)
- A failed connection could only ever be Inconclusive. After a timed-out connect the tester now sends one ICMP echo; a live host plus a timeout on an expected-Blocked path is recorded as `ExpectedBlocked` (new `host_alive` field). An actively refused connection stays Inconclusive with an explanation.

### Analyzer (`Code/Analyze.py`)
- `--batch` can be repeated: several sealed batches of the same engagement are consolidated into one report. The first batch holding evidence for an asset is used; a later duplicate is noted, never merged.
- `ExpectedBlocked` with `host_alive` true is scored Pass for the segmentation test.
- A domain-joined member host may legitimately record the three domain-level directory sources as NotApplicable.

### Patch engine (`Extensions/PatchCheck.py`)
- Product matching: edition variants ("23H2 Edition", "Azure Edition") no longer win a tie against the base product. A Server 2022 build 20348 Server Core host was matched to the 23H2 product and produced an invalid missing-update count.
- The MSRC release index is sorted by year and month before the window is sliced; it is alphabetical at source, so the last N entries were not the last N months. Use a wide window (`--months 60`) on old builds; the tool warns when the window truncates.

### Importers
- `HardeningKittyImport.py` accepts the two extra columns (`DefaultValue`, `Filter`) that current HardeningKitty releases write.

## 0.6, 2026-09-24

First public release: 45 evidence sources, 45 rules, sealed batches, off-host analyzer, patch engine on Microsoft's free CVRF feed with CISA KEV, importers for offline updates, HardeningKitty, Nmap, agentless CIM, wireless (host, over-the-air, controller) and Greenbone.
