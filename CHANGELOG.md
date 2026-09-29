# Changelog

All notable changes to PostureKit. The schema version of the evidence files is unchanged (1.0), so batches collected with earlier 0.6 builds still analyze.

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
