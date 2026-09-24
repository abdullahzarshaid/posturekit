#!/usr/bin/env python3
"""Draft a findings register from collected evidence.

Input
-----
  Tests.csv            rule results produced by Analyze.py
  MissingUpdates.json  optional, produced by PatchCheck.py

Output
------
  findings.json        a DRAFT register in the reporting data contract's shape

What this does and does not do
------------------------------
Everything the evidence supports is written: identifiers, affected assets, the
observed value, the evidence pointer and its hash, and - for missing updates -
Microsoft's own CVSS vector.

Everything that requires judgement is left as an explicit ANALYST REQUIRED
marker rather than being invented: exploitability, attack chain, impact and
proof-of-concept steps. A proof-of-concept is only ever transcribed from a real
capture, so this tool never writes one.

Severity is not assigned to configuration findings here. A configuration
difference is an observation until an analyst has weighed it against the
client's approved baseline and documented exceptions.

Missing updates are grouped into a single finding per host. A register carrying
several hundred separate CVE rows is unusable in a report and misrepresents one
remediation action as hundreds.
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

ANALYST = "ANALYST REQUIRED"

# Configuration rules mapped to the weakness they evidence. A rule with no entry
# gets no CWE rather than a guessed one.
CWE_BY_RULE = {
    # Only mappings that can be defended in a client review are recorded here.
    # Where the honest answer is that the weakness class depends on context, the
    # rule carries no CWE and the assessor assigns one. A wrong CWE in a report is
    # worse than an absent one: it invites a correction from the client.
    "SMB01":  "CWE-477",   # Use of Obsolete Function - SMBv1 server
    "SMB04":  "CWE-477",   # Use of Obsolete Function - SMBv1 client driver
    "SMB02":  "CWE-353",   # Missing Support for Integrity Check - signing not required
    "SMB03":  "CWE-353",
    "RDP01":  "CWE-287",   # Improper Authentication - network level authentication
    "UAC01":  "CWE-250",   # Execution with Unnecessary Privileges
    "UAC02":  "CWE-250",
    "UAC03":  "CWE-250",
    "SAM01":  "CWE-1188",  # Insecure Default Initialization of Resource
    "CRED01": "CWE-522",   # Insufficiently Protected Credentials - WDigest cleartext
    "CRED02": "CWE-522",   # Insufficiently Protected Credentials - LSASS unprotected
    "CRED03": "CWE-327",   # Broken or Risky Cryptographic Algorithm - LM hash
    "CRED04": "CWE-524",   # Use of Cache Containing Sensitive Information
    "CRED05": "CWE-306",   # Missing Authentication for Critical Function - autologon
    "CRED06": "CWE-256",   # Plaintext Storage of a Password
    "NET01":  "CWE-290",   # Authentication Bypass by Spoofing - LLMNR poisoning
    "PRIV01": "CWE-250",   # Execution with Unnecessary Privileges
    "PRIV02": "CWE-250",
    "LOG01":  "CWE-778",   # Insufficient Logging
    "LOG02":  "CWE-778",
    "PWD01":  "CWE-521",   # Weak Password Requirements
    "PWD02":  "CWE-307",   # Improper Restriction of Excessive Authentication Attempts
    "MEDIA01":"CWE-1188",  # Insecure Default Initialization of Resource

    # Deliberately unmapped, with the reason:
    #   FW01/FW02/FW03 - a disabled firewall profile is a control failure whose
    #     weakness class depends on what it then exposes. No single CWE fits.
    #   CRED07 - the absence of a managed local administrator password solution is
    #     an operational gap; the weakness it leads to (shared local credentials
    #     enabling lateral movement) is a different finding with different evidence.
}

REMEDIATION = {
    "CRED04": "Reduce the number of cached interactive logons to the value in the approved baseline.",
    "NET01": "Disable LLMNR by policy after confirming name resolution is unaffected.",
    "LOG01": "Enable PowerShell script block logging by policy and forward the events to the log platform.",
    "LOG02": "Enable PowerShell module logging by policy for the modules in the approved list.",
    "PWD01": "Set a minimum local password length in line with the approved policy.",
    "PWD02": "Configure an account lockout threshold within the approved range. A threshold of zero disables lockout entirely.",
    "MEDIA01": "Restrict AutoRun for all drive types by policy.",
    "CRED02": "Enable LSA protection so the authentication subsystem runs as a protected process.",
    "CRED03": "Disable LAN Manager hash storage.",
    "SMB01": "Remove the SMBv1 server feature.",
    "SMB04": "Disable the SMBv1 client driver.",
    "CRED07": "Deploy a managed local administrator password solution with automatic rotation.",
}


def _read_json(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, ValueError):
            continue
    raise SystemExit("Cannot decode JSON: %s" % path)


def _severity_from_score(score):
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return None


def _config_findings(rows):
    findings = []
    # One finding per rule, listing every host that failed it. A report reads by
    # weakness, not by machine.
    by_rule = {}
    for row in rows:
        if row.get("result") != "Fail":
            continue
        rule_id = row["test_id"].split(".")[-1]
        by_rule.setdefault(rule_id, []).append(row)

    for index, (rule_id, hits) in enumerate(sorted(by_rule.items()), start=1):
        first = hits[0]
        assets = sorted({h.get("asset_id") for h in hits if h.get("asset_id")})
        observed = sorted({(h.get("observed") or "absent") for h in hits})
        findings.append({
            "id": "CFG-%02d" % index,
            "source_rule": rule_id,
            "title": first.get("objective") or rule_id,
            "severity": ANALYST,
            "severity_basis": ("Not assigned by tooling. A configuration difference is an "
                               "observation until weighed against the client's approved baseline "
                               "and documented exceptions."),
            "status": "Open",
            "cvss_vector": ANALYST,
            "cvss_base_score": ANALYST,
            "cwe": CWE_BY_RULE.get(rule_id),
            "affected_assets": assets,
            "affected_asset_count": len(assets),
            "description": first.get("objective"),
            "observed_result": "Observed value: %s. Expected: %s."
                               % (", ".join(observed), first.get("expected") or "see rule"),
            "technical_interpretation": first.get("technical_interpretation"),
            "preconditions": ANALYST,
            "exploitability": ANALYST,
            "attack_chain": ANALYST,
            "proof_of_concept": ("NOT APPLICABLE - configuration review. A proof of concept is "
                                 "only written when transcribed from a real capture."),
            "impact": ANALYST,
            "remediation": REMEDIATION.get(rule_id, ANALYST),
            "retest_guidance": "Re-collect the host evidence and confirm the value now meets the approved baseline.",
            "evidence": [{
                "evidence_file": h.get("evidence_file"),
                "evidence_pointer": h.get("evidence_pointer"),
                "evidence_sha256": h.get("evidence_sha256"),
                "asset_id": h.get("asset_id"),
                "observed": h.get("observed"),
                "timestamp_utc": h.get("timestamp_utc"),
            } for h in hits],
            "limitations": first.get("limitations"),
            "method": first.get("method"),
            "validation": first.get("validation"),
        })
    return findings


def _coverage_gap(patch):
    """Record that patch state could not be determined.

    This is not a finding - it is the absence of one - but it must appear in the
    register. A host whose patch state was never established must never produce a
    report that simply says nothing about patching, because silence reads as
    'nothing wrong'.
    """
    return {
        "id": "GAP-01",
        "kind": "CoverageGap",
        "title": "Patch state could not be determined for this host",
        "severity": "Not assessed",
        "status": "Not tested",
        "affected_assets": [patch.get("asset_id") or patch.get("computer_name")],
        "description": (
            "The host reports %s at servicing level %s. No vendor product matched "
            "that identity, so no determination of outstanding security updates was "
            "made."
            % (patch.get("os_caption") or "an unidentified operating system",
               patch.get("observed_build") or "an unrecorded build")),
        "observed_result": "No determination made.",
        "impact": ("This host is UNASSESSED for missing security updates. It is not "
                   "evidence that the host is patched, and it must not be presented "
                   "or counted as though it were."),
        "remediation": ("Re-collect with a collector that records the operating system "
                        "release and servicing level, or assess this host by another "
                        "method and record the result."),
        "limitations": "; ".join(patch.get("limitations") or []),
        "method": "Credentialed servicing-level assessment against vendor published data.",
        "validation": "Not determined.",
    }


def _patch_finding(patch, index):
    updates = patch.get("missing_updates") or []
    if not updates:
        return None

    scored = [u for u in updates if u.get("cvss_base_score") is not None]
    worst = max(scored, key=lambda u: u["cvss_base_score"]) if scored else None
    counts = patch.get("counts", {})
    kev = [u for u in updates if u.get("known_exploited")]

    # Distinct KBs are what actually gets installed.
    kbs = sorted({u.get("kb") for u in updates if u.get("kb")})

    return {
        "id": "VULN-%02d" % index,
        "title": "Operating system is missing published security updates",
        "severity": _severity_from_score(worst["cvss_base_score"]) if worst else ANALYST,
        "severity_basis": ("Taken from the vendor's own CVSS vector for the most severe "
                           "outstanding update. Confirm the rating is appropriate for this "
                           "client's environment before issue."),
        "status": "Open",
        "cvss_vector": worst["cvss_vector"] if worst else ANALYST,
        "cvss_base_score": worst["cvss_base_score"] if worst else ANALYST,
        "cwe": "CWE-1104",
        "affected_assets": [patch.get("asset_id") or patch.get("computer_name")],
        "affected_asset_count": 1,
        "description": (
            "The host is running %s at servicing level %s. Microsoft has published fixes "
            "that require a later build, so %d security updates are outstanding."
            % (patch.get("os_caption"), patch.get("observed_build"), len(updates))),
        "observed_result": (
            "Servicing level %s. Outstanding updates: %d (%d rated 9.0 or above, %d rated "
            "7.0 to 8.9). Distinct update packages required: %d."
            % (patch.get("observed_build"), len(updates),
               counts.get("critical_9_plus", 0), counts.get("high_7_plus", 0), len(kbs))),
        "technical_interpretation": (
            "Determined by comparing the host's recorded servicing level against the build "
            "in which each fix shipped. No vulnerability was validated by execution."),
        "preconditions": ANALYST,
        "exploitability": (
            "%d of the outstanding CVEs appear in the CISA Known Exploited Vulnerabilities "
            "catalogue: %s." % (len(kev), ", ".join(u["cve"] for u in kev[:10]))
            if kev else
            "None of the outstanding CVEs currently appear in the CISA Known Exploited "
            "Vulnerabilities catalogue. That is not evidence they cannot be exploited."),
        "attack_chain": ANALYST,
        "proof_of_concept": ("NOT APPLICABLE - determined from servicing level against vendor "
                             "data. No exploitation was attempted."),
        "impact": ANALYST,
        "remediation": (
            "Apply the outstanding cumulative update so the host reaches at least build %s. "
            "Update packages required: %s."
            % (worst["fixed_build"] if worst else ANALYST, ", ".join("KB" + k for k in kbs[:8]))),
        "retest_guidance": "Re-collect the host evidence and confirm the servicing level has advanced past the required build.",
        "evidence": [{
            "evidence_file": "MissingUpdates.json",
            "evidence_pointer": "missing_updates",
            "asset_id": patch.get("asset_id"),
            "source_batch": patch.get("source_batch"),
            "generated_utc": patch.get("generated_utc"),
        }],
        "cve_detail": [{
            "cve": u["cve"], "kb": u.get("kb"), "cvss_base_score": u.get("cvss_base_score"),
            "cvss_vector": u.get("cvss_vector"), "fixed_build": u.get("fixed_build"),
            "known_exploited": u.get("known_exploited"),
        } for u in updates],
        "limitations": "; ".join(patch.get("limitations") or []),
        "method": "Credentialed servicing-level assessment against vendor published data.",
        "validation": "Not validated by execution.",
    }


def _software_gap(software):
    return {
        "id": "GAP-SW-01",
        "kind": "CoverageGap",
        "title": "Third-party software could not be assessed for this host",
        "severity": "Not assessed",
        "status": "Not tested",
        "affected_assets": [software.get("asset_id") or software.get("computer_name")],
        "description": ("The installed-software inventory was not present or not collected, so "
                        "end-of-life and outdated third-party software could not be assessed."),
        "observed_result": "No determination made.",
        "impact": ("This host is UNASSESSED for third-party software risk. It is not evidence "
                   "that the host carries no outdated or unsupported software."),
        "remediation": "Re-collect with the software inventory source enabled and re-run the assessment.",
        "limitations": "; ".join(software.get("limitations") or []),
        "method": "Installed-software inventory against a curated lifecycle catalogue.",
        "validation": "Not determined.",
    }


def _software_finding(software, index):
    items = software.get("items") or []
    if not items:
        return None
    counts = software.get("counts", {})
    asset = software.get("asset_id") or software.get("computer_name")
    return {
        "id": "SW-%02d" % index,
        "title": "Outdated or end-of-life third-party software is installed",
        "severity": ANALYST,
        "severity_basis": ("Not assigned by tooling. End-of-life or outdated software is an "
                           "observation; an assessor weighs each item against the client's "
                           "baseline, compensating controls and exposure before rating it."),
        "status": "Open",
        "cvss_vector": ANALYST,
        "cvss_base_score": ANALYST,
        "cwe": "CWE-1104",   # Use of Unmaintained Third Party Components
        "affected_assets": [asset],
        "affected_asset_count": 1,
        "description": (
            "%d installed third-party products are end-of-life or below a curated safe version "
            "floor. Unsupported and outdated software no longer receives security fixes and is a "
            "common initial-access and privilege-escalation route." % len(items)),
        "observed_result": (
            "Inventory of %d products: %d end-of-life, %d below version floor, %d known-exploited "
            "product family present, %d with an unreadable version to confirm manually."
            % (counts.get("inventory_size", 0), counts.get("end_of_life", 0),
               counts.get("below_floor", 0), counts.get("kev_product_present", 0),
               counts.get("version_unreadable", 0))),
        "technical_interpretation": (
            "Determined from the installed-software inventory against a dated lifecycle catalogue "
            "and reference version floors. No CVE was matched to a product/version and nothing "
            "was executed."),
        "preconditions": ANALYST,
        "exploitability": ANALYST,
        "attack_chain": ANALYST,
        "proof_of_concept": ("NOT APPLICABLE - inventory review against vendor lifecycle data. "
                             "No exploitation was attempted."),
        "impact": ANALYST,
        "remediation": ("Update each listed product to a vendor-supported version, or remove it "
                        "where it is not required. Replace end-of-life products with a supported "
                        "alternative."),
        "retest_guidance": "Re-collect the host evidence and confirm each listed product is supported and current.",
        "evidence": [{
            "evidence_file": "SoftwareRisk.json",
            "evidence_pointer": "items",
            "asset_id": asset,
            "source_batch": software.get("source_batch"),
            "generated_utc": software.get("generated_utc"),
        }],
        "software_detail": [{
            "name": i.get("name"), "version": i.get("version"), "publisher": i.get("publisher"),
            "risk_type": i.get("risk_type"), "basis": i.get("basis"),
        } for i in items],
        "limitations": "; ".join(software.get("limitations") or []),
        "method": "Installed-software inventory against a curated, dated lifecycle catalogue and reference version floors.",
        "validation": "Not validated by execution.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Draft a findings register from collected evidence.")
    parser.add_argument("--derived", required=True,
                        help="directory holding Tests.csv from Analyze.py")
    parser.add_argument("--patch", default=None,
                        help="MissingUpdates.json from PatchCheck.py (optional)")
    parser.add_argument("--software", default=None,
                        help="SoftwareRisk.json from SoftwareCheck.py (optional)")
    parser.add_argument("--output", required=True, help="output directory")
    parser.add_argument("--engagement-id", default="LAB-001")
    arguments = parser.parse_args()

    tests_path = os.path.join(arguments.derived, "Tests.csv")
    if not os.path.isfile(tests_path):
        raise SystemExit("No Tests.csv in %s. Run Analyze.py first." % arguments.derived)
    with open(tests_path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    findings = _config_findings(rows)

    coverage_gaps = []
    if arguments.patch and os.path.isfile(arguments.patch):
        patch = _read_json(arguments.patch)
        if patch.get("status") == "Unknown":
            coverage_gaps.append(_coverage_gap(patch))
        else:
            entry = _patch_finding(patch, 1)
            if entry:
                findings.insert(0, entry)

    if arguments.software and os.path.isfile(arguments.software):
        software = _read_json(arguments.software)
        if software.get("status") == "Unknown":
            coverage_gaps.append(_software_gap(software))
        else:
            sw_entry = _software_finding(software, 1)
            if sw_entry:
                findings.append(sw_entry)

    needs_analyst = sum(
        1 for f in findings
        for value in f.values()
        if isinstance(value, str) and value == ANALYST)

    document = {
        "schema_version": "1.0",
        "register_status": "DRAFT",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "engagement_id": arguments.engagement_id,
        "notice": (
            "This register is a draft derived from collected evidence. It is not a report and "
            "it is not client-facing. Every field marked ANALYST REQUIRED must be completed by "
            "an assessor, every severity must be confirmed against the client's approved "
            "baseline, and every finding must be traced to its raw evidence before issue. "
            "No proof-of-concept text is generated here; a proof of concept is only ever "
            "transcribed from a real capture."),
        "counts": {
            "findings": len(findings),
            "coverage_gaps": len(coverage_gaps),
            "fields_awaiting_analyst": needs_analyst,
        },
        "findings": findings,
        "coverage_gaps": coverage_gaps,
    }

    os.makedirs(arguments.output, exist_ok=True)
    path = os.path.join(arguments.output, "findings.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)

    print("Draft findings   : %d" % len(findings))
    for finding in findings:
        print("   %-8s %-10s %s" % (finding["id"], finding["severity"], finding["title"][:56]))
    for gap in coverage_gaps:
        print("   %-8s %-10s %s" % (gap["id"], "NOT TESTED", gap["title"][:56]))
    if coverage_gaps:
        print("Coverage gaps    : %d  - these hosts are UNASSESSED, not clean."
              % len(coverage_gaps))
    print("Fields awaiting analyst completion: %d" % needs_analyst)
    print("Written          : %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
