#!/usr/bin/env python3
"""Draft a findings register from collected evidence.

Input
-----
  Manifest.txt         the derived folder's seal, written by Analyze.py (or
                       Code/SealDerived.py); verified before anything is read
  Tests.csv            rule results produced by Analyze.py
  Coverage.csv         per-asset collection status produced by Analyze.py
  Evidence.json        optional, the same run's package (source counts per asset,
                       engagement_id and the batch ids that were analysed)
  MissingUpdates.json  optional, produced by PatchCheck.py
  SoftwareRisk.json    optional, produced by SoftwareCheck.py
  ReviewDispositions   optional CSV of analyst dispositions for review rows

The derived folder is verified exactly as Code/VerifyManifest.py verifies it
(every listed file present, SHA-256 equal, nothing unmanifested) BEFORE
Tests.csv, Coverage.csv or Evidence.json is read. A folder that fails, has no
Manifest.txt, or whose Evidence.json names a different engagement than
--engagement-id is not converted: the register is written with an empty
findings list, one GAP-IN entry and register_status InputRejected, exit 2.
A --patch or --software file must record the batch it was assessed from
(source_batch); when Evidence.json lists the analysed batch ids it must be one
of them, or its hosts are recorded as GAP-IN entries and no finding is drawn
from them (exit 4, like a missing input path).

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

Coverage is never silent. Every asset in the approved scope that did not
produce complete host evidence (NotAttempted, Error, Excluded, EvidenceRejected,
Partial) is written as a coverage gap carrying its asset_id, and an explicitly
supplied patch or software input that does not exist is a required-input gap
with a non-zero exit, never a quiet skip.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

ANALYST = "ANALYST REQUIRED"

# Exit codes. 0: register written and every supplied input was read.
# 2: the derived folder itself was rejected (Manifest.txt missing or failing,
#    or Evidence.json names another engagement). Nothing was converted; the
#    register holds an empty findings list and one GAP-IN entry.
# 4: register written, but a required input named on the command line was
#    absent or does not belong to the analysed batches (recorded as a coverage
#    gap). The caller must not treat the draft as complete.
EXIT_OK = 0
EXIT_INPUT_REJECTED = 2
EXIT_REQUIRED_INPUT = 4
DEFAULT_ENGAGEMENT_ID = "LAB-001"

# The manifest line form Code/VerifyManifest.py checks: "sha256  name".
MANIFEST_LINE = re.compile(r"^([0-9a-fA-F]{64})  ([^/\\]+)$")

# A CVE identifier as MITRE issues it. Anything else in the vendor's "cve" field
# (ADV220005 and the like) is an advisory and is never called a CVE.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

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

# Analyst dispositions for review-queue rows. The CSV template is
# Templates\ReviewDispositions.csv; the columns must match it exactly.
DISPOSITION_FIELDS = ["test_id", "disposition", "rationale", "reviewer",
                      "timestamp_utc", "evidence_file", "evidence_sha256"]
DISPOSITIONS = ("ConfirmedFinding", "RejectedCandidate", "EvidenceGap",
                "ApprovedException", "Pending")
PENDING = {"disposition": "Pending"}

KB_LABEL = "KB references of the latest fixes in the evaluated window"
COVERAGE_COMPLETE = ("Complete",)
COVERAGE_USABLE = ("Complete", "Partial")


def _read_json(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, ValueError):
            continue
    raise SystemExit("Cannot decode JSON: %s" % path)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def _build_tuple(text):
    """'10.0.20348.3' -> (10, 0, 20348, 3); None when unparseable."""
    if not text:
        return None
    parts = str(text).strip().split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _is_cve(identifier):
    return bool(identifier) and CVE_RE.fullmatch(str(identifier).strip()) is not None


def _plural(count, singular, plural):
    return "%d %s" % (count, singular if count == 1 else plural)


def _record_summary(updates):
    """('N vendor records: X CVEs and Y advisories (ADV...)', cve_rows, advisory_ids)
    for the outstanding rows. Advisories are listed by identifier; the bracket
    is omitted when there are none."""
    cves = [u for u in updates if _is_cve(u.get("cve"))]
    advisories = [str(u.get("cve")) for u in updates if not _is_cve(u.get("cve"))]
    text = "%s: %s and %s" % (_plural(len(updates), "vendor record", "vendor records"),
                               _plural(len(cves), "CVE", "CVEs"),
                               _plural(len(advisories), "advisory", "advisories"))
    if advisories:
        text += " (%s)" % ", ".join(advisories)
    return text, cves, advisories


# ------------------------------------------------------------ derived input
def verify_derived_folder(derived):
    """Verify a derived folder's Manifest.txt the way Code/VerifyManifest.py does.

    Returns the list of reasons; empty when the folder is exactly what its
    manifest says: every listed file present as a regular file, SHA-256 equal,
    no duplicate or malformed lines, and no regular file other than
    Manifest.txt that the manifest does not name.
    """
    folder = os.path.abspath(derived)
    if not os.path.isdir(folder) or os.path.islink(folder):
        return ["%s is not a directory, or is a symlink" % folder]
    manifest = os.path.join(folder, "Manifest.txt")
    if not os.path.isfile(manifest) or os.path.islink(manifest):
        return ["Manifest.txt is missing from %s, so the derived output was never sealed and nothing in it "
                "can be verified (re-run Analyze.py, or seal the folder with Code/SealDerived.py)" % folder]
    reasons = []
    seen = set()
    with open(manifest, encoding="utf-8-sig") as handle:
        lines = handle.read().splitlines()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        match = MANIFEST_LINE.match(line)
        if not match:
            reasons.append("Manifest.txt line %d: malformed" % number)
            continue
        expected, name = match.groups()
        if name in seen:
            reasons.append("%s: duplicate manifest entry" % name)
            continue
        seen.add(name)
        path = os.path.join(folder, name)
        if not os.path.isfile(path) or os.path.islink(path):
            reasons.append("%s: MISSING OR INVALID" % name)
            continue
        if _sha256(path).lower() != expected.lower():
            reasons.append("%s: HASH MISMATCH against Manifest.txt" % name)
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if name == "Manifest.txt" or name in seen or not os.path.isfile(path) or os.path.islink(path):
            continue
        reasons.append("%s: UNMANIFESTED" % name)
    return reasons


def _evidence_metadata(derived):
    """Evidence.json's metadata block when the derived folder carries one, else {}."""
    path = os.path.join(derived, "Evidence.json")
    if not os.path.isfile(path):
        return {}
    try:
        package = _read_json(path)
    except SystemExit:
        return {}
    meta = package.get("metadata") if isinstance(package, dict) else None
    return meta if isinstance(meta, dict) else {}


def _analysed_batches(meta):
    """The batch ids the evidence set was built from (metadata.batch_ids, else
    batch_id, comma-joined for a merge), or [] when it records none."""
    ids = meta.get("batch_ids")
    if isinstance(ids, list) and ids:
        return [str(item) for item in ids]
    single = meta.get("batch_id")
    if isinstance(single, str) and single.strip():
        return [part.strip() for part in single.split(",") if part.strip()]
    return []


def _batch_membership(kind, host_block, document, analysed):
    """None when the host block (or its document) records a source_batch that is one
    of the analysed batches; otherwise the reason it cannot be used."""
    source = host_block.get("source_batch")
    if source is None:
        source = document.get("source_batch")
    if source is None or not str(source).strip():
        return ("the %s output records no source_batch, so the batch it was assessed from cannot be "
                "established" % kind)
    if analysed and str(source) not in analysed:
        return ("the %s output records source_batch %s, which is not one of the analysed batches (%s)"
                % (kind, source, ", ".join(analysed)))
    return None


def _foreign_input_gap(kind, path, host_block, reason):
    """A supplied --patch / --software result that does not belong to the batches
    Analyze.py normalised. It is recorded, never converted into a finding."""
    asset = host_block.get("asset_id") or host_block.get("computer_name")
    return {
        "id": None,   # numbered when appended to the register
        "kind": "CoverageGap",
        "title": "Required %s input does not belong to the analysed batches" % kind,
        "severity": "Not assessed",
        "status": "Not tested",
        "affected_assets": [asset] if asset else [],
        "asset_id": asset,
        "input_kind": kind,
        "input_path": path,
        "description": ("%s output does not belong to the analysed batches: %s. File supplied as --%s: %s. "
                        "The %s result for this host was not converted." % (kind, reason, kind, path, kind)),
        "observed_result": "Input not converted: %s" % path,
        "impact": ("This host is UNASSESSED for %s in this register. The result exists, but it cannot be tied "
                   "to the evidence set that was analysed, so it must not be presented as part of it." % kind),
        "remediation": ("Run the %s assessment against the same sealed batch that Analyze.py normalised (its "
                        "batch_id is recorded in Evidence.json) and supply the file it writes." % kind),
        "limitations": "The file was read; its batch lineage did not match the evidence set.",
        "method": "source_batch recorded by the assessment compared with the batch ids in Evidence.json metadata.",
        "validation": "Not determined.",
    }


def _write_register(output, document):
    os.makedirs(output, exist_ok=True)
    path = os.path.join(output, "findings.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)
    return path


def _reject_input(arguments, reason):
    """The derived folder cannot be trusted: write a register that converts nothing
    (empty findings, one GAP-IN entry, register_status InputRejected) and exit 2."""
    folder = os.path.abspath(arguments.derived)
    gap = {
        "id": "GAP-IN-01",
        "kind": "CoverageGap",
        "title": "Derived analysis input rejected",
        "severity": "Not assessed",
        "status": "Not tested",
        "affected_assets": [],
        "input_kind": "derived",
        "input_path": folder,
        "description": "Derived analysis input rejected: %s" % reason,
        "observed_result": "The derived folder %s was not converted." % folder,
        "impact": ("Nothing in this register was drawn from the evidence. Every scoped asset is UNASSESSED "
                   "here, and the draft must not be presented as a result of any kind."),
        "remediation": ("Re-run Analyze.py from the sealed raw batch, or restore the sealed derived folder "
                        "whose Manifest.txt verifies with Code/VerifyManifest.py, then convert again."),
        "limitations": "No test row, coverage row or evidence package was read.",
        "method": "Manifest.txt verification (Code/VerifyManifest.py rules) and engagement identity check.",
        "validation": "Not determined.",
    }
    document = {
        "schema_version": "1.0",
        "register_status": "InputRejected",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "engagement_id": arguments.engagement_id or DEFAULT_ENGAGEMENT_ID,
        "notice": ("This register converts nothing. The derived analysis input was rejected before any "
                   "finding could be drawn from it; see coverage_gaps."),
        "input_rejection": {"folder": folder, "reason": reason},
        "counts": {
            "findings": 0, "coverage_gaps": 1, "review_queue": 0, "fields_awaiting_analyst": 0,
            "dispositions_recorded": 0, "pending": 0, "scoped_assets": 0, "scoped_assets_complete": 0,
            "required_input_failures": 1,
        },
        "findings": [],
        "coverage_gaps": [gap],
        "review_queue": [],
    }
    path = _write_register(arguments.output, document)
    print("DERIVED INPUT REJECTED: %s" % reason)
    print("Nothing was converted. Written : %s" % path)
    return EXIT_INPUT_REJECTED


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
        if not assets and not (first.get("test_id") or "").startswith("HOST."):
            # A network, wireless or scanner row carries no asset_id. Anchor the finding
            # to the site or the source position so it is never asset-less.
            assets = sorted({(h.get("site_id") or h.get("source_position") or "")
                             for h in hits} - {""})
        observed = sorted({(h.get("observed") or "absent") for h in hits})
        control_refs = sorted({(h.get("control_refs") or "") for h in hits} - {""})
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
            "control_refs": "; ".join(control_refs) if control_refs else None,
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


REVIEW_RESULTS = ("Candidate", "Inconclusive", "Unknown", "Error", "Not tested")
UNRESOLVED_RESULTS = ("Unknown", "Error", "Not tested")


def _needs_review(row):
    """A row the analyst must disposition before the register is complete.

    Candidate, Inconclusive, Unknown, Error and Not tested rows never become
    findings on their own, and an Observation in the network_vulnerability
    category is a scanner result awaiting confirmation. Dropping any of them
    silently would read as 'nothing wrong'.
    """
    result = row.get("result")
    if result in REVIEW_RESULTS:
        return True
    return result == "Observation" and row.get("category") == "network_vulnerability"


def _review_queue(rows):
    queue = []
    for row in rows:
        if not _needs_review(row):
            continue
        observed = row.get("observed")
        observed = "" if observed is None else str(observed)
        if len(observed) > 160:
            observed = observed[:157] + "..."
        queue.append({
            "test_id": row.get("test_id"),
            "category": row.get("category"),
            "asset_id": row.get("asset_id") or row.get("site_id") or row.get("source_position") or "",
            "result": row.get("result"),
            "objective": row.get("objective"),
            "observed": observed,
            "evidence_file": row.get("evidence_file"),
            "evidence_sha256": row.get("evidence_sha256"),
        })
    return queue


def _review_gaps(rows, start_index):
    """Coverage gaps summarising rows that are not yet dispositioned.

    One gap per asset counting its Unknown, Error and Not tested rows, and one
    gap per category counting Candidate rows awaiting disposition. Same shape as
    the patch and software gaps so a consumer handles them identically.
    """
    unresolved = {}
    candidates = {}
    for row in rows:
        result = row.get("result")
        if result in UNRESOLVED_RESULTS:
            key = row.get("asset_id") or row.get("site_id") or row.get("source_position") or "(no asset)"
            unresolved.setdefault(key, {"Unknown": 0, "Error": 0, "Not tested": 0})
            unresolved[key][result] += 1
        elif result == "Candidate":
            key = row.get("category") or "(no category)"
            candidates[key] = candidates.get(key, 0) + 1

    gaps = []
    index = start_index
    for asset, counts in sorted(unresolved.items()):
        total = sum(counts.values())
        gaps.append({
            "id": "GAP-RV-%02d" % index,
            "kind": "CoverageGap",
            "title": "Tests without a determination for this asset",
            "severity": "Not assessed",
            "status": "Not tested",
            "affected_assets": [asset],
            "description": (
                "%d test rows for this asset ended without a determination: %d Unknown, "
                "%d Error, %d Not tested."
                % (total, counts["Unknown"], counts["Error"], counts["Not tested"])),
            "observed_result": "No determination made for the listed rows.",
            "impact": ("These checks are UNASSESSED for this asset. The absence of a finding "
                       "is not evidence that the control is in place."),
            "remediation": ("Re-collect the missing source, or assess each listed row by another "
                            "method and record the result in the review queue."),
            "limitations": "Counts are taken from the rule results; see review_queue for the rows.",
            "method": "Rule results that did not reach Pass or Fail.",
            "validation": "Not determined.",
        })
        index += 1
    for category, count in sorted(candidates.items()):
        gaps.append({
            "id": "GAP-RV-%02d" % index,
            "kind": "CoverageGap",
            "title": "Candidate results awaiting analyst disposition",
            "severity": "Not assessed",
            "status": "Not tested",
            "affected_assets": [],
            "description": ("%d Candidate rows in category %s await confirmation or rejection by "
                            "an analyst." % (count, category)),
            "observed_result": "Candidate rows are not findings until confirmed.",
            "impact": ("Until each candidate is dispositioned the register neither confirms nor "
                       "excludes the exposure it describes."),
            "remediation": "Confirm or reject each candidate against raw evidence and manual testing.",
            "limitations": "Counts are taken from the rule results; see review_queue for the rows.",
            "method": "Imported candidate results (scanner or update applicability).",
            "validation": "Not determined.",
        })
        index += 1
    return gaps


# ------------------------------------------------------------ asset coverage
def _read_coverage(derived):
    """Per-asset collection status from Coverage.csv, enriched with the source
    counts Evidence.json carries for the same asset when it is present.

    Returns [] when Coverage.csv is absent (an older derived folder, or a
    Tests.csv assembled by hand). Assets that appear only in Evidence.json are
    included too, so neither file can hide an asset the other knows about.
    """
    path = os.path.join(derived, "Coverage.csv")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    detail = {}
    evidence_path = os.path.join(derived, "Evidence.json")
    if os.path.isfile(evidence_path):
        try:
            package = _read_json(evidence_path)
        except SystemExit:
            package = {}
        for item in (package.get("coverage") or []) if isinstance(package, dict) else []:
            if isinstance(item, dict) and item.get("asset_id"):
                detail[str(item["asset_id"])] = item
    assets = []
    seen = set()
    for row in rows:
        asset = (row.get("asset_id") or "").strip()
        if not asset:
            continue
        entry = {"asset_id": asset, "site_id": (row.get("site_id") or "").strip(),
                 "computer_name": (row.get("computer_name") or "").strip(),
                 "status": (row.get("status") or "").strip(), "evidence": (row.get("evidence") or "").strip(),
                 "note": (row.get("note") or "").strip(), "sources_collected": None, "sources_total": None}
        extra = detail.get(asset, {})
        for key in ("sources_collected", "sources_total"):
            if type(extra.get(key)) is int:
                entry[key] = extra[key]
        assets.append(entry)
        seen.add(asset)
    for asset, item in detail.items():
        if asset in seen:
            continue
        assets.append({"asset_id": asset, "site_id": str(item.get("site_id") or ""),
                       "computer_name": str(item.get("computer_name") or ""),
                       "status": str(item.get("status") or ""), "evidence": str(item.get("evidence") or ""),
                       "note": str(item.get("note") or ""),
                       "sources_collected": item.get("sources_collected") if type(item.get("sources_collected")) is int else None,
                       "sources_total": item.get("sources_total") if type(item.get("sources_total")) is int else None})
    return assets


_SOURCE_POINTER = re.compile(r"sources\[id=([^\]]+)\]")


def _unusable_sources(rows, asset):
    """Source ids whose rule results for this asset show the source was not
    usable: Error, Unsupported (Not tested) or absent. Read from the evidence
    pointer of each row, so it names real sources rather than guessing."""
    out = set()
    for row in rows:
        if (row.get("asset_id") or "") != asset:
            continue
        match = _SOURCE_POINTER.match(row.get("evidence_pointer") or "")
        if not match:
            continue
        result = row.get("result")
        interpretation = row.get("technical_interpretation") or ""
        if result in ("Error", "Not tested") or (result == "Unknown" and "absent" in interpretation):
            out.add(match.group(1))
    return sorted(out)


def _asset_coverage_gaps(assets, rows, start_index):
    """One coverage gap per scoped asset that did not produce complete evidence.

    NotAttempted, Error, Pending, Excluded and EvidenceRejected assets get a gap
    stating the ledger's own note. Partial assets get a gap stating how many
    sources were usable and which sources the rule results show as unusable.
    Every gap carries asset_id so a consumer can join it back to the scope.
    """
    titles = {
        "NotAttempted": "Scoped asset was not collected",
        "Error": "Scoped asset collection failed",
        "Pending": "Scoped asset collection is still pending",
        "Excluded": "Scoped asset excluded by the approved scope",
        "EvidenceRejected": "Scoped asset evidence was rejected at the integrity gate",
        "Partial": "Scoped asset has only partial host evidence",
    }
    gaps = []
    index = start_index
    for asset in assets:
        status = asset.get("status") or ""
        if status in COVERAGE_COMPLETE:
            continue
        asset_id = asset["asset_id"]
        note = asset.get("note") or "no note recorded"
        title = titles.get(status, "Scoped asset has no usable host evidence")
        if status == "Partial":
            collected, total = asset.get("sources_collected"), asset.get("sources_total")
            if collected is not None and total is not None:
                counts = "%d of %d sources usable (Collected or NotApplicable)" % (collected, total)
            else:
                counts = "source counts not recorded (Evidence.json absent or older)"
            unusable = _unusable_sources(rows, asset_id)
            description = (
                "Asset %s is in the approved scope with collection status Partial: %s. Sources the "
                "rule results show as Error, Unsupported or absent: %s. Ledger note: %s"
                % (asset_id, counts, ", ".join(unusable) if unusable else "none identified from the rule results",
                   note))
            observed = "Partial collection; checks that depend on the unusable sources made no determination."
            impact = ("Checks that depend on the uncollected sources are UNASSESSED for this asset. "
                      "A Pass elsewhere on this host does not extend to them.")
            remediation = "Re-collect the missing sources on this host, or assess them by another method and record the result."
        else:
            description = ("Asset %s is in the approved scope with collection status %s, so no host "
                           "evidence was evaluated for it. Ledger note: %s" % (asset_id, status or "unrecorded", note))
            observed = "No host evidence was evaluated for this asset."
            if status == "Excluded":
                impact = ("This asset was excluded by the approved scope and is UNASSESSED. It must be listed "
                          "as out of scope, never counted among assessed hosts.")
                remediation = "If the asset should be assessed, amend the approved scope and re-collect."
            else:
                impact = ("This asset is UNASSESSED. The absence of findings for it is not evidence that it "
                          "is secure, and it must not be presented or counted as though it were assessed.")
                remediation = ("Re-collect this asset with the collector, resolve the recorded ledger error, "
                               "or assess it by another method and record the result.")
        gaps.append({
            "id": "GAP-CV-%02d" % index,
            "kind": "CoverageGap",
            "title": title,
            "severity": "Not assessed",
            "status": "Not tested",
            "asset_id": asset_id,
            "affected_assets": [asset_id],
            "coverage_status": status,
            "site_id": asset.get("site_id") or None,
            "computer_name": asset.get("computer_name") or None,
            "sources_collected": asset.get("sources_collected"),
            "sources_total": asset.get("sources_total"),
            "description": description,
            "observed_result": observed,
            "impact": impact,
            "remediation": remediation,
            "limitations": note,
            "method": "Collection ledger (Coverage.csv and Evidence.json) against the approved scope.",
            "validation": "Not determined.",
        })
        index += 1
    return gaps


def _scan_gaps(rows, start_index):
    """A coverage gap for every scan-level row (VULN.SCAN) that is not an
    Observation: the scanner export was incomplete, or completion could not be
    established, so its absence of detections must not be read as coverage."""
    gaps = []
    index = start_index
    for row in rows:
        test_id = row.get("test_id") or ""
        if row.get("category") != "network_vulnerability" or not test_id.endswith(".SCAN"):
            continue
        if row.get("result") == "Observation":
            continue
        position = row.get("source_position") or row.get("site_id") or "(scanning position not recorded)"
        gaps.append({
            "id": "GAP-SC-%02d" % index,
            "kind": "CoverageGap",
            "title": "Scanner export incomplete or completion not established",
            "severity": "Not assessed",
            "status": "Not tested",
            "affected_assets": [position],
            "source_position": position,
            "scan_result": row.get("result"),
            "description": ("The network vulnerability scan export from %s is %s: %s. Observed: %s"
                            % (position,
                               "incomplete" if row.get("result") == "Inconclusive" else "of unestablished completion",
                               row.get("technical_interpretation") or "no interpretation recorded",
                               row.get("observed") or "")),
            "observed_result": "Scan completeness was not established as Done with an end time.",
            "impact": ("Scanner detections from this export are partial at best. Hosts and services without a "
                       "detection are UNASSESSED by this scan, not clean."),
            "remediation": "Re-export the report after the scanner task reports Done, or run the scan to completion and import that export.",
            "limitations": row.get("limitations") or "",
            "method": "Scan metadata (status, progress, end time) read from the imported export.",
            "validation": "Not determined.",
        })
        index += 1
    return gaps


def _missing_input_gap(kind, path, index):
    """A required input named on the command line does not exist. This is a
    coverage failure of the whole register, recorded loudly and never skipped."""
    label = {"patch": "patch assessment (MissingUpdates.json from PatchCheck.py)",
             "software": "software assessment (SoftwareRisk.json from SoftwareCheck.py)"}[kind]
    return {
        "id": "GAP-IN-%02d" % index,
        "kind": "CoverageGap",
        "title": "Required %s input was not found" % kind,
        "severity": "Not assessed",
        "status": "Not tested",
        "affected_assets": [],
        "input_kind": kind,
        "input_path": path,
        "description": ("The %s file supplied as --%s does not exist: %s. No %s state was read for any "
                        "host, so every host is UNASSESSED for %s." % (label, kind, path, kind, kind)),
        "observed_result": "Input file absent: %s" % path,
        "impact": ("The register carries no %s findings for any host. That is a missing input, not a "
                   "clean result, and the draft must not be presented as complete." % kind),
        "remediation": "Run the %s assessment and supply the file it writes, or remove the argument deliberately." % kind,
        "limitations": "The path was given explicitly; nothing was read from it.",
        "method": "Command-line input check.",
        "validation": "Not determined.",
    }


# ------------------------------------------------------------ patch findings
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
        "asset_id": patch.get("asset_id") or patch.get("computer_name"),
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


def _feed_date(patch):
    text = patch.get("feed_fetched_utc")
    if not text:
        return None
    return str(text)[:10]


def _kev_evaluated(patch, updates):
    """False when the catalogue was unavailable (kev_available false) or any row
    carries a null known_exploited; the overlay was then not applied."""
    if patch.get("kev_available") is False:
        return False
    return not any(u.get("known_exploited") is None for u in updates)


def _window_limitations(patch):
    """The truncated-window limitation PatchCheck writes when findings were still
    being found in the oldest release evaluated (the count is a floor)."""
    out = []
    for text in patch.get("limitations") or []:
        lowered = str(text).lower()
        if "window too narrow" in lowered or "floor" in lowered:
            out.append(str(text))
    return out


def _patch_finding(patch, index, host_position=None):
    """One finding per host for its outstanding operating-system updates.

    host_position is the host's index in MissingUpdates.json's hosts[] list
    (defaults to index - 1); the evidence pointer names it so each finding is
    traceable to its own block, not to the top-level mirror of the first host.
    """
    updates = patch.get("missing_updates") or []
    if not updates:
        return None
    if host_position is None:
        host_position = index - 1

    scored = [u for u in updates if u.get("cvss_base_score") is not None]
    worst = max(scored, key=lambda u: u["cvss_base_score"]) if scored else None
    counts = patch.get("counts", {})
    feed_date = _feed_date(patch)
    kev_evaluated = _kev_evaluated(patch, updates)
    kev = [u for u in updates if u.get("known_exploited") is True]
    # Vendor records are CVEs and advisories (ADV...). They are counted apart here
    # from the rows themselves, so an older MissingUpdates.json without the split
    # counts still reads correctly; an advisory is never called a CVE.
    record_summary, cve_rows, advisories = _record_summary(updates)
    kev_count = counts.get("known_exploited") if type(counts.get("known_exploited")) is int else len(kev)

    # The remediation target is the highest fixed build on the host's servicing
    # branch across every outstanding row, compared numerically. The worst-scoring
    # CVE's own fixed build is often older and would understate the target.
    host_build = _build_tuple(patch.get("observed_build") or patch.get("full_build"))
    fixed = []
    for u in updates:
        build = _build_tuple(u.get("fixed_build"))
        if build is None or len(build) < 2:
            continue
        if host_build and len(host_build) >= 2 and build[-2] != host_build[-2]:
            continue
        fixed.append((build, u))
    fixed.sort(key=lambda item: item[0], reverse=True)
    if fixed:
        max_build = ".".join(str(n) for n in fixed[0][0])
        remediation = (
            "Apply the current cumulative update for this servicing branch. The latest fixed "
            "build referenced by this result is %s (vendor data of %s); confirm the applicable "
            "current update and supersedence with the vendor catalogue before issuing a target "
            "build." % (max_build, feed_date or "an unrecorded date"))
    else:
        max_build = None
        remediation = "ANALYST REQUIRED: remediation target not determined."
    kb_references = []
    for _build, u in fixed:
        kb = u.get("kb")
        if kb and ("KB" + str(kb)) not in kb_references:
            kb_references.append("KB" + str(kb))
        if len(kb_references) == 8:
            break

    if not kev_evaluated:
        exploitability = (
            "The CISA Known Exploited Vulnerabilities catalogue was unavailable or not evaluated "
            "for this result, so exploitation-in-the-wild status is not determined for the "
            "outstanding CVEs. That is not evidence they are not exploited.")
    elif kev:
        exploitability = (
            "As of the catalogue snapshot of %s, %d of the outstanding CVEs appear in the CISA "
            "Known Exploited Vulnerabilities catalogue: %s."
            % (feed_date or "an unrecorded date", len(kev), ", ".join(u["cve"] for u in kev[:10])))
    else:
        exploitability = (
            "As of the catalogue snapshot of %s, no outstanding CVE appears in the CISA Known "
            "Exploited Vulnerabilities catalogue. That is not evidence they cannot be exploited."
            % (feed_date or "an unrecorded date"))

    window = _window_limitations(patch)
    other_limitations = [str(l) for l in (patch.get("limitations") or []) if str(l) not in window]

    evidence = [{
        "evidence_file": "MissingUpdates.json",
        "evidence_pointer": "hosts[%d]" % host_position,
        "asset_id": patch.get("asset_id"),
        "full_build": patch.get("full_build") or patch.get("observed_build"),
        "feed_fetched_utc": patch.get("feed_fetched_utc"),
        "source_batch": patch.get("source_batch"),
        "generated_utc": patch.get("generated_utc"),
    }]
    if host_position == 0:
        # The first host is also mirrored at the top level of MissingUpdates.json
        # for older consumers; only that host may point there.
        evidence.append({
            "evidence_file": "MissingUpdates.json",
            "evidence_pointer": "missing_updates",
            "asset_id": patch.get("asset_id"),
            "full_build": patch.get("full_build") or patch.get("observed_build"),
            "feed_fetched_utc": patch.get("feed_fetched_utc"),
            "source_batch": patch.get("source_batch"),
            "generated_utc": patch.get("generated_utc"),
        })

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
            "that require a later build on this servicing branch; the outstanding "
            "cumulative-update stream carries %s."
            % (patch.get("os_caption"), patch.get("observed_build"), record_summary)),
        "observed_result": (
            "Servicing level %s. Outstanding: %s (%d rated 9.0 or above, %d rated "
            "7.0 to 8.9). Latest fixed build referenced: %s."
            % (patch.get("observed_build"), record_summary,
               counts.get("critical_9_plus", 0), counts.get("high_7_plus", 0),
               max_build or "not determined")),
        "counts": {
            "vendor_records": len(updates),
            "cve_identifiers": len(cve_rows),
            "advisory_identifiers": len(advisories),
            "known_exploited": kev_count,
        },
        "advisories": advisories,
        "technical_interpretation": (
            "Determined by comparing the host's recorded servicing level against the build "
            "in which each fix shipped. No vulnerability was validated by execution."),
        "preconditions": ANALYST,
        "exploitability": exploitability,
        "kev_evaluated": kev_evaluated,
        "attack_chain": ANALYST,
        "proof_of_concept": ("NOT APPLICABLE - determined from servicing level against vendor "
                             "data. No exploitation was attempted."),
        "impact": ANALYST,
        "remediation": remediation,
        "remediation_target_build": max_build,
        "kb_references": {"label": KB_LABEL, "items": kb_references},
        "retest_guidance": "Re-collect the host evidence and confirm the servicing level has advanced past the current cumulative update for this branch.",
        "evidence": evidence,
        "cve_detail": [{
            "cve": u["cve"], "identifier_kind": "CVE" if _is_cve(u.get("cve")) else "advisory",
            "kb": u.get("kb"), "cvss_base_score": u.get("cvss_base_score"),
            "cvss_vector": u.get("cvss_vector"), "fixed_build": u.get("fixed_build"),
            "known_exploited": u.get("known_exploited"),
        } for u in updates],
        "window_truncated": bool(window) or bool(patch.get("window_truncated")),
        "limitations": "; ".join(window + other_limitations),
        "method": "Credentialed servicing-level assessment against vendor published data.",
        "validation": "Not validated by execution.",
    }


# --------------------------------------------------------- software findings
def _software_gap(software):
    return {
        "id": "GAP-SW-01",
        "kind": "CoverageGap",
        "title": "Third-party software could not be assessed for this host",
        "severity": "Not assessed",
        "status": "Not tested",
        "affected_assets": [software.get("asset_id") or software.get("computer_name")],
        "asset_id": software.get("asset_id") or software.get("computer_name"),
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
            "evidence_pointer": "hosts[%d]" % (index - 1),
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


# ------------------------------------------------------------- dispositions
def _read_dispositions(path, known_ids):
    """Analyst dispositions keyed by test_id, validated the way Analyze.merge_manual
    validates Manual.csv: exact columns, no duplicate test_id, every test_id must
    exist in Tests.csv, the disposition must be one of DISPOSITIONS, and an
    evidence file (when named) must exist next to the CSV and match its SHA-256.
    Any violation stops the run; a register must never carry a disposition that
    points at nothing."""
    if not os.path.isfile(path):
        raise SystemExit("Dispositions file not found: %s" % path)
    base = os.path.dirname(os.path.abspath(path))
    records = {}
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != DISPOSITION_FIELDS:
            raise SystemExit("Dispositions CSV columns do not match Templates/ReviewDispositions.csv exactly. "
                             "Expected: %s" % ",".join(DISPOSITION_FIELDS))
        for row in reader:
            test_id = (row.get("test_id") or "").strip()
            if not test_id:
                continue
            if test_id in records:
                raise SystemExit("Duplicate disposition for test_id %s." % test_id)
            if test_id not in known_ids:
                raise SystemExit("Disposition references unknown test_id: %s." % test_id)
            disposition = (row.get("disposition") or "").strip()
            if disposition not in DISPOSITIONS:
                raise SystemExit("Invalid disposition %r for %s. Allowed: %s."
                                 % (disposition, test_id, ", ".join(DISPOSITIONS)))
            evidence = (row.get("evidence_file") or "").strip()
            claimed = (row.get("evidence_sha256") or "").strip().lower()
            actual = ""
            if evidence:
                parts = evidence.replace("\\", "/").split("/")
                if os.path.isabs(evidence) or ".." in parts:
                    raise SystemExit("Disposition evidence path for %s must be relative to the CSV directory." % test_id)
                full = os.path.join(base, *parts)
                if not os.path.isfile(full):
                    raise SystemExit("Disposition evidence file for %s is missing: %s" % (test_id, evidence))
                actual = _sha256(full)
                if not re.fullmatch(r"[0-9a-f]{64}", claimed) or actual != claimed:
                    raise SystemExit("Disposition evidence SHA-256 mismatch for %s." % test_id)
            elif claimed:
                raise SystemExit("Disposition evidence_sha256 provided without evidence_file for %s." % test_id)
            records[test_id] = {
                "disposition": disposition,
                "rationale": (row.get("rationale") or "").strip(),
                "reviewer": (row.get("reviewer") or "").strip(),
                "timestamp_utc": (row.get("timestamp_utc") or "").strip(),
                "evidence_file": evidence,
                "evidence_sha256": actual,
            }
    return records


def _apply_dispositions(review_queue, records):
    for entry in review_queue:
        record = records.get(entry.get("test_id"))
        entry["disposition"] = dict(record) if record else dict(PENDING)
    return review_queue


# ----------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(
        description="Draft a findings register from collected evidence.")
    parser.add_argument("--derived", required=True,
                        help="directory holding Tests.csv (and Coverage.csv) from Analyze.py")
    parser.add_argument("--patch", default=None,
                        help="MissingUpdates.json from PatchCheck.py (optional; if given it must exist)")
    parser.add_argument("--software", default=None,
                        help="SoftwareRisk.json from SoftwareCheck.py (optional; if given it must exist)")
    parser.add_argument("--dispositions", default=None,
                        help="completed Templates/ReviewDispositions.csv (optional)")
    parser.add_argument("--output", required=True, help="output directory")
    parser.add_argument("--engagement-id", default=None,
                        help="engagement the register is for; must equal Evidence.json's engagement_id when "
                             "both are present (default: the engagement_id Evidence.json records, else %s)"
                             % DEFAULT_ENGAGEMENT_ID)
    arguments = parser.parse_args()

    # The derived folder is verified before a single row is read. An edited
    # Tests.csv under an unchanged Manifest.txt, a missing manifest or an
    # unmanifested file means nothing in the folder can be trusted.
    reasons = verify_derived_folder(arguments.derived)
    if reasons:
        return _reject_input(arguments, "Manifest.txt verification of %s failed: %s"
                             % (os.path.abspath(arguments.derived), "; ".join(reasons)))

    tests_path = os.path.join(arguments.derived, "Tests.csv")
    if not os.path.isfile(tests_path):
        raise SystemExit("No Tests.csv in %s. Run Analyze.py first." % arguments.derived)
    with open(tests_path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    known_ids = {row.get("test_id") for row in rows if row.get("test_id")}

    meta = _evidence_metadata(arguments.derived)
    recorded_engagement = meta.get("engagement_id")
    if arguments.engagement_id and recorded_engagement is not None and str(recorded_engagement) != arguments.engagement_id:
        return _reject_input(arguments, "Evidence.json in %s records engagement_id %r but --engagement-id %r was given"
                             % (os.path.abspath(arguments.derived), recorded_engagement, arguments.engagement_id))
    engagement_id = arguments.engagement_id or (str(recorded_engagement) if recorded_engagement else DEFAULT_ENGAGEMENT_ID)
    analysed_batches = _analysed_batches(meta)

    dispositions = {}
    if arguments.dispositions:
        dispositions = _read_dispositions(arguments.dispositions, known_ids)

    findings = _config_findings(rows)

    coverage_gaps = []
    required_input_failures = []
    foreign_input_gaps = []
    # Both engines assess every scoped host and list them under "hosts"; older
    # outputs carry one host at the top level. Every host is read: an undetermined,
    # unattempted or rejected host becomes a coverage gap, never silence. A host
    # whose result was assessed from a batch other than the analysed ones (or from
    # no recorded batch) is a GAP-IN entry and is never converted.
    if arguments.patch:
        if not os.path.isfile(arguments.patch):
            required_input_failures.append(("patch", arguments.patch))
        else:
            patch = _read_json(arguments.patch)
            patch_hosts = patch.get("hosts") or [patch]
            inserted = 0
            for host_index, host_block in enumerate(patch_hosts, 1):
                # Feed date, KEV availability and (in older outputs) the source batch
                # are recorded once at the top level.
                for key in ("feed_fetched_utc", "kev_available", "source_batch"):
                    if key not in host_block and key in patch:
                        host_block[key] = patch[key]
                status = host_block.get("status")
                if status == "Excluded":
                    continue
                foreign = _batch_membership("patch", host_block, patch, analysed_batches)
                if foreign:
                    foreign_input_gaps.append(_foreign_input_gap("patch", arguments.patch, host_block, foreign))
                    continue
                if status in ("Unknown", "EvidenceRejected", "NotAttempted"):
                    gap = _coverage_gap(host_block)
                    gap["id"] = "GAP-PT-%02d" % host_index
                    if status == "EvidenceRejected":
                        gap["title"] = "Patch state not assessed: host evidence rejected"
                        gap["limitations"] = str(host_block.get("rejection_reason") or gap.get("limitations"))
                    elif status == "NotAttempted":
                        gap["title"] = "Patch state not assessed: no verified host evidence for this scoped asset"
                        gap["description"] = ("The asset is in the approved scope but produced no verified host "
                                              "evidence (ledger status %s), so no determination of outstanding "
                                              "security updates was made."
                                              % (host_block.get("ledger_status") or "absent"))
                        gap["limitations"] = str(host_block.get("rejection_reason") or gap.get("limitations"))
                    coverage_gaps.append(gap)
                else:
                    entry = _patch_finding(host_block, host_index, host_position=host_index - 1)
                    if entry:
                        findings.insert(inserted, entry)
                        inserted += 1

    if arguments.software:
        if not os.path.isfile(arguments.software):
            required_input_failures.append(("software", arguments.software))
        else:
            software = _read_json(arguments.software)
            software_hosts = software.get("hosts") or [software]
            for host_index, host_block in enumerate(software_hosts, 1):
                if "source_batch" not in host_block and "source_batch" in software:
                    host_block["source_batch"] = software["source_batch"]
                status = host_block.get("status")
                if status == "Excluded":
                    continue
                foreign = _batch_membership("software", host_block, software, analysed_batches)
                if foreign:
                    foreign_input_gaps.append(_foreign_input_gap("software", arguments.software, host_block, foreign))
                    continue
                if status in ("Unknown", "EvidenceRejected", "NotAttempted"):
                    gap = _software_gap(host_block)
                    gap["id"] = "GAP-SW-%02d" % host_index
                    if status == "EvidenceRejected":
                        gap["title"] = "Third-party software not assessed: host evidence rejected"
                        gap["limitations"] = str(host_block.get("rejection_reason") or gap.get("limitations"))
                    elif status == "NotAttempted":
                        gap["title"] = "Third-party software not assessed: no verified host evidence for this scoped asset"
                        gap["limitations"] = str(host_block.get("rejection_reason") or gap.get("limitations"))
                    coverage_gaps.append(gap)
                else:
                    sw_entry = _software_finding(host_block, host_index)
                    if sw_entry:
                        findings.append(sw_entry)

    for kind, path in required_input_failures:
        coverage_gaps.append(_missing_input_gap(kind, path, len(coverage_gaps) + 1))
    for gap in foreign_input_gaps:
        gap["id"] = "GAP-IN-%02d" % (len(coverage_gaps) + 1)
        coverage_gaps.append(gap)
    input_failures = len(required_input_failures) + len(foreign_input_gaps)

    assets = _read_coverage(arguments.derived)
    coverage_gaps.extend(_asset_coverage_gaps(assets, rows, len(coverage_gaps) + 1))
    coverage_gaps.extend(_scan_gaps(rows, len(coverage_gaps) + 1))

    review_queue = _apply_dispositions(_review_queue(rows), dispositions)
    coverage_gaps.extend(_review_gaps(rows, len(coverage_gaps) + 1))

    needs_analyst = sum(
        1 for f in findings
        for value in f.values()
        if isinstance(value, str) and value == ANALYST)
    pending = sum(1 for entry in review_queue if entry["disposition"].get("disposition") == "Pending")

    document = {
        "schema_version": "1.0",
        "register_status": "DRAFT",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "engagement_id": engagement_id,
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
            "review_queue": len(review_queue),
            "fields_awaiting_analyst": needs_analyst,
            "dispositions_recorded": len(dispositions),
            "pending": pending,
            "scoped_assets": len(assets),
            "scoped_assets_complete": sum(1 for a in assets if a.get("status") in COVERAGE_COMPLETE),
            "required_input_failures": input_failures,
        },
        "findings": findings,
        "coverage_gaps": coverage_gaps,
        "review_queue": review_queue,
    }

    path = _write_register(arguments.output, document)

    print("Draft findings   : %d" % len(findings))
    for finding in findings:
        print("   %-8s %-10s %s" % (finding["id"], finding["severity"], finding["title"][:56]))
    for gap in coverage_gaps:
        print("   %-8s %-10s %s" % (gap["id"], "NOT TESTED", gap["title"][:56]))
    if coverage_gaps:
        print("Coverage gaps    : %d  - these hosts are UNASSESSED, not clean."
              % len(coverage_gaps))
    print("Review queue     : %d rows awaiting analyst disposition (Candidate, Unknown, Error, "
          "Not tested, Inconclusive, scanner observations)" % len(review_queue))
    if dispositions:
        print("Dispositions     : %d recorded, %d review rows still Pending" % (len(dispositions), pending))
    print("Fields awaiting analyst completion: %d" % needs_analyst)
    print("Written          : %s" % path)
    print("Reminder         : seal the derived output after this step with "
          "python Code/SealDerived.py \"%s\" so Manifest.txt covers findings.json and the review files."
          % os.path.abspath(arguments.output))
    if input_failures:
        for kind, missing in required_input_failures:
            print("REQUIRED INPUT MISSING: --%s %s does not exist; recorded as a coverage gap." % (kind, missing))
        for gap in foreign_input_gaps:
            print("INPUT NOT CONVERTED: --%s %s: %s; recorded as a coverage gap."
                  % (gap["input_kind"], gap["input_path"], gap["description"].split(". ")[0]))
        return EXIT_REQUIRED_INPUT
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
