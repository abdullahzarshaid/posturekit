#!/usr/bin/env python3
"""Assess installed third-party software for end-of-life and outdated versions.

Method
------
The collector records installed software in the ``software`` source, read from
the machine uninstall registry as ``{Name, Version, Publisher}``.  This module
reads that inventory off-host and flags three things:

  * End-of-life software     - a product line that no longer receives security
                               updates from its vendor (a stable, dated fact).
  * Version below a floor     - an installed version older than a curated, dated
                               reference floor for a high-risk product.
  * KEV product presence      - a product family that appears in the CISA Known
                               Exploited Vulnerabilities catalogue is present;
                               advisory only, because KEV has no version field.

What this deliberately does NOT do
----------------------------------
It never maps an arbitrary product+version to a CVE.  Blind CPE / keyword
matching produces confident findings for software the host does not run and
mis-scores versions, so it is not used.  Every signal here is either a dated
vendor lifecycle fact, a comparison against a curated floor, or an advisory
product-presence flag - each one an assessor confirms before it reaches a
report.  Severity is never assigned by this module.

Windows operating-system updates are handled by PatchCheck.py; this module
ignores Microsoft OS components and security-update (KB) entries.

The curated catalogue below is dated and must be reviewed each quarter.  It is
bundled so the module runs fully offline.  The optional CISA KEV overlay reuses
the cache PatchCheck.py already populated; no new network access is introduced.

A Host file is assessed only after its digest matches the ledger AND its own
identity agrees with the ledger target (``EvidenceGate.validate_host_document``:
schema, engagement, asset, site, computer name, scope and collector lineage). A
contradiction is EvidenceRejected under the ledger's asset id, never assessed.
``source_batch`` is the ledger's ``batch_id`` (the folder basename is kept as
``source_batch_dir``); ``collector_sha256`` is recorded as the batch recorded it.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

# Scope.json / Batch.json validation and per-target accounting are shared with
# Analyze.py and PatchCheck.py (Code\EvidenceGate.py).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Code"))
import EvidenceGate  # noqa: E402

CATALOG_DATE = "2026-09"   # review quarterly

# --- 1. End-of-life: any installed version of these product lines is unsupported
EOL_ANY = [
    (("adobe flash player",), "Adobe Flash Player reached end-of-life in December 2020."),
    (("microsoft silverlight",), "Microsoft Silverlight reached end-of-life in October 2021."),
    (("adobe shockwave",), "Adobe Shockwave Player was discontinued in April 2019."),
    (("quicktime",), "Apple QuickTime for Windows stopped receiving security updates in 2016."),
    (("adobe air",), "Adobe stopped supporting Adobe AIR (transferred to HARMAN); confirm the support status of this build."),
]

# --- 2. End-of-life below a major version (product line lifecycle)
#     (name tokens, first still-supported major, reason)
EOL_BELOW_MAJOR = [
    (("python",), 3, "Python 2.x reached end-of-life in January 2020."),
    (("node.js", "nodejs"), 18, "Node.js releases below 18 are end-of-life."),
    (("openssl",), 3, "OpenSSL 1.x lines are end-of-life; 3.0 or later is supported."),
    (("mysql server",), 8, "MySQL Server 5.x is end-of-life; 8.0 or later is supported."),
    (("postgresql",), 13, "PostgreSQL below 13 is end-of-life."),
]

# --- 3. Reference version floors for high-risk, frequently-updated products.
#     Below the floor is treated as outdated. Floors are dated references, not
#     precise CVE boundaries; an assessor confirms current status.
#     (name tokens, floor tuple, floor label, publisher hint or None)
FLOORS = [
    (("google chrome",),      (120, 0, 0, 0), "120",                          "google"),
    (("mozilla firefox",),    (115, 0, 0, 0), "115 (ESR line)",               "mozilla"),
    (("7-zip",),              (23, 0, 0, 0),  "23.00",                        None),
    (("winrar",),             (6, 23, 0, 0),  "6.23 (older is exploited - CVE-2023-38831)", None),
    (("vlc media player",),   (3, 0, 18, 0),  "3.0.18",                       "videolan"),
    (("wireshark",),          (4, 0, 0, 0),   "4.0",                          None),
    (("putty",),              (0, 76, 0, 0),  "0.76",                         None),
    (("filezilla",),          (3, 60, 0, 0),  "3.60",                         None),
    (("notepad++",),          (8, 4, 0, 0),   "8.4",                          None),
    (("zoom",),               (5, 13, 0, 0),  "5.13",                         None),
    (("git",),                (2, 40, 0, 0),  "2.40",                         None),
    (("libreoffice",),        (7, 5, 0, 0),   "7.5",                          None),
    (("apache tomcat",),      (9, 0, 0, 0),   "9.0 (older lines are end-of-life)", None),
]

# Names that look like third-party software but are Microsoft OS / update content
# handled elsewhere, or are not application software. Excluded to avoid noise.
# Every pattern is anchored on word boundaries: the bare substring "kb" used
# here before dropped "QuickBooks" and "ThinkBook" from the inventory.
_EXCLUDE_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\bkb\d{4,}\b",                     # KB5031356 (a KB article number)
    r"\bsecurity update\b",
    r"\bupdate for\b",
    r"\bhotfix\b",
    r"\bservicing stack\b",
    r"\bmicrosoft visual c\+\+ 20\d\d\b",  # runtimes, handled by their own updates
    r"\bwindows software development kit\b",
    r"\bmicrosoft edge webview\b",
))

CATALOG_WARNING = (
    "The bundled version floors and lifecycle facts are a curated snapshot dated "
    "%s. They may be out of date; confirm each flagged item against the vendor's "
    "current lifecycle and release information before it reaches a report."
    % CATALOG_DATE)


def _excluded(name):
    return any(pattern.search(name) for pattern in _EXCLUDE_PATTERNS)


def _read_json(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, ValueError):
            continue
    raise SystemExit("Cannot decode JSON: %s" % path)


def _norm(name):
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def parse_version(text):
    """Leading dotted-numeric version -> tuple of ints, else None.

    '120.0.6099.109' -> (120,0,6099,109); '3.0.18' -> (3,0,18);
    '1.1.1w' -> (1,1,1) (trailing non-numeric is ignored);
    '8u331', 'unknown', '' -> None (not confidently parseable).
    """
    if not text:
        return None
    match = re.match(r"\s*(\d+(?:\.\d+)*)", str(text))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _java_major(name, version):
    """Return the Java major version if this looks like a Java runtime, else None.

    Handles '8u331', '1.8.0_331' (=8) and '17.0.2'.
    """
    if "java" not in name and "jre" not in name and "jdk" not in name:
        return None
    v = str(version or "")
    m = re.search(r"\b8u\d+", v) or re.search(r"1\.8\.", v)
    if m:
        return 8
    m = re.match(r"\s*(\d+)", v)
    if m:
        major = int(m.group(1))
        return major if major != 1 else None  # 1.x handled above
    return None


def _matches(name, tokens):
    return any(tok in name for tok in tokens)


def assess(inventory, kev_products):
    items = []
    for entry in inventory:
        raw_name = entry.get("Name") or entry.get("name")
        version = entry.get("Version") or entry.get("version")
        publisher = entry.get("Publisher") or entry.get("publisher")
        name = _norm(raw_name)
        if not name or _excluded(name):
            continue
        vt = parse_version(version)

        # Java lifecycle (special version scheme)
        jm = _java_major(name, version)
        if jm is not None and jm <= 8:
            items.append(_item(raw_name, version, publisher, "EndOfLife",
                               "Java SE %s and earlier no longer receive public "
                               "security updates without a support subscription." % jm))
            continue

        matched = False
        for tokens, reason in EOL_ANY:
            if _matches(name, tokens):
                items.append(_item(raw_name, version, publisher, "EndOfLife", reason))
                matched = True
                break
        if matched:
            continue

        for tokens, first_major, reason in EOL_BELOW_MAJOR:
            if _matches(name, tokens) and vt and vt[0] < first_major:
                items.append(_item(raw_name, version, publisher, "EndOfLife", reason))
                matched = True
                break
        if matched:
            continue

        for tokens, floor, label, pub in FLOORS:
            if not _matches(name, tokens):
                continue
            if pub and publisher and pub not in _norm(publisher):
                continue
            if vt is None:
                items.append(_item(raw_name, version, publisher, "VersionUnreadable",
                                   "Version string could not be parsed; confirm it is at "
                                   "or above %s manually." % label))
            elif vt < floor:
                items.append(_item(raw_name, version, publisher, "BelowVersionFloor",
                                   "Installed version is below the curated reference "
                                   "floor of %s (as of %s)." % (label, CATALOG_DATE)))
            matched = True
            break
        if matched:
            continue

        # KEV product presence - advisory only
        if kev_products:
            for token in kev_products:
                if token and len(token) >= 4 and token in name:
                    items.append(_item(raw_name, version, publisher, "KevProductPresent",
                                       "A product family in the CISA Known Exploited "
                                       "Vulnerabilities catalogue is present. This is a "
                                       "presence flag, not a version match; confirm the "
                                       "installed version and patch level."))
                    break
    return items


def _item(name, version, publisher, risk, basis):
    return {
        "name": name,
        "version": version,
        "publisher": publisher,
        "risk_type": risk,
        "basis": basis,
        "severity": "ANALYST REQUIRED",
    }


def _kev_products(cache_dir):
    """Reuse PatchCheck's cached KEV file to build a set of product/vendor tokens.

    Cache-only; introduces no network access. Returns an empty set when absent.
    """
    if not cache_dir:
        return set()
    path = os.path.join(cache_dir, "cisa_kev.json")
    if not os.path.isfile(path):
        return set()
    try:
        kev = _read_json(path)
    except SystemExit:
        return set()
    tokens = set()
    for v in kev.get("vulnerabilities", []):
        for field in ("product", "vendorProject"):
            val = _norm(v.get(field))
            # keep single distinctive words to reduce false matches
            for word in val.split():
                if len(word) >= 5 and word not in ("microsoft", "windows", "server",
                                                    "adobe", "system", "manager"):
                    tokens.add(word)
    return tokens


def main():
    parser = argparse.ArgumentParser(
        description="Assess installed third-party software for EOL and outdated versions.")
    parser.add_argument("--batch", required=True, help="sealed raw batch directory")
    parser.add_argument("--output", required=True, help="output directory")
    parser.add_argument("--cache", default=None,
                        help="cache directory holding cisa_kev.json (optional, cache-only)")
    parser.add_argument("--no-kev", action="store_true",
                        help="skip the KEV product-presence overlay")
    arguments = parser.parse_args()

    try:
        identity, gate = gate_batch(arguments.batch)
    except ValueError as exc:
        raise SystemExit("Refusing to assess %s: %s" % (arguments.batch, exc))
    if not gate:
        raise SystemExit("No target is accounted for in %s. Nothing was collected from this "
                         "batch." % arguments.batch)
    batch_dir_name = os.path.basename(os.path.abspath(arguments.batch))
    # The batch a result came from is the ledger's batch_id, not a folder name.
    batch_name = identity["batch_id"] or batch_dir_name

    kev_products = set() if arguments.no_kev else _kev_products(arguments.cache)
    kev_limitation = None
    if not kev_products and not arguments.no_kev:
        kev_limitation = (
            "No cached CISA KEV catalogue was available, so the product-presence overlay "
            "was not applied. Run PatchCheck.py once with network access to populate it.")

    result = {
        "schema_version": "1.0",
        "evidence_kind": "SoftwareRiskAssessment",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_batch": batch_name,
        "source_batch_dir": batch_dir_name,
        "engagement_id": identity["engagement_id"],
        "scope_sha256": identity["scope_sha256"],
        "collector_sha256": identity["collector_sha256"],
        "catalog_date": CATALOG_DATE,
        "catalog_warning": CATALOG_WARNING,
        "method": ("Installed-software inventory (uninstall registry) compared against a "
                   "curated, dated lifecycle catalogue and reference version floors, plus an "
                   "advisory CISA KEV product-presence overlay. No CVE was matched to a "
                   "product/version, nothing was executed, and nothing was exploited."),
        "status": None,
        "hosts": [],
    }
    for gate_host in gate:
        if gate_host["status"] == "Accepted":
            result["hosts"].append(assess_host(gate_host["document"], kev_products,
                                               kev_limitation, batch_name))
        else:
            result["hosts"].append(_unassessed(gate_host, batch_name))

    # The first host is mirrored at the top level for backward compatibility.
    first = result["hosts"][0]
    for key, value in first.items():
        if key not in result:
            result[key] = value
    result["status"] = first["status"]

    _write(arguments.output, result)
    statuses = [h["status"] for h in result["hosts"]]
    if "RiskySoftware" in statuses:
        return 1
    if any(s in ("Unknown", "EvidenceRejected", "NotAttempted") for s in statuses):
        return 2
    return 0


def gate_hosts(batch):
    """Account for every target in the approved scope of a sealed batch.

    Same contract as PatchCheck.gate_hosts: one dict per approved target with
    status Accepted (digest verified, identity verified, document loaded),
    EvidenceRejected, NotAttempted or Excluded, plus the ledger reason. A Host
    file on disk that no accepted ledger entry covers is EvidenceRejected, never
    assessed; so is a digest-consistent file whose own identity contradicts the
    ledger target (listed under the LEDGER asset id with every contradiction).
    Raises ValueError when Batch.json or Scope.json is missing or invalid.
    """
    return gate_batch(batch)[1]


def gate_batch(batch):
    """(identity, hosts): identity is the ledger's own {'batch_id', 'engagement_id',
    'scope_sha256', 'collector_sha256', 'batch_dir'}; hosts is gate_hosts()."""
    gate = EvidenceGate.verify_batch(batch)
    identity = {
        "batch_id": None if gate.get("batch_id") is None else str(gate["batch_id"]),
        "engagement_id": gate.get("engagement_id"),
        "scope_sha256": gate.get("scope_sha256"),
        "collector_sha256": (gate.get("batch") or {}).get("collector_sha256"),
        "batch_dir": gate.get("batch_dir"),
    }
    targets = {t["asset_id"]: t for t in gate["targets"]}
    on_disk = {}
    for name in sorted(os.listdir(batch)):
        if name.startswith("Host.") and name.lower().endswith(".json"):
            try:
                on_disk[name] = _read_json(os.path.join(batch, name))
            except SystemExit:
                on_disk[name] = None
    claimed = set()
    hosts = []
    for entry in gate["hosts"]:
        asset_id = entry["asset_id"]
        record = {"asset_id": asset_id, "status": None, "evidence_file": entry.get("evidence_file"),
                  "document": None, "reason": entry.get("reason"), "ledger_status": entry.get("status")}
        if entry["status"] == "Excluded":
            record["status"] = "Excluded"
        elif entry["status"] == "EvidenceRejected":
            record["status"] = "EvidenceRejected"
            if entry.get("digest_ok") is False:
                record["reason"] = ("evidence digest mismatch: SHA-256 of %s does not equal the "
                                    "evidence_sha256 recorded for asset %s in Batch.json"
                                    % (entry.get("evidence_file"), asset_id))
            claimed.add(entry.get("evidence_file"))
        elif entry["status"] in ("Complete", "Partial"):
            name = entry["evidence_file"]
            claimed.add(name)
            document = on_disk.get(name)
            if document is None:
                record.update(status="EvidenceRejected", reason="%s could not be read" % name)
            else:
                contradictions = EvidenceGate.validate_host_document(document, targets[asset_id], gate["batch"])
                if contradictions:
                    record.update(status="EvidenceRejected", document=document,
                                  reason="host document identity mismatch in %s for ledger asset %s: %s"
                                         % (name, asset_id, "; ".join(contradictions)))
                else:
                    record.update(status="Accepted", document=document)
        else:
            record["status"] = "NotAttempted"
            unsealed = [n for n, d in on_disk.items()
                        if n not in claimed and isinstance(d, dict) and str(d.get("asset_id")) == str(asset_id)]
            if unsealed:
                claimed.add(unsealed[0])
                record.update(status="EvidenceRejected", evidence_file=unsealed[0],
                              reason="no ledger entry in Batch.json for asset %s (%s): the file is present "
                                     "but not sealed, so it cannot be verified" % (asset_id, unsealed[0]))
        hosts.append(record)
    for name, document in on_disk.items():
        if name in claimed:
            continue
        asset_id = document.get("asset_id") if isinstance(document, dict) else None
        hosts.append({"asset_id": asset_id, "status": "EvidenceRejected", "evidence_file": name,
                      "document": None, "ledger_status": None,
                      "reason": "no ledger entry in Batch.json for asset %s (%s) and the asset is not in "
                                "the approved scope" % (asset_id, name)})
    return identity, hosts


def _unassessed(gate_host, batch_name):
    """Per-host record for a target that produced no verified inventory:
    EvidenceRejected, NotAttempted or Excluded, with the reason. Never clean.
    Listed under the LEDGER asset id; a rejected document's own asset_id is kept
    as document_asset_id so the contradiction stays visible."""
    status = gate_host["status"]
    document = gate_host.get("document") if isinstance(gate_host.get("document"), dict) else {}
    result = {
        "asset_id": gate_host.get("asset_id"),
        "computer_name": gate_host.get("asset_id"),
        "document_asset_id": document.get("asset_id"),
        "source_batch": batch_name,
        "collector_sha256": document.get("collector_sha256"),
        "inventory_status": None,
        "status": status,
        "ledger_status": gate_host.get("ledger_status"),
        "evidence_file": gate_host.get("evidence_file"),
        "rejection_reason": gate_host.get("reason"),
        "items": [],
        "counts": {},
        "limitations": [],
    }
    if status == "Excluded":
        result["limitations"].append("Excluded by the approved scope; not assessed.")
    elif status == "EvidenceRejected":
        result["limitations"].append(
            "Evidence rejected: %s. No software determination was made for this host "
            "and it must not be presented as assessed." % gate_host.get("reason"))
    else:
        result["limitations"].append(
            "No verified host evidence for this target (ledger status %s: %s). Third-party "
            "software was not assessed. This is NOT evidence that the host carries no "
            "outdated software." % (gate_host.get("ledger_status") or "absent", gate_host.get("reason")))
    return result


def software_inventory(host_document):
    """(inventory_list_or_None, source_status, limitation_or_None).

    The inventory is usable only when the software source reports Collected or
    Partial and carries a list. An absent source, an Error/Unsupported status,
    or a non-list payload yields None: the host is then Unknown, never clean.
    """
    found = None
    for source in host_document.get("sources", []) or []:
        if source.get("id") == "software":
            found = source
            break
    if found is None:
        return None, None, ("The software inventory was not collected on this host (no "
                            "software source in the evidence), so third-party software "
                            "could not be assessed. This is not evidence that the host "
                            "carries no outdated software.")
    status = (found.get("status") or "").strip()
    data = found.get("data")
    if status.lower() not in ("collected", "partial") or not isinstance(data, list):
        return None, status, ("The software inventory was not collected on this host "
                              "(source status %s), so third-party software could not be "
                              "assessed. This is not evidence that the host carries no "
                              "outdated software." % (status or "not recorded"))
    if status.lower() == "partial":
        return data, status, ("The software inventory was only partially collected "
                              "(source status Partial), so software not in the returned "
                              "subset was not assessed. An absent item is not evidence "
                              "of its absence on the host.")
    return data, status, None


def assess_host(host_document, kev_products, kev_limitation, batch_name):
    """Assess one host record. Returns the per-host result dict."""
    host = host_document.get("host", {}) or {}
    inventory, source_status, note = software_inventory(host_document)
    result = {
        "asset_id": host_document.get("asset_id"),
        "computer_name": host.get("computer_name"),
        "source_batch": batch_name,
        "collector_sha256": host_document.get("collector_sha256"),
        "inventory_status": source_status,
        "status": None,
        "items": [],
        "counts": {},
        "limitations": [
            "Only software registered in the machine uninstall registry is seen; "
            "user-only, portable and unregistered software is not.",
            "The catalogue is a curated, dated reference (%s) and must be reviewed "
            "quarterly; it is not a complete vulnerability database." % CATALOG_DATE,
            "A 'below floor' or 'end-of-life' item is an outdated/unsupported observation, "
            "not a validated exploitable vulnerability. An assessor assigns severity.",
            "KEV product presence is a family-level flag with no version match; confirm the "
            "installed version and patch level before drawing any conclusion.",
        ],
    }

    if inventory is None:
        result["status"] = "Unknown"
        result["limitations"].insert(0, note)
        return result
    if note:
        result["limitations"].insert(0, note)
    if kev_limitation:
        result["limitations"].append(kev_limitation)

    items = assess(inventory, kev_products)
    order = {"EndOfLife": 0, "BelowVersionFloor": 1, "KevProductPresent": 2, "VersionUnreadable": 3}
    items.sort(key=lambda it: order.get(it["risk_type"], 9))
    result["items"] = items
    result["counts"] = {
        "inventory_size": len(inventory),
        "flagged": len(items),
        "end_of_life": sum(1 for i in items if i["risk_type"] == "EndOfLife"),
        "below_floor": sum(1 for i in items if i["risk_type"] == "BelowVersionFloor"),
        "kev_product_present": sum(1 for i in items if i["risk_type"] == "KevProductPresent"),
        "version_unreadable": sum(1 for i in items if i["risk_type"] == "VersionUnreadable"),
    }
    # NoRiskySoftwareFound is only ever stated for an inventory that was collected.
    result["status"] = "RiskySoftware" if items else "NoRiskySoftwareFound"
    return result


def _write(output_dir, result):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "SoftwareRisk.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1)
    hosts = result.get("hosts") or [result]
    for host in hosts:
        counts = host.get("counts", {})
        print("Host                : %s" % (host.get("computer_name") or host.get("asset_id")))
        print("Status              : %s" % host["status"])
        if host.get("rejection_reason"):
            print("Reason              : %s" % host["rejection_reason"])
        if counts:
            print("Inventory / flagged : %d / %d" % (counts.get("inventory_size", 0),
                                                      counts.get("flagged", 0)))
            print("End-of-life         : %d" % counts.get("end_of_life", 0))
            print("Below version floor : %d" % counts.get("below_floor", 0))
            print("KEV product present : %d" % counts.get("kev_product_present", 0))
        print("")
    print("Catalogue           : %s" % result.get("catalog_warning"))
    print("Written             : %s" % path)
    print("Analyst review is required before any of this reaches a report.")


if __name__ == "__main__":
    sys.exit(main())
