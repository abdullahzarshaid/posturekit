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
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

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
_EXCLUDE = (
    "security update", "update for", "hotfix", "kb", "servicing stack",
    "microsoft visual c++ 20",           # runtimes, handled by their own updates
    "windows software development kit", "microsoft edge webview",
)


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
        if not name or any(x in name for x in _EXCLUDE):
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

    host_files = [n for n in os.listdir(arguments.batch) if n.startswith("Host.")]
    if not host_files:
        raise SystemExit("No Host.*.json in %s. Nothing was collected from this "
                         "target." % arguments.batch)
    host_document = _read_json(os.path.join(arguments.batch, host_files[0]))
    host = host_document.get("host", {})

    inventory = None
    for source in host_document.get("sources", []):
        if source.get("id") == "software":
            if (source.get("status") or "").lower() not in ("collected", "ok", "complete", ""):
                inventory = None
            inventory = source.get("data")
            break

    result = {
        "schema_version": "1.0",
        "evidence_kind": "SoftwareRiskAssessment",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "asset_id": host_document.get("asset_id"),
        "computer_name": host.get("computer_name"),
        "source_batch": os.path.basename(os.path.abspath(arguments.batch)),
        "catalog_date": CATALOG_DATE,
        "method": ("Installed-software inventory (uninstall registry) compared against a "
                   "curated, dated lifecycle catalogue and reference version floors, plus an "
                   "advisory CISA KEV product-presence overlay. No CVE was matched to a "
                   "product/version, nothing was executed, and nothing was exploited."),
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
        result["limitations"].insert(
            0, "The software inventory source was not present or not collected on this host, "
               "so third-party software could not be assessed. This is not evidence that the "
               "host carries no outdated software.")
        _write(arguments.output, result)
        return 2

    kev_products = set() if arguments.no_kev else _kev_products(arguments.cache)
    if not kev_products and not arguments.no_kev:
        result["limitations"].append(
            "No cached CISA KEV catalogue was available, so the product-presence overlay "
            "was not applied. Run PatchCheck.py once with network access to populate it.")

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
    result["status"] = "RiskySoftware" if items else "NoRiskySoftwareFound"
    _write(arguments.output, result)
    return 0 if not items else 1


def _write(output_dir, result):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "SoftwareRisk.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1)
    counts = result.get("counts", {})
    print("Status              : %s" % result["status"])
    if counts:
        print("Inventory / flagged : %d / %d" % (counts.get("inventory_size", 0),
                                                  counts.get("flagged", 0)))
        print("End-of-life         : %d" % counts.get("end_of_life", 0))
        print("Below version floor : %d" % counts.get("below_floor", 0))
        print("KEV product present : %d" % counts.get("kev_product_present", 0))
    print("Written             : %s" % path)
    print("Analyst review is required before any of this reaches a report.")


if __name__ == "__main__":
    sys.exit(main())
