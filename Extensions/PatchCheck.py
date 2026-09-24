#!/usr/bin/env python3
"""Determine missing Microsoft security updates for a collected host.

Method
------
The collector records the exact servicing level of the host as
``host.full_build`` (for example ``10.0.26200.9457``), read from
``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`` -> ``CurrentBuild`` +
``UBR``.  Microsoft publishes, per CVE and per product, the build in which the
fix shipped (``FixedBuild``).  A CVE is therefore outstanding on this host when
its ``FixedBuild`` for the matching product is greater than the host's own
build.

This is the same mechanism a credentialed vulnerability scan uses.  Nothing is
executed on the host and nothing is exploited; the determination is made
off-host from vendor data.

Deliberate limits
-----------------
* The hotfix list (``Win32_QuickFixEngineering``) is NOT used.  It omits
  cumulative updates, so it understates patch state on Windows 10/11 and
  Server 2016+.
* Only Microsoft operating-system CVEs are covered.  Third-party software is
  out of scope for this module.
* Severity is taken from Microsoft's own CVSS vector.  It is never invented
  here, and an analyst must still confirm the rating is appropriate for the
  client before it reaches a report.

Data sources, all free and requiring no API key:
    MSRC CVRF   https://api.msrc.microsoft.com/cvrf/v3.0/
    CISA KEV    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Both are cached to disk so an assessment can run fully offline once the cache
has been populated on an internet-connected machine.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

MSRC_INDEX = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_DOC = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{}"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
UA = "-NetworkAssessment/PatchCheck"
TIMEOUT = 90


# --------------------------------------------------------------------------- io
def _read_json(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    for encoding in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, ValueError):
            continue
    raise SystemExit("Cannot decode JSON: %s" % path)


def _fetch(url):
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _cached(cache_dir, name, url, offline):
    """Return cached JSON, fetching and storing it when permitted."""
    path = os.path.join(cache_dir, name)
    if os.path.isfile(path):
        return _read_json(path), "cache"
    if offline:
        raise SystemExit(
            "Offline mode and no cached copy of %s. Populate the cache on a "
            "connected machine with --refresh first." % name)
    data = _fetch(url)
    os.makedirs(cache_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return data, "network"


# ------------------------------------------------------------------- build math
def _build_tuple(text):
    """'10.0.26200.9457' -> (10, 0, 26200, 9457); None when unparseable."""
    if not text:
        return None
    parts = str(text).strip().split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _product_names(document):
    """Flatten the per-document ProductTree into {ProductID: name}."""
    names = {}

    def walk(branch):
        for child in branch.get("Branch", []):
            walk(child)
        for product in branch.get("FullProductName", []):
            names[product["ProductID"]] = product["Value"]

    tree = document.get("ProductTree", {})
    for branch in tree.get("Branch", []):
        walk(branch)
    for product in tree.get("FullProductName", []):
        names[product["ProductID"]] = product["Value"]
    return names


# The collector records os_caption, architecture, display_version and the
# installation type. Those four identify the Microsoft product exactly, without
# guessing.
_ARCH = {"64-bit": "x64", "32-bit": "32-bit", "ARM64": "ARM64"}

# Products that contain the word "Server" but are not the Windows operating
# system. Matching on "server <year>" alone pulls these in.
_NOT_WINDOWS = ("sql server", "exchange server", "sharepoint server",
                "skype for business", "office online server", "management studio",
                "azure arc")


def match_product(names, os_caption, display_version, architecture,
                  installation_type=None):
    """Return [(product_id, product_name)] for this host, best match first.

    Matching is deliberately strict. Where the evidence does not identify a
    product beyond doubt the caller reports Unknown, because a wrong product
    match produces confident findings for software the host does not run.
    """
    caption = (os_caption or "").lower()
    arch = _ARCH.get(architecture, architecture or "")
    release = (display_version or "").strip()
    core = "core" in (installation_type or "").lower()

    candidates = []

    if "windows server" in caption:
        # Server: the year identifies the product. Architecture does not appear
        # in Microsoft's Windows Server product names.
        import re as _re
        year = _re.search(r"windows server\s+(\d{4})", caption)
        if not year:
            return []
        want_core = "(server core installation)"
        for product_id, name in names.items():
            if "-" in product_id:
                continue
            lowered = name.lower()
            if any(bad in lowered for bad in _NOT_WINDOWS):
                continue
            if not lowered.startswith("windows server " + year.group(1)):
                continue
            is_core = want_core in lowered
            if is_core != core:
                continue
            candidates.append((10, product_id, name))

    elif "windows 11" in caption or "windows 10" in caption:
        family = "windows 11" if "windows 11" in caption else "windows 10"
        if not release:
            # Without the release there is no way to know which product applies,
            # and picking the newest would be a guess presented as a fact.
            return []
        for product_id, name in names.items():
            if "-" in product_id:
                continue
            lowered = name.lower()
            if any(bad in lowered for bad in _NOT_WINDOWS):
                continue
            if not lowered.startswith(family + " version " + release.lower()):
                continue
            if arch and arch.lower() not in lowered:
                continue
            candidates.append((10, product_id, name))

    else:
        return []

    candidates.sort(reverse=True)
    return [(product_id, name) for _score, product_id, name in candidates]


def missing_for_host(document, product_id, host_build):
    """CVEs whose fix requires a build newer than the host's."""
    findings = []
    for vulnerability in document.get("Vulnerability", []):
        cve = vulnerability.get("CVE")
        title = (vulnerability.get("Title") or {}).get("Value")
        scores = vulnerability.get("CVSSScoreSets") or [{}]
        base = scores[0].get("BaseScore")
        vector = scores[0].get("Vector")
        for remediation in vulnerability.get("Remediations", []):
            if product_id not in (remediation.get("ProductID") or []):
                continue
            fixed = _build_tuple(remediation.get("FixedBuild"))
            if not fixed or len(fixed) != len(host_build) or fixed <= host_build:
                continue
            findings.append({
                "cve": cve,
                "title": title,
                "kb": (remediation.get("Description") or {}).get("Value"),
                "fixed_build": remediation.get("FixedBuild"),
                "observed_build": ".".join(str(n) for n in host_build),
                "cvss_base_score": base,
                "cvss_vector": vector,
                "restart_required": remediation.get("RestartRequired"),
                "url": remediation.get("URL"),
            })
            break  # one remediation per CVE per product is enough
    return findings


# ------------------------------------------------------------------------ main
def main():
    parser = argparse.ArgumentParser(
        description="Determine missing Microsoft updates from collected evidence.")
    parser.add_argument("--batch", required=True,
                        help="sealed raw batch directory")
    parser.add_argument("--output", required=True,
                        help="directory for the result (created if absent)")
    parser.add_argument("--cache", default=None,
                        help="vendor-data cache directory (default: <output>/cache)")
    parser.add_argument("--months", type=int, default=12,
                        help="how many recent monthly vendor releases to evaluate (default 12). "
                             "A narrow window under-reports: measured on one host, three months "
                             "found 1 known-exploited vulnerability where twelve found 16. Widen "
                             "it, never narrow it, unless you have a reason you can write down.")
    parser.add_argument("--offline", action="store_true",
                        help="use only cached vendor data; never reach the network")
    parser.add_argument("--refresh", action="store_true",
                        help="re-download vendor data even when cached")
    arguments = parser.parse_args()

    batch = arguments.batch
    host_files = [name for name in os.listdir(batch) if name.startswith("Host.")]
    if not host_files:
        raise SystemExit("No Host.*.json in %s. Nothing was collected from this "
                         "target, so no patch determination is possible." % batch)

    host_document = _read_json(os.path.join(batch, host_files[0]))
    host = host_document.get("host", {})
    full_build = host.get("full_build")
    build = _build_tuple(full_build)

    # Server Core is a separate Microsoft product with its own fixed builds, so the
    # installation type has to be part of the match.
    installation_type = None
    for source in host_document.get("sources", []):
        if source.get("id") == "patchlevel" and source.get("data"):
            installation_type = (source["data"][0] or {}).get("InstallationType")
            break

    cache_dir = arguments.cache or os.path.join(arguments.output, "cache")
    os.makedirs(arguments.output, exist_ok=True)
    if arguments.refresh and os.path.isdir(cache_dir):
        for name in os.listdir(cache_dir):
            os.remove(os.path.join(cache_dir, name))

    result = {
        "schema_version": "1.0",
        "evidence_kind": "MissingUpdateAssessment",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "asset_id": host_document.get("asset_id"),
        "computer_name": host.get("computer_name"),
        "os_caption": host.get("os_caption"),
        "display_version": host.get("display_version"),
        "architecture": host.get("architecture"),
        "installation_type": installation_type,
        "observed_build": full_build,
        "source_batch": os.path.basename(os.path.abspath(batch)),
        "method": ("Servicing level recorded by the collector compared against "
                   "Microsoft CVRF FixedBuild per product. No host execution, "
                   "no exploitation, no vulnerability validation."),
        "status": None,
        "product_matched": None,
        "documents_evaluated": [],
        "missing_updates": [],
        "limitations": [],
    }

    if not build:
        result["status"] = "Unknown"
        result["limitations"].append(
            "The host record carries no parseable full_build, so patch state "
            "cannot be determined. Re-collect with a collector that records "
            "CurrentBuild and UBR.")
        _write(arguments.output, result)
        return 2

    index, _origin = _cached(cache_dir, "msrc_index.json", MSRC_INDEX,
                             arguments.offline)
    releases = index.get("value", index)
    recent = releases[-arguments.months:] if arguments.months else releases

    product_id = None
    product_name = None
    seen = {}

    for release in recent:
        release_id = release["ID"]
        document, _origin = _cached(
            cache_dir, "msrc_%s.json" % release_id,
            MSRC_DOC.format(release_id), arguments.offline)
        names = _product_names(document)

        if product_id is None:
            candidates = match_product(names, host.get("os_caption"),
                                       host.get("display_version"),
                                       host.get("architecture"),
                                       installation_type)
            if candidates:
                product_id, product_name = candidates[0]

        if product_id is None or product_id not in names:
            result["documents_evaluated"].append(
                {"release": release_id, "matched": False})
            continue

        result["documents_evaluated"].append(
            {"release": release_id, "matched": True})
        for finding in missing_for_host(document, product_id, build):
            # Keep the earliest advertised fix for each CVE.
            if finding["cve"] not in seen:
                finding["msrc_release"] = release_id
                seen[finding["cve"]] = finding

    if product_id is None:
        result["status"] = "Unknown"
        result["limitations"].append(
            "No Microsoft product matched this host's caption (%s), release (%s), "
            "architecture (%s) and installation type (%s), so no determination was "
            "made. This is NOT evidence that the host is patched. A client host "
            "reporting no readable release version will land here by design, "
            "because guessing the release would produce confident findings for "
            "software the host may not run."
            % (host.get("os_caption"), host.get("display_version") or "not recorded",
               host.get("architecture"), installation_type or "not recorded"))
        _write(arguments.output, result)
        return 2

    result["product_matched"] = {"product_id": product_id, "name": product_name}

    # CISA Known Exploited Vulnerabilities overlay - prioritisation only.
    kev_ids = set()
    try:
        kev, _origin = _cached(cache_dir, "cisa_kev.json", KEV_URL,
                               arguments.offline)
        kev_ids = {entry["cveID"] for entry in kev.get("vulnerabilities", [])}
    except SystemExit:
        result["limitations"].append(
            "The CISA Known Exploited Vulnerabilities catalogue was not "
            "available, so no exploitation-in-the-wild overlay was applied.")
    except (urllib.error.URLError, ValueError, KeyError):
        result["limitations"].append(
            "The CISA Known Exploited Vulnerabilities catalogue could not be "
            "read, so no exploitation-in-the-wild overlay was applied.")

    findings = sorted(seen.values(),
                      key=lambda item: -(item.get("cvss_base_score") or 0))
    for finding in findings:
        finding["known_exploited"] = finding["cve"] in kev_ids

    result["missing_updates"] = findings
    result["status"] = "MissingUpdates" if findings else "NoMissingUpdates"
    result["counts"] = {
        "total": len(findings),
        "known_exploited": sum(1 for f in findings if f["known_exploited"]),
        "critical_9_plus": sum(1 for f in findings
                               if (f.get("cvss_base_score") or 0) >= 9.0),
        "high_7_plus": sum(1 for f in findings
                           if 7.0 <= (f.get("cvss_base_score") or 0) < 9.0),
    }
    # If the oldest release evaluated still yields findings, older releases almost
    # certainly do too, and the window is hiding them.
    oldest = recent[0]["ID"] if recent else None
    truncated = any(f.get("msrc_release") == oldest for f in findings)
    if truncated:
        result["window_truncated"] = True
        result["limitations"].append(
            "WINDOW TOO NARROW. Outstanding updates were still being found in the "
            "oldest release evaluated (%s), so older releases will contain more. "
            "This count is a floor, not a total. Re-run with a larger --months "
            "value before reporting." % oldest)
    else:
        result["window_truncated"] = False

    result["limitations"].extend([
        "Only the %d most recent Microsoft releases were evaluated. A CVE fixed "
        "in an older release and still outstanding will not appear."
        % len(recent),
        "Microsoft operating-system updates only. Third-party software is not "
        "assessed by this module.",
        "Determination is by servicing level, not by confirming the presence of "
        "a vulnerable file on disk.",
        "No vulnerability was validated by execution. These are outstanding "
        "vendor fixes, not confirmed exploitable conditions.",
    ])

    _write(arguments.output, result)
    return 0 if not findings else 1


def _write(output_dir, result):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "MissingUpdates.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1)
    counts = result.get("counts", {})
    print("Status            : %s" % result["status"])
    if result.get("product_matched"):
        print("Product           : %s" % result["product_matched"]["name"])
    print("Observed build    : %s" % result.get("observed_build"))
    if counts:
        print("Missing updates   : %d  (critical %d, high %d, known-exploited %d)"
              % (counts["total"], counts["critical_9_plus"],
                 counts["high_7_plus"], counts["known_exploited"]))
    if result.get("window_truncated"):
        print("WARNING           : the evaluation window is too narrow. Updates were still")
        print("                    being found in the oldest release checked, so this count")
        print("                    is a floor, not a total. Re-run with a larger --months.")
    print("Written           : %s" % path)
    print("Analyst review is required before any of this reaches a report.")


if __name__ == "__main__":
    sys.exit(main())
