#!/usr/bin/env python3
"""Determine missing Microsoft security updates for every collected host.

Method
------
The collector records the exact servicing level of the host as
``host.full_build`` (for example ``10.0.26200.9457``), read from
``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`` -> ``CurrentBuild`` +
``UBR``.  Microsoft publishes, per CVE and per product, the build in which the
fix shipped (``FixedBuild``).  A CVE is therefore outstanding on this host when
its ``FixedBuild`` for the matching product, on the host's own servicing branch
(same CurrentBuild), carries a higher UBR than the host's own.

Only the last two components (CurrentBuild, UBR) are compared.  The collector
always writes a ``10.0.`` prefix, while Microsoft publishes ``6.3.9600.x`` for
Server 2012 R2 and ``6.2.9200.x`` for Server 2012, so the leading components
never decide the outcome.  A FixedBuild on a different servicing branch (a
different CurrentBuild) says nothing about this host and is ignored.

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
has been populated on an internet-connected machine.  Each cached document
carries a ``.meta.json`` sidecar recording when it was fetched; documents older
than ``MAX_FEED_AGE_DAYS`` are re-fetched unless ``--offline`` is given.

Every Host.*.json in the batch is assessed, and only after its SHA-256 has been
checked against the ``evidence_sha256`` recorded for that asset in Batch.json.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

MSRC_INDEX = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_DOC = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{}"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
UA = "PostureKit/PatchCheck"
TIMEOUT = 90
MAX_FEED_AGE_DAYS = 35

_FETCH_ERRORS = (urllib.error.URLError, socket.timeout, ValueError, OSError)


class FeedUnavailable(Exception):
    """A vendor document could not be obtained (network, decode or offline gap)."""

    def __init__(self, name, reason):
        Exception.__init__(self, "%s: %s" % (name, reason))
        self.name = name
        self.reason = reason


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


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fetch(url):
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _now():
    return datetime.now(timezone.utc)


def _parse_utc(text):
    """ISO-8601 text -> aware datetime, or None when unparseable."""
    if not text:
        return None
    try:
        value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _meta_path(path):
    return path + ".meta.json"


def _read_fetched_utc(path):
    """Fetch time of a cached document from its sidecar; file mtime for a
    cache written before sidecars existed (the sidecar is then created)."""
    meta = _meta_path(path)
    if os.path.isfile(meta):
        try:
            value = _parse_utc(_read_json(meta).get("fetched_utc"))
        except (SystemExit, AttributeError):
            value = None
        if value is not None:
            return value
    value = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
    _write_meta(path, value)
    return value


def _write_meta(path, fetched):
    with open(_meta_path(path), "w", encoding="utf-8") as handle:
        json.dump({"fetched_utc": fetched.isoformat()}, handle)


def _age_days(fetched):
    return (_now() - fetched).total_seconds() / 86400.0


def _store(cache_dir, path, data):
    os.makedirs(cache_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    fetched = _now()
    _write_meta(path, fetched)
    return fetched


def _cached(cache_dir, name, url, offline, max_age_days=MAX_FEED_AGE_DAYS):
    """Return (data, origin, fetched_utc, stale) for a cached vendor document.

    origin is "cache" or "network".  stale is True only when the copy returned
    is older than max_age_days and could not be refreshed (offline, or the
    refresh itself failed).  Raises FeedUnavailable when nothing usable exists.
    """
    path = os.path.join(cache_dir, name)
    if os.path.isfile(path):
        fetched = _read_fetched_utc(path)
        fresh = max_age_days is None or _age_days(fetched) <= max_age_days
        if fresh or offline:
            return _read_json(path), "cache", fetched, not fresh
        try:
            data = _fetch(url)
        except _FETCH_ERRORS:
            # The stale copy is still vendor data; use it and say so.
            return _read_json(path), "cache", fetched, True
        fetched = _store(cache_dir, path, data)
        return data, "network", fetched, False
    if offline:
        raise FeedUnavailable(
            name, "offline mode and no cached copy; populate the cache on a "
                  "connected machine with --refresh first")
    try:
        data = _fetch(url)
    except _FETCH_ERRORS as exc:
        raise FeedUnavailable(name, "%s (%s)" % (exc.__class__.__name__, exc))
    fetched = _store(cache_dir, path, data)
    return data, "network", fetched, False


# ------------------------------------------------------------------- build math
def _build_tuple(text):
    """'10.0.26200.9457' -> (10, 0, 26200, 9457); None when unparseable."""
    if not text:
        return None
    parts = str(text).strip().split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _servicing(build):
    """(CurrentBuild, UBR) of a build tuple: the last two components.

    The collector always prefixes 10.0, while Microsoft publishes 6.3.9600.x
    for Server 2012 R2 and 6.2.9200.x for Server 2012, so only the servicing
    components may be compared.  None when the tuple is too short.
    """
    if not build or len(build) < 2:
        return None
    return (build[-2], build[-1])


def _same_branch(fixed, host_build):
    """True when a FixedBuild sits on the host's servicing branch."""
    f = _servicing(fixed)
    h = _servicing(host_build)
    return bool(f and h and f[0] == h[0])


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

# Spellings the collector (and hand-edited evidence) have been seen to carry.
# Compared after lower-casing and removing spaces, hyphens and underscores.
_ARCH_ALIASES = {
    "x64": ("64bit", "64bits", "x64", "amd64", "x8664", "64"),
    "32-bit": ("32bit", "32bits", "x86", "i386", "i686", "32"),
    "ARM64": ("arm64", "aarch64", "arm64bit"),
}


def normalise_arch(architecture):
    """Map any recognised spelling of the architecture to Microsoft's product
    wording ("x64", "32-bit", "ARM64").  Unrecognised text is returned as-is
    so it can still be reported."""
    if not architecture:
        return ""
    text = str(architecture).strip()
    if text in _ARCH:
        return _ARCH[text]
    key = re.sub(r"[\s_\-]+", "", text.lower())
    for canonical, aliases in _ARCH_ALIASES.items():
        if key in aliases:
            return canonical
    return text


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
    arch = normalise_arch(architecture)
    release = (display_version or "").strip().lower()
    core = "core" in (installation_type or "").lower()

    candidates = []

    if "windows server" in caption:
        # Server: the year identifies the product. Architecture does not appear
        # in Microsoft's Windows Server product names.
        year = re.search(r"windows server\s+(\d{4})", caption)
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
            # Edition qualifiers ("23H2 Edition", "Datacenter: Azure Edition",
            # "R2") must be confirmed by the host's own evidence: either the
            # caption carries the qualifier, or the product names the host's
            # display_version. A qualifier the host does not confirm rules the
            # product out; it is never a fallback. Without this a 20348 host
            # was scored against the 25398 "23H2 Edition" product (and the
            # reverse) whenever that was the only candidate in a document.
            residue = lowered.replace("windows server " + year.group(1), "", 1)
            residue = residue.replace(want_core, "").strip(" ,")
            if not residue:
                score = 100
            elif release and release in residue:
                score = 110          # names the host's release: preferred
            elif residue in caption:
                score = 105          # confirmed by the caption ("R2")
            else:
                continue
            candidates.append((score, product_id, name))

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
            if not lowered.startswith(family + " version " + release):
                continue
            if arch and arch.lower() not in lowered:
                continue
            candidates.append((10, product_id, name))

    else:
        return []

    candidates.sort(reverse=True)
    return [(product_id, name) for _score, product_id, name in candidates]


_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _release_date(release):
    """Sort key for MSRC release IDs such as 2026-Sep; unparseable IDs sort first."""
    match = re.match(r"(\d{4})-([A-Za-z]{3})", str(release.get("ID", "")))
    if not match:
        return (0, 0)
    return (int(match.group(1)), _MONTHS.get(match.group(2).title(), 0))


def score_set_for(vulnerability, product_id):
    """(base_score, vector, source) for the matched product.

    Microsoft scores each product separately; the first set in the list is
    frequently another product's. The set whose ProductID list names the
    matched product is used ("product"). The first set is used only when no
    set names any product at all ("first_set"). When the sets do name
    products but none is ours, no score is reported ("none").
    """
    sets = vulnerability.get("CVSSScoreSets") or []
    for entry in sets:
        if product_id in (entry.get("ProductID") or []):
            return entry.get("BaseScore"), entry.get("Vector"), "product"
    if sets and not any(entry.get("ProductID") for entry in sets):
        return sets[0].get("BaseScore"), sets[0].get("Vector"), "first_set"
    return None, None, "none"


def branch_remediations(document, product_id, host_build):
    """(same_branch, other_branch) counts of FixedBuilds for the product."""
    same = other = 0
    for vulnerability in document.get("Vulnerability", []):
        for remediation in vulnerability.get("Remediations", []):
            if product_id not in (remediation.get("ProductID") or []):
                continue
            fixed = _build_tuple(remediation.get("FixedBuild"))
            if not fixed or _servicing(fixed) is None:
                continue
            if _same_branch(fixed, host_build):
                same += 1
            else:
                other += 1
    return same, other


def missing_for_host(document, product_id, host_build):
    """CVEs whose fix, on the host's servicing branch, is newer than the host.

    Compared on (CurrentBuild, UBR) only. A FixedBuild on another servicing
    branch is ignored: it says nothing about this host.
    """
    findings = []
    host_key = _servicing(host_build)
    if host_key is None:
        return findings
    for vulnerability in document.get("Vulnerability", []):
        cve = vulnerability.get("CVE")
        title = (vulnerability.get("Title") or {}).get("Value")
        base, vector, source = score_set_for(vulnerability, product_id)
        for remediation in vulnerability.get("Remediations", []):
            if product_id not in (remediation.get("ProductID") or []):
                continue
            fixed = _build_tuple(remediation.get("FixedBuild"))
            if not fixed or not _same_branch(fixed, host_build):
                continue
            if _servicing(fixed) <= host_key:
                continue
            findings.append({
                "cve": cve,
                "title": title,
                "kb": (remediation.get("Description") or {}).get("Value"),
                "fixed_build": remediation.get("FixedBuild"),
                "observed_build": ".".join(str(n) for n in host_build),
                "cvss_base_score": base,
                "cvss_vector": vector,
                "cvss_source": source,
                "restart_required": remediation.get("RestartRequired"),
                "url": remediation.get("URL"),
            })
            break  # one remediation per CVE per product is enough
    return findings


# ------------------------------------------------------------- per-host logic
def _installation_type(host_document):
    # Server Core is a separate Microsoft product with its own fixed builds, so
    # the installation type has to be part of the match.
    for source in host_document.get("sources", []):
        if source.get("id") == "patchlevel" and source.get("data"):
            return (source["data"][0] or {}).get("InstallationType")
    return None


def _host_shell(host_document, batch_name):
    host = host_document.get("host", {}) or {}
    return {
        "asset_id": host_document.get("asset_id"),
        "computer_name": host.get("computer_name"),
        "os_caption": host.get("os_caption"),
        "display_version": host.get("display_version"),
        "architecture": host.get("architecture"),
        "installation_type": _installation_type(host_document),
        "observed_build": host.get("full_build"),
        "full_build": host.get("full_build"),
        "source_batch": batch_name,
        "status": None,
        "product_matched": None,
        "documents_evaluated": [],
        "missing_updates": [],
        "limitations": [],
    }


def assess_host(host_document, documents, kev_ids, kev_available, batch_name,
                feed_limitations=()):
    """Assess one verified host record against the evaluated documents.

    documents is [(release_id, document_json)] oldest first. kev_ids is the
    set of known-exploited CVE ids, or None when the catalogue was unavailable.
    Returns the per-host result dict.
    """
    host = host_document.get("host", {}) or {}
    result = _host_shell(host_document, batch_name)
    installation_type = result["installation_type"]
    build = _build_tuple(result["full_build"])
    result["limitations"].extend(feed_limitations)

    if _servicing(build) is None:
        result["status"] = "Unknown"
        result["limitations"].append(
            "The host record carries no parseable full_build, so patch state "
            "cannot be determined. Re-collect with a collector that records "
            "CurrentBuild and UBR.")
        return result

    product_id = None
    product_name = None
    seen = {}
    same_branch_total = 0
    other_branch_total = 0

    for release_id, document in documents:
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

        same, other = branch_remediations(document, product_id, build)
        same_branch_total += same
        other_branch_total += other
        result["documents_evaluated"].append(
            {"release": release_id, "matched": True,
             "same_branch_fixes": same, "other_branch_fixes": other})
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
            "reporting no readable release version, or a server product that could "
            "not be identified unambiguously, lands here by design, because "
            "guessing the product would produce confident findings for software "
            "the host may not run."
            % (host.get("os_caption"), host.get("display_version") or "not recorded",
               host.get("architecture"), installation_type or "not recorded"))
        return result

    result["product_matched"] = {"product_id": product_id, "name": product_name}

    if same_branch_total == 0:
        # Every published fix for the matched product sits on another servicing
        # branch. Nothing was compared, so nothing can be concluded.
        result["status"] = "Unknown"
        result["limitations"].append(
            "The matched product (%s) publishes fixed builds only on a different "
            "servicing branch from this host (CurrentBuild %d; %d fixed build(s) "
            "seen on other branches, none on this one), so no determination was "
            "made. This is NOT evidence that the host is patched. Confirm the "
            "product identification and the host's recorded build."
            % (product_name, build[-2], other_branch_total))
        return result

    findings = sorted(seen.values(),
                      key=lambda item: -(item.get("cvss_base_score") or 0))
    for finding in findings:
        finding["known_exploited"] = (
            finding["cve"] in kev_ids if kev_available else None)

    result["missing_updates"] = findings
    result["status"] = "MissingUpdates" if findings else "NoMissingUpdates"
    result["counts"] = {
        "total": len(findings),
        "known_exploited": sum(1 for f in findings if f["known_exploited"] is True),
        "critical_9_plus": sum(1 for f in findings
                               if (f.get("cvss_base_score") or 0) >= 9.0),
        "high_7_plus": sum(1 for f in findings
                           if 7.0 <= (f.get("cvss_base_score") or 0) < 9.0),
    }
    # If the oldest release evaluated still yields findings, older releases almost
    # certainly do too, and the window is hiding them.
    oldest = documents[0][0] if documents else None
    truncated = any(f.get("msrc_release") == oldest for f in findings)
    result["window_truncated"] = truncated
    if truncated:
        result["limitations"].append(
            "WINDOW TOO NARROW. Outstanding updates were still being found in the "
            "oldest release evaluated (%s), so older releases will contain more. "
            "This count is a floor, not a total. Re-run with a larger --months "
            "value before reporting." % oldest)
    if not kev_available:
        result["limitations"].append(
            "The CISA Known Exploited Vulnerabilities catalogue was not available, "
            "so known_exploited is null on every row and no exploitation-in-the-wild "
            "overlay was applied.")

    result["limitations"].extend([
        "Only the %d most recent Microsoft releases were evaluated. A CVE fixed "
        "in an older release and still outstanding will not appear."
        % len(documents),
        "Microsoft operating-system updates only. Third-party software is not "
        "assessed by this module.",
        "Determination is by servicing level, not by confirming the presence of "
        "a vulnerable file on disk.",
        "No vulnerability was validated by execution. These are outstanding "
        "vendor fixes, not confirmed exploitable conditions.",
    ])
    return result


# ------------------------------------------------------------ integrity gate
def verify_hosts(batch):
    """Check every Host.*.json against the Batch.json ledger.

    Returns [(file_name, host_document_or_None, rejection_reason_or_None)] in
    file-name order. A host whose SHA-256 does not equal the evidence_sha256
    recorded for its asset, or that has no ledger entry at all, is rejected
    and must never produce a patch result.
    """
    host_files = sorted(name for name in os.listdir(batch)
                        if name.startswith("Host.") and name.lower().endswith(".json"))
    ledger_path = os.path.join(batch, "Batch.json")
    ledger = None
    ledger_error = None
    if not os.path.isfile(ledger_path):
        ledger_error = "Batch.json is absent from the batch, so no evidence file can be verified"
    else:
        try:
            ledger = _read_json(ledger_path)
        except SystemExit as exc:
            ledger_error = "Batch.json could not be read (%s)" % exc
    by_asset = {}
    by_file = {}
    if ledger is not None:
        for entry in ledger.get("targets", []) or []:
            if entry.get("asset_id") is not None:
                by_asset[str(entry["asset_id"])] = entry
            if entry.get("evidence_file"):
                by_file[str(entry["evidence_file"])] = entry

    verified = []
    for name in host_files:
        path = os.path.join(batch, name)
        try:
            document = _read_json(path)
            digest = _sha256(path)
        except (SystemExit, OSError) as exc:
            verified.append((name, None, "%s could not be read (%s)" % (name, exc)))
            continue
        if ledger_error:
            verified.append((name, document, ledger_error))
            continue
        asset_id = document.get("asset_id")
        entry = by_asset.get(str(asset_id)) if asset_id is not None else None
        if entry is None:
            entry = by_file.get(name)
        if entry is None:
            verified.append((name, document,
                             "no ledger entry in Batch.json for asset %s (%s)"
                             % (asset_id, name)))
            continue
        recorded = str(entry.get("evidence_sha256") or "").lower()
        if recorded != digest:
            verified.append((name, document,
                             "evidence digest mismatch: SHA-256 of %s does not equal "
                             "the evidence_sha256 recorded for asset %s in Batch.json"
                             % (name, asset_id)))
            continue
        verified.append((name, document, None))
    return verified


def _rejected(document, name, reason, batch_name):
    result = _host_shell(document or {}, batch_name)
    result["evidence_file"] = name
    result["status"] = "EvidenceRejected"
    result["rejection_reason"] = reason
    result["limitations"].append(
        "Evidence rejected: %s. No patch determination was made for this host "
        "and it must not be presented as assessed." % reason)
    return result


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
    batch_name = os.path.basename(os.path.abspath(batch))
    verified = verify_hosts(batch)
    if not verified:
        raise SystemExit("No Host.*.json in %s. Nothing was collected from this "
                         "target, so no patch determination is possible." % batch)

    cache_dir = arguments.cache or os.path.join(arguments.output, "cache")
    os.makedirs(arguments.output, exist_ok=True)
    if arguments.refresh and os.path.isdir(cache_dir):
        for name in os.listdir(cache_dir):
            os.remove(os.path.join(cache_dir, name))

    result = {
        "schema_version": "1.0",
        "evidence_kind": "MissingUpdateAssessment",
        "generated_utc": _now().isoformat(),
        "source_batch": batch_name,
        "method": ("Servicing level recorded by the collector compared against "
                   "Microsoft CVRF FixedBuild per product on the host's own "
                   "servicing branch. No host execution, no exploitation, no "
                   "vulnerability validation."),
        "status": None,
        "kev_available": False,
        "feed_fetched_utc": None,
        "feed_age_days": None,
        "hosts": [],
    }

    accepted = [(name, document) for name, document, reason in verified if reason is None]

    documents = []
    kev_ids = None
    kev_available = False
    feed_limitations = []
    fetched_times = []
    stale_names = []
    feed_failure = None

    if accepted:
        try:
            index, _origin, fetched, stale = _cached(
                cache_dir, "msrc_index.json", MSRC_INDEX, arguments.offline)
            fetched_times.append(fetched)
            if stale:
                stale_names.append(("msrc_index.json", fetched))
            releases = index.get("value", index)
            # The MSRC index is not chronological (it sorts alphabetically, Apr
            # before Jan), so slice the window only after sorting by year and month.
            releases = sorted(releases, key=_release_date)
            recent = releases[-arguments.months:] if arguments.months else releases
            for release in recent:
                release_id = release["ID"]
                name = "msrc_%s.json" % release_id
                document, _origin, fetched, stale = _cached(
                    cache_dir, name, MSRC_DOC.format(release_id), arguments.offline)
                fetched_times.append(fetched)
                if stale:
                    stale_names.append((name, fetched))
                documents.append((release_id, document))
        except FeedUnavailable as exc:
            feed_failure = exc
        except (KeyError, TypeError, AttributeError) as exc:
            feed_failure = FeedUnavailable(
                "msrc", "unexpected document structure (%s: %s)"
                        % (exc.__class__.__name__, exc))

        if feed_failure is None:
            # CISA Known Exploited Vulnerabilities overlay - prioritisation only.
            try:
                kev, _origin, fetched, stale = _cached(
                    cache_dir, "cisa_kev.json", KEV_URL, arguments.offline)
                kev_ids = {entry["cveID"] for entry in kev.get("vulnerabilities", [])}
                kev_available = True
                fetched_times.append(fetched)
                if stale:
                    stale_names.append(("cisa_kev.json", fetched))
            except (FeedUnavailable, KeyError, TypeError, AttributeError) as exc:
                print("CISA KEV unavailable: %s" % exc)
                kev_ids = None
                kev_available = False

        for name, fetched in stale_names:
            feed_limitations.append(
                "Vendor document %s is %d days old (fetched %s) and was not "
                "refreshed%s. Findings reflect that snapshot."
                % (name, int(_age_days(fetched)), fetched.isoformat(),
                   " because --offline was given" if arguments.offline
                   else " because the refresh failed"))

    result["kev_available"] = kev_available
    if fetched_times:
        oldest = min(fetched_times)
        result["feed_fetched_utc"] = oldest.isoformat()
        result["feed_age_days"] = int(_age_days(oldest))

    if feed_failure is not None:
        reason = ("Vendor document %s could not be fetched: %s"
                  % (feed_failure.name, feed_failure.reason))
        print("Vendor data unavailable: %s" % reason)
        for name, document, rejection in verified:
            if rejection is not None:
                result["hosts"].append(_rejected(document, name, rejection, batch_name))
                continue
            host = _host_shell(document, batch_name)
            host["status"] = "Unknown"
            host["limitations"].append(
                reason + ". No patch determination was made. This is NOT "
                         "evidence that the host is patched.")
            result["hosts"].append(host)
        _finish(result, arguments.output)
        return 2

    for name, document, rejection in verified:
        if rejection is not None:
            result["hosts"].append(_rejected(document, name, rejection, batch_name))
            continue
        result["hosts"].append(assess_host(
            document, documents, kev_ids, kev_available, batch_name,
            feed_limitations))

    _finish(result, arguments.output)
    statuses = [h["status"] for h in result["hosts"]]
    if "MissingUpdates" in statuses:
        return 1
    if any(s in ("Unknown", "EvidenceRejected") for s in statuses):
        return 2
    return 0


def _finish(result, output_dir):
    """Mirror the first host at the top level (backward compatibility), then write."""
    first = result["hosts"][0] if result["hosts"] else None
    if first is not None:
        for key, value in first.items():
            if key not in result:
                result[key] = value
        result["status"] = first["status"]
    else:
        result["status"] = "Unknown"
    _write(output_dir, result)


def _write(output_dir, result):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "MissingUpdates.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1)
    hosts = result.get("hosts") or [result]
    for host in hosts:
        counts = host.get("counts", {})
        label = host.get("computer_name") or host.get("asset_id") or "host"
        print("Host              : %s" % label)
        print("Status            : %s" % host["status"])
        if host.get("rejection_reason"):
            print("Reason            : %s" % host["rejection_reason"])
        if host.get("product_matched"):
            print("Product           : %s" % host["product_matched"]["name"])
        print("Observed build    : %s" % host.get("observed_build"))
        if counts:
            kev = ("known-exploited %d" % counts["known_exploited"]
                   if result.get("kev_available") else "known-exploited n/a")
            print("Missing updates   : %d  (critical %d, high %d, %s)"
                  % (counts["total"], counts["critical_9_plus"],
                     counts["high_7_plus"], kev))
        if host.get("window_truncated"):
            print("WARNING           : the evaluation window is too narrow. Updates were still")
            print("                    being found in the oldest release checked, so this count")
            print("                    is a floor, not a total. Re-run with a larger --months.")
        print("")
    if result.get("feed_fetched_utc"):
        print("Vendor data age   : %s days (oldest document fetched %s)"
              % (result.get("feed_age_days"), result["feed_fetched_utc"]))
    print("Written           : %s" % path)
    print("Analyst review is required before any of this reaches a report.")


if __name__ == "__main__":
    sys.exit(main())
