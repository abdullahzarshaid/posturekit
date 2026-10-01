#!/usr/bin/env python3
"""Shared input and coverage contract for a sealed raw collection batch.

Every consumer of a raw batch (Analyze.py, PatchCheck.py, SoftwareCheck.py)
must agree on what the batch is before it reads a single host record:

  * Scope.json  - the approved scope: engagement, 1 to 20 targets, each with
                  an enabled flag. Nothing outside it is ever assessed.
  * Batch.json  - the collector's ledger: one entry per attempted target with
                  its status, evidence file and the SHA-256 recorded at seal.

verify_batch() performs the same validations Analyze.analyze_batch performs
(schema, approved_for_lab, scope digest, engagement, target count, ledger
identity) and then accounts for EVERY approved target, not only the ones that
produced a Host file. A target the collector never reached is reported as
NotAttempted with the ledger's own error, so no downstream module can present
silence as a clean result.

Python 3.10+ standard library only. Nothing is executed, nothing is fetched.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any

VERSION = "0.6"
MAX_BYTES = 30 * 1024 * 1024
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
TARGET_STATUSES = {"Pending", "Excluded", "NotAttempted", "Error", "Complete", "Partial"}
EVIDENCE_STATUSES = ("Complete", "Partial")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise ValueError(f"Expected a regular evidence file: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"JSON exceeds {MAX_BYTES} bytes: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Non-finite JSON number: {value}")))
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object: {path.name}")
    return data


def safe_child(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", name):
        raise ValueError("Evidence must be a simple JSON filename, not a path or URL.")
    candidate = root / name
    if candidate.is_symlink() or candidate.resolve().parent != root.resolve():
        raise ValueError("Evidence path leaves the batch directory or is a symlink.")
    return candidate


def _validate_scope(scope: dict[str, Any]) -> dict[str, dict[str, Any]]:
    targets = scope.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 20:
        raise ValueError("This tool expects 1-20 scoped assets.")
    approved: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("Target is not an object.")
        for key in ("asset_id", "site_id", "computer_name"):
            if not isinstance(target.get(key), str) or not ID_RE.fullmatch(target[key]):
                raise ValueError(f"Invalid target {key}.")
        if type(target.get("enabled")) is not bool or target["asset_id"].casefold() in folded:
            raise ValueError("Invalid enabled flag or duplicate asset ID.")
        folded.add(target["asset_id"].casefold())
        approved[target["asset_id"]] = target
    return approved


def _validate_ledger(batch: dict[str, Any], approved: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    entries = batch.get("targets")
    if not isinstance(entries, list) or len(entries) > 20:
        raise ValueError("Invalid batch target list.")
    indexed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("asset_id") not in approved or entry["asset_id"] in indexed:
            raise ValueError("Unknown or duplicate target in batch ledger.")
        if entry.get("status") not in TARGET_STATUSES:
            raise ValueError("Unrecognized batch target status.")
        target = approved[entry["asset_id"]]
        if entry.get("site_id") != target["site_id"] or str(entry.get("computer_name", "")).casefold() != target["computer_name"].casefold():
            raise ValueError("Batch ledger identity mismatch.")
        indexed[entry["asset_id"]] = entry
    return indexed


def _host_entry(batch_dir: Path, target: dict[str, Any], entry: dict[str, Any] | None) -> dict[str, Any]:
    asset_id = target["asset_id"]
    host = {"asset_id": asset_id, "site_id": target["site_id"], "computer_name": target["computer_name"],
            "status": "NotAttempted", "evidence_file": None, "evidence_sha256": None,
            "digest_ok": None, "reason": None}
    if not target["enabled"]:
        host.update(status="Excluded", reason="Excluded by the approved scope.")
        return host
    if entry is None:
        host.update(reason="No ledger entry in Batch.json for asset %s; no collection was recorded." % asset_id)
        return host
    status = entry.get("status")
    if status not in EVIDENCE_STATUSES:
        host.update(status=status, reason=entry.get("error") or "No completed collection available.")
        return host
    host["evidence_file"] = entry.get("evidence_file")
    try:
        path = safe_child(batch_dir, entry.get("evidence_file"))
        if not path.is_file():
            raise ValueError("Evidence file %s recorded in Batch.json is absent from the batch." % path.name)
        digest = sha256(path)
    except (ValueError, OSError) as exc:
        host.update(status="EvidenceRejected", reason=str(exc))
        return host
    host["evidence_sha256"] = digest
    if digest != entry.get("evidence_sha256"):
        host.update(status="EvidenceRejected", digest_ok=False, reason="Evidence digest mismatch.")
        return host
    host.update(status=status, digest_ok=True)
    return host


def verify_batch(batch_dir) -> dict[str, Any]:
    """Validate Scope.json and Batch.json and account for every approved target.

    Returns {'engagement_id', 'scope_sha256', 'batch_id', 'targets', 'ledger',
    'hosts', 'batch', 'scope'}. hosts holds one entry per approved target with
    status Complete/Partial (digest_ok True), EvidenceRejected (digest_ok False
    or the file could not be read), NotAttempted/Error/Pending (the ledger's
    own status and error) or Excluded. Raises ValueError with a clear message
    when either file is missing or fails validation.
    """
    batch_dir = Path(batch_dir).resolve()
    if not batch_dir.is_dir():
        raise ValueError("Batch directory does not exist: %s" % batch_dir)
    batch_path = batch_dir / "Batch.json"
    scope_path = batch_dir / "Scope.json"
    if not batch_path.is_file():
        raise ValueError("Batch.json is absent from the batch directory %s, so no evidence file can be "
                         "verified. Only a sealed batch (Scope.json + Batch.json) is assessed." % batch_dir)
    if not scope_path.is_file():
        raise ValueError("Scope.json is absent from the batch directory %s, so the approved scope cannot be "
                         "established and no target can be accounted for." % batch_dir)
    batch = read_json(batch_path)
    scope = read_json(scope_path)
    if batch.get("schema_version") != "1.0" or batch.get("tool_version") != VERSION or batch.get("evidence_kind") != "CollectionBatch":
        raise ValueError("Unsupported batch schema or tool version.")
    if scope.get("schema_version") != "1.0" or scope.get("approved_for_lab") is not True:
        raise ValueError("Missing approved lab scope.")
    if batch.get("scope_sha256") != sha256(scope_path) or batch.get("engagement_id") != scope.get("engagement_id"):
        raise ValueError("Scope digest or engagement mismatch.")
    approved = _validate_scope(scope)
    ledger = _validate_ledger(batch, approved)
    hosts = [_host_entry(batch_dir, target, ledger.get(asset_id)) for asset_id, target in approved.items()]
    return {
        "engagement_id": batch["engagement_id"],
        "scope_sha256": batch["scope_sha256"],
        "batch_id": batch.get("batch_id"),
        "batch_dir": str(batch_dir),
        "targets": [dict(target) for target in approved.values()],
        "ledger": ledger,
        "hosts": hosts,
        "batch": batch,
        "scope": scope,
    }
