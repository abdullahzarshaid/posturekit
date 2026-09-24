#!/usr/bin/env python3
"""Normalize an operator-generated over-the-air Wi-Fi capture into evidence JSON (Wireless Layer B).

This tool does NOT transmit, capture or run any radio. It reads an airodump-ng CSV
(and an optional `wash` WPS listing) that the operator produced separately on an
authorized engagement with a monitor-mode adapter and physical presence, plus an
authorized-access-point allowlist, and classifies each observed access point:
authorized, rogue/evil-twin (a corporate ESSID from a radio not on the allowlist),
open, hidden, WPS-enabled, or external. It infers no exploitation.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = '0.6'
MAX_CSV = 25 * 1024 * 1024


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def parse_airodump(text: str) -> list[dict]:
    # airodump-ng CSV: an AP section, a blank line, then a station section. We use the AP section only.
    lines = text.splitlines()
    ap_rows, header = [], None
    for line in lines:
        s = line.strip()
        if s.startswith('BSSID') and 'ESSID' in s:
            header = [c.strip() for c in line.split(',')]
            continue
        if header is None:
            continue
        if s == '' or s.startswith('Station MAC'):
            break
        parts = [c.strip() for c in line.split(',')]
        if len(parts) < len(header):
            parts += [''] * (len(header) - len(parts))
        row = dict(zip(header, parts[:len(header)]))
        if row.get('BSSID'):
            ap_rows.append(row)
    return ap_rows


def parse_wash(text: str) -> set:
    # wash output lists WPS-enabled BSSIDs in the first whitespace column.
    wps = set()
    for line in text.splitlines():
        s = line.strip()
        parts = s.split()
        if len(parts) >= 1 and len(parts[0]) == 17 and parts[0].count(':') == 5:
            wps.add(parts[0].upper())
    return wps


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, required=True, help='airodump-ng CSV produced by the operator')
    ap.add_argument('--authorized', type=Path, required=True, help='JSON: {"corporate_essids":[...], "authorized_bssids":[...]}')
    ap.add_argument('--wash', type=Path, help='Optional wash WPS-scan text output')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--engagement', required=True)
    ap.add_argument('--source-site', default='')
    ap.add_argument('--source-position', required=True, help='Where/when the capture was taken, e.g. "3rd floor, client HQ, 2026-10-20"')
    args = ap.parse_args()
    try:
        if args.output.exists():
            raise ValueError('Choose a new output file.')
        for p in (args.input, args.authorized):
            if not p.is_file() or p.is_symlink():
                raise ValueError(f'Input must be a regular file: {p.name}')
        if args.input.stat().st_size > MAX_CSV:
            raise ValueError('Capture CSV exceeds the 25 MiB lab limit.')
        allow = json.loads(args.authorized.read_text(encoding='utf-8-sig'))
        corp = {str(e).strip() for e in allow.get('corporate_essids', []) if str(e).strip()}
        auth_bssids = {str(b).strip().upper() for b in allow.get('authorized_bssids', []) if str(b).strip()}
        wps = parse_wash(args.wash.read_text(encoding='utf-8-sig', errors='replace')) if args.wash and args.wash.is_file() else set()
        rows = parse_airodump(args.input.read_text(encoding='utf-8-sig', errors='replace'))
        if len(rows) > 50000:
            raise ValueError('Unreasonable access-point count.')
        obs = []
        for r in rows:
            bssid = (r.get('BSSID') or '').strip().upper()
            essid = (r.get('ESSID') or '').strip()
            privacy = (r.get('Privacy') or '').strip()
            hidden = (essid == '') or (r.get('ESSID', '') == '' )
            is_open = privacy.upper() in ('', 'OPN')
            is_corp = essid in corp and essid != ''
            wps_on = bssid in wps
            if is_corp and bssid not in auth_bssids:
                classification = 'RogueOrEvilTwin'
            elif is_corp:
                classification = 'AuthorizedAP'
            elif hidden:
                classification = 'Hidden'
            elif is_open:
                classification = 'Open'
            else:
                classification = 'External'
            obs.append({
                'bssid': bssid, 'essid': essid, 'channel': (r.get('channel') or '').strip(),
                'privacy': privacy, 'cipher': (r.get('Cipher') or '').strip(),
                'authentication': (r.get('Authentication') or '').strip(),
                'power': (r.get('Power') or '').strip(), 'hidden': bool(hidden),
                'open': bool(is_open), 'corporate_essid': bool(is_corp), 'wps_enabled': bool(wps_on),
                'classification': classification,
            })
        doc = {
            'schema_version': '1.0', 'tool_version': VERSION, 'evidence_kind': 'WirelessAirObservations',
            'engagement_id': args.engagement, 'source_site_id': args.source_site,
            'source_position': args.source_position, 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'input_file': args.input.name, 'input_sha256': sha256(args.input),
            'corporate_essids': sorted(corp), 'authorized_bssid_count': len(auth_bssids),
            'observations': obs,
            'limitations': [
                'Radio observation from one physical position and time window only; absence is not proof.',
                'Rogue/evil-twin classification depends entirely on the supplied authorized-access-point allowlist being complete and correct.',
                'No frames were transmitted or injected by this importer, and no key was cracked or captured.',
            ],
        }
        args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding='utf-8')
        counts = {}
        for o in obs:
            counts[o['classification']] = counts.get(o['classification'], 0) + 1
        print(f'Wrote {args.output} : {len(obs)} access points {counts}')
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'Import failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
