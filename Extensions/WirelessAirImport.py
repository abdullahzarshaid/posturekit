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
    # The csv module is used so an ESSID containing a comma (or a quoted field) does not shift
    # the columns; cells are stripped of surrounding whitespace after parsing.
    # Python 3.10's csv module rejects a line that contains NUL, and airodump writes a
    # hidden SSID as a run of NULs. Swap NUL for a private-use character while parsing
    # and restore it afterwards so is_hidden_essid() still sees the NULs.
    nul_marker = '\ue000'
    lines = text.replace('\x00', nul_marker).splitlines()
    ap_rows, header = [], None
    for parts in csv.reader(lines):
        parts = [c.replace(nul_marker, '\x00') for c in parts]
        # Blank lines are skipped rather than ending the section: the station section
        # always starts with its own "Station MAC" header, which is the real boundary,
        # and a file whose line endings were rewritten can carry stray blank lines.
        if not parts or all(c.strip() == '' for c in parts):
            continue
        first = parts[0].strip()
        if header is None:
            if first == 'BSSID' and any(c.strip() == 'ESSID' for c in parts):
                header = [c.strip() for c in parts]
            continue
        if first == 'Station MAC':
            break
        idx = header.index('ESSID') if 'ESSID' in header else len(header) - 1
        if len(parts) > len(header):
            # airodump does not quote the ESSID, so a name holding a comma spills into
            # extra cells. Rejoin the overflow (from the raw cells, so the original
            # spacing survives) into the ESSID column rather than shift or drop it.
            overflow = len(parts) - len(header)
            merged = ','.join(parts[idx:idx + overflow + 1])
            parts = parts[:idx] + [merged] + parts[idx + overflow + 1:]
        cells = [c.strip() for c in parts]
        if len(cells) < len(header):
            cells += [''] * (len(header) - len(cells))
        essid = cells[idx]
        if len(essid) >= 2 and essid[0] == '"' and essid[-1] == '"':
            # a tool that quoted the ESSID but left a space after the delimiter
            # defeats csv quoting; unwrap the quotes after the rejoin above.
            cells[idx] = essid[1:-1]
        row = dict(zip(header, cells[:len(header)]))
        if row.get('BSSID'):
            ap_rows.append(row)
    return ap_rows


def is_hidden_essid(raw: str) -> bool:
    """A hidden SSID is written by airodump as empty, as a run of NUL characters
    (one per byte of the hidden length) or with a leading NUL."""
    if raw is None:
        return True
    if raw == '' or raw.strip() == '':
        return True
    if raw.startswith('\x00'):
        return True
    return all(ch == '\x00' for ch in raw)


def normalise_essid(essid: str) -> str:
    """Lower-case and strip spaces, hyphens and underscores for look-alike comparison."""
    return ''.join(ch for ch in (essid or '').lower() if ch not in ' -_')


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
        if args.wash is not None:
            if not args.wash.is_file() or args.wash.is_symlink():
                raise ValueError(f'Wash input must be a regular file: {args.wash.name}')
            wps = parse_wash(args.wash.read_text(encoding='utf-8-sig', errors='replace'))
            wps_source = 'wash'
        else:
            # No wash listing: WPS state is unknown for every AP, never "disabled".
            wps = set()
            wps_source = None
        corp_norm = {normalise_essid(e): e for e in corp}
        rows = parse_airodump(args.input.read_text(encoding='utf-8-sig', errors='replace'))
        if len(rows) > 50000:
            raise ValueError('Unreasonable access-point count.')
        obs = []
        for r in rows:
            bssid = (r.get('BSSID') or '').strip().upper()
            raw_essid = r.get('ESSID') or ''
            hidden = is_hidden_essid(raw_essid)
            essid = '' if hidden else raw_essid.strip()
            privacy = (r.get('Privacy') or '').strip()
            is_open = privacy.upper() in ('', 'OPN')
            is_corp = essid in corp and essid != ''
            lookalike_of = ''
            if not is_corp and not hidden:
                match = corp_norm.get(normalise_essid(essid))
                if match is not None and match != essid:
                    lookalike_of = match
            wps_on = (bssid in wps) if wps_source == 'wash' else None
            if is_corp and bssid not in auth_bssids:
                classification = 'RogueOrEvilTwin'
            elif is_corp:
                classification = 'AuthorizedAP'
            elif lookalike_of:
                classification = 'LookalikeEssid'
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
                'open': bool(is_open), 'corporate_essid': bool(is_corp), 'lookalike_of': lookalike_of or None,
                'wps_enabled': wps_on,
                'classification': classification,
            })
        limitations = [
            'Radio observation from one physical position and time window only; absence is not proof.',
            'Rogue/evil-twin classification depends entirely on the supplied authorized-access-point allowlist being complete and correct.',
            'Look-alike classification compares ESSIDs after lowercasing and removing spaces, hyphens and underscores; it does not detect other visually similar names.',
            'No frames were transmitted or injected by this importer, and no key was cracked or captured.',
        ]
        if wps_source is None:
            limitations.append('No wash WPS listing was supplied, so WPS state is unknown (null) for every access point.')
        doc = {
            'schema_version': '1.0', 'tool_version': VERSION, 'evidence_kind': 'WirelessAirObservations',
            'engagement_id': args.engagement, 'source_site_id': args.source_site,
            'source_position': args.source_position, 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'input_file': args.input.name, 'input_sha256': sha256(args.input),
            'corporate_essids': sorted(corp), 'authorized_bssid_count': len(auth_bssids),
            'wps_source': wps_source,
            'observations': obs,
            'limitations': limitations,
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
