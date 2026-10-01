#!/usr/bin/env python3
"""Normalize a wireless-controller configuration intake into evidence JSON (Wireless Layer C).

This tool does NOT connect to any controller. The operator fills a vendor-neutral
intake (Templates\WirelessControllerIntake.example.json) from the client's own
controller export or console (Cisco WLC/9800, Aruba, Meraki, UniFi, Ruckus, etc.).
This importer validates it and stamps it into the evidence schema. The analyzer
then evaluates guest isolation, VLAN separation, corporate authentication, open
SSIDs, PMF and rogue/WIPS detection.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = '0.6'
SEC = {'open', 'wep', 'wpa-psk', 'wpa2-psk', 'wpa3-psk', 'wpa2-enterprise', 'wpa3-enterprise', 'wpa2/wpa3-mixed'}
PMF = {'disabled', 'optional', 'required'}
# A control whose state the export does not show is recorded as unknown, never as
# disabled. "not_supported" records that the platform has no such control.
UNKNOWN = {'unknown', 'not_supported'}
PURPOSE = {'corporate', 'guest', 'iot', 'voice', 'byod', 'other'}


def tri_state(value, field):
    """true/false pass through; null or an absent field -> 'unknown';
    'unknown' / 'not_supported' are accepted as text. Anything else is an error."""
    if isinstance(value, bool):
        return value
    if value is None:
        return 'unknown'
    text = str(value).strip().lower()
    if text in UNKNOWN:
        return text
    raise ValueError(f'{field} must be true, false, null, "unknown" or "not_supported".')


def field_notes(container, fields):
    """Operator notes per field (dict field_notes in the intake), passed through as
    text for the listed fields only."""
    notes = container.get('field_notes') if isinstance(container, dict) else None
    if not isinstance(notes, dict):
        return {}
    out = {}
    for field in fields:
        note = notes.get(field)
        if isinstance(note, str) and note.strip():
            out[field] = note.strip()
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, required=True, help='Filled WirelessControllerIntake JSON')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--engagement', required=True)
    args = ap.parse_args()
    try:
        if args.output.exists():
            raise ValueError('Choose a new output file.')
        if not args.input.is_file() or args.input.is_symlink():
            raise ValueError('Input must be a regular JSON file.')
        doc = json.loads(args.input.read_text(encoding='utf-8-sig'))
        if doc.get('engagement_id') != args.engagement:
            raise ValueError('Intake engagement_id does not match --engagement.')
        controller = doc.get('controller') or {}
        if not isinstance(controller, dict):
            raise ValueError('controller must be an object.')
        controller_out = {k: tri_state(controller.get(k), f'controller.{k}')
                          for k in ('rogue_detection_enabled', 'wips_enabled')}
        controller_notes = field_notes(controller, ('rogue_detection_enabled', 'wips_enabled'))
        if controller_notes:
            controller_out['field_notes'] = controller_notes
        unknown_fields = []
        for k in ('rogue_detection_enabled', 'wips_enabled'):
            if not isinstance(controller_out[k], bool):
                unknown_fields.append(f'controller.{k}={controller_out[k]}')
        wlans = doc.get('wlans')
        if not isinstance(wlans, list) or not wlans or len(wlans) > 500:
            raise ValueError('wlans must be a non-empty list (<=500).')
        corp_vlans = set()
        norm = []
        for w in wlans:
            if not isinstance(w, dict):
                raise ValueError('Each WLAN must be an object.')
            ssid = str(w.get('ssid') or '').strip()
            purpose = str(w.get('purpose') or '').strip().lower()
            security = str(w.get('security') or '').strip().lower()
            pmf = 'unknown' if w.get('pmf') is None else str(w.get('pmf')).strip().lower()
            if not ssid or purpose not in PURPOSE or security not in SEC or pmf not in (PMF | UNKNOWN):
                raise ValueError(f'Invalid WLAN record for ssid={ssid!r} (check purpose/security/pmf values).')
            vlan = w.get('vlan')
            if vlan is not None and not isinstance(vlan, int):
                raise ValueError(f'vlan must be an integer or null for {ssid}.')
            iso = tri_state(w.get('client_isolation'), f'client_isolation for {ssid}')
            rec = {'ssid': ssid, 'purpose': purpose, 'security': security, 'pmf': pmf,
                   'vlan': vlan, 'client_isolation': iso, 'band': str(w.get('band') or '').strip()}
            notes = field_notes(w, ('client_isolation', 'pmf', 'security', 'vlan'))
            if notes:
                rec['field_notes'] = notes
            if pmf in UNKNOWN:
                unknown_fields.append(f'{ssid}.pmf={pmf}')
            if not isinstance(iso, bool):
                unknown_fields.append(f'{ssid}.client_isolation={iso}')
            norm.append(rec)
            if purpose == 'corporate' and isinstance(vlan, int):
                corp_vlans.add(vlan)
        out = {
            'schema_version': '1.0', 'tool_version': VERSION, 'evidence_kind': 'WirelessControllerConfig',
            'engagement_id': args.engagement, 'site_id': str(doc.get('site_id') or ''),
            'source_position': str(doc.get('source_position') or 'Client wireless controller configuration export'),
            'controller_vendor': str(doc.get('controller_vendor') or 'unspecified'),
            'normalized_utc': datetime.now(timezone.utc).isoformat(),
            'input_file': args.input.name, 'input_sha256': sha256(args.input),
            'controller': controller_out,
            'corporate_vlans': sorted(corp_vlans), 'corporate_vlans_known': bool(corp_vlans), 'wlans': norm,
            'limitations': ['Configuration review only; it does not prove runtime enforcement or that the export is current and complete.'],
        }
        if not corp_vlans:
            out['limitations'].append('No corporate WLAN carries an integer VLAN, so guest-to-corporate VLAN separation cannot be determined from this intake.')
        if unknown_fields:
            out['limitations'].append('Control state unknown or not supported for: %s. These are recorded as Unknown, not as failures; confirm them on the controller.' % ', '.join(unknown_fields))
        args.output.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f'Wrote {args.output} : {len(norm)} WLANs, corporate VLANs {sorted(corp_vlans)} (known={bool(corp_vlans)})')
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'Import failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
