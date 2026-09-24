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
PURPOSE = {'corporate', 'guest', 'iot', 'voice', 'byod', 'other'}


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
        for k in ('rogue_detection_enabled', 'wips_enabled'):
            if not isinstance(controller.get(k), bool):
                raise ValueError(f'controller.{k} must be true/false.')
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
            pmf = str(w.get('pmf') or '').strip().lower()
            if not ssid or purpose not in PURPOSE or security not in SEC or pmf not in PMF:
                raise ValueError(f'Invalid WLAN record for ssid={ssid!r} (check purpose/security/pmf values).')
            vlan = w.get('vlan')
            if vlan is not None and not isinstance(vlan, int):
                raise ValueError(f'vlan must be an integer or null for {ssid}.')
            iso = w.get('client_isolation')
            if iso is not None and not isinstance(iso, bool):
                raise ValueError(f'client_isolation must be true/false/null for {ssid}.')
            rec = {'ssid': ssid, 'purpose': purpose, 'security': security, 'pmf': pmf,
                   'vlan': vlan, 'client_isolation': iso, 'band': str(w.get('band') or '').strip()}
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
            'controller': {'rogue_detection_enabled': bool(controller['rogue_detection_enabled']),
                           'wips_enabled': bool(controller['wips_enabled'])},
            'corporate_vlans': sorted(corp_vlans), 'wlans': norm,
            'limitations': ['Configuration review only; it does not prove runtime enforcement or that the export is current and complete.'],
        }
        args.output.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f'Wrote {args.output} : {len(norm)} WLANs, corporate VLANs {sorted(corp_vlans)}')
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f'Import failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
