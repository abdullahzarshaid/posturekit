#!/usr/bin/env python3
"""Normalize a Greenbone / OpenVAS (GVM) report XML into evidence JSON (network vulnerability scan).

This tool does NOT run a scan. It reads a report the operator exported from their own
authorized Greenbone/GVM instance (free, unlimited, no licence) and normalizes each
result into an evidence observation, preserving the scanner's own name, host, port,
threat, CVSS and CVE references. Threat-bearing results are emitted as Candidates that
an analyst must confirm; informational rows are observations. The importer infers no
exploitation and adds no severity of its own.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

VERSION = '0.6'
MAX_XML = 100 * 1024 * 1024
THREATS = {'high', 'medium', 'low', 'log', 'false positive', 'alarm', 'debug', ''}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def _text(el, tag):
    c = el.find(tag)
    return (c.text or '').strip() if c is not None and c.text else ''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, required=True, help='GVM/OpenVAS report XML')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--engagement', required=True)
    ap.add_argument('--source-site', default='')
    ap.add_argument('--source-position', required=True, help='Where the scan ran from, e.g. "Internal sensor, user LAN"')
    args = ap.parse_args()
    try:
        if args.output.exists():
            raise ValueError('Choose a new output file.')
        if not args.input.is_file() or args.input.is_symlink():
            raise ValueError('Input must be a regular XML file.')
        if args.input.stat().st_size > MAX_XML:
            raise ValueError('Report XML exceeds the 100 MiB lab limit.')
        root = ET.parse(args.input).getroot()
        # results can sit at report/results/result or anywhere under the document
        results = root.findall('.//results/result') or root.findall('.//result')
        if len(results) > 200000:
            raise ValueError('Unreasonable result count.')
        obs = []
        for r in results:
            host = _text(r, 'host')
            # host element may carry an <asset> child; strip it by taking the leading text only
            if not host:
                he = r.find('host')
                host = (he.text or '').strip() if he is not None and he.text else ''
            port = _text(r, 'port')
            name = _text(r, 'name')
            threat = _text(r, 'threat')
            severity = _text(r, 'severity')
            nvt = r.find('nvt')
            oid = nvt.get('oid') if nvt is not None else ''
            cvss = _text(nvt, 'cvss_base') if nvt is not None else ''
            cves = []
            if nvt is not None:
                for ref in nvt.findall('.//ref'):
                    if (ref.get('type') or '').lower() == 'cve' and ref.get('id'):
                        cves.append(ref.get('id'))
                for cve in nvt.findall('.//cve'):
                    if cve.text:
                        cves += [c.strip() for c in cve.text.split(',') if c.strip()]
            tl = threat.lower()
            if tl not in THREATS:
                tl = ''
            obs.append({
                'host': host, 'port': port, 'name': name, 'threat': threat,
                'severity_cvss': severity or cvss, 'nvt_oid': oid,
                'cves': sorted(set(cves)),
                'actionable': tl in ('high', 'medium', 'low', 'alarm'),
            })
        doc = {
            'schema_version': '1.0', 'tool_version': VERSION, 'evidence_kind': 'GreenboneObservations',
            'engagement_id': args.engagement, 'source_site_id': args.source_site,
            'source_position': args.source_position, 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'input_file': args.input.name, 'input_sha256': sha256(args.input),
            'result_count': len(obs), 'observations': obs,
            'limitations': [
                'Network vulnerability scanner output from one scanning position; an open detection is not a confirmed exploited vulnerability.',
                'Greenbone/GVM feed currency and scan configuration determine coverage; false positives and false negatives are possible.',
                'No exploitation was performed and the scanner severity is not adopted as assessor-assigned severity.',
            ],
        }
        args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding='utf-8')
        by = {}
        for o in obs:
            by[o['threat'] or 'None'] = by.get(o['threat'] or 'None', 0) + 1
        print(f'Wrote {args.output} : {len(obs)} results {by}')
        return 0
    except (ValueError, OSError, ET.ParseError) as exc:
        print(f'Import failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
