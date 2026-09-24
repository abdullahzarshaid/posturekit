#!/usr/bin/env python3
"""Normalize an operator-generated Nmap XML file into evidence JSON.

This tool does not run Nmap. It deliberately ignores NSE script output and only
normalizes host/port/service observations so downstream reporting can distinguish
network exposure from a confirmed vulnerability.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

VERSION='0.6'
MAX_XML=50*1024*1024


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--engagement', required=True)
    ap.add_argument('--source-id', required=True)
    ap.add_argument('--source-site', default='')
    ap.add_argument('--source-position', required=True)
    args=ap.parse_args()
    try:
        if args.output.exists(): raise ValueError('Choose a new output file.')
        if not args.input.is_file() or args.input.is_symlink(): raise ValueError('Input must be a regular XML file.')
        if args.input.stat().st_size>MAX_XML: raise ValueError('Nmap XML exceeds the 50 MiB lab limit.')
        root=ET.parse(args.input).getroot()
        if root.tag!='nmaprun': raise ValueError('Expected Nmap XML root element nmaprun.')
        observations=[]; ignored_scripts=0
        for host in root.findall('host'):
            status=host.find('status'); host_state=status.get('state') if status is not None else None
            addresses=[a.get('addr') for a in host.findall('address') if a.get('addr')]
            if not addresses: continue
            addr=addresses[0]
            names=[h.get('name') for h in host.findall('./hostnames/hostname') if h.get('name')]
            ports=host.findall('./ports/port')
            for port in ports:
                state=port.find('state'); svc=port.find('service')
                scripts=port.findall('script'); ignored_scripts+=len(scripts)
                observations.append({
                    'address':addr,'all_addresses':addresses,'hostnames':names,'host_state':host_state,
                    'protocol':port.get('protocol'),'port':int(port.get('portid')) if (port.get('portid') or '').isdigit() else port.get('portid'),
                    'state':state.get('state') if state is not None else None,
                    'reason':state.get('reason') if state is not None else None,
                    'service':None if svc is None else {
                        'name':svc.get('name'),'product':svc.get('product'),'version':svc.get('version'),
                        'extrainfo':svc.get('extrainfo'),'tunnel':svc.get('tunnel'),'method':svc.get('method'),'conf':svc.get('conf')},
                })
        finished=root.find('./runstats/finished')
        completed=(finished.get('timestr') if finished is not None else None)
        doc={
            'schema_version':'1.0','tool_version':VERSION,'evidence_kind':'NmapObservations',
            'engagement_id':args.engagement,'source_asset_id':args.source_id,'source_site_id':args.source_site,
            'source_position':args.source_position,'input_file':args.input.name,'input_sha256':sha256(args.input),
            'nmap_version':root.get('version'),'nmap_start_epoch':root.get('start'),'nmap_args':root.get('args'),
            'completed_label':completed,'normalized_utc':datetime.now(timezone.utc).isoformat(),
            'observations':observations,'limitations':[
                'NSE script output is intentionally not imported by this tool.',
                'Service/version identification is an observation, not proof of a vulnerability.',
                'Results depend on the scanner position, routes, target state and scan options.'
            ],'ignored_nse_script_results':ignored_scripts}
        args.output.write_text(json.dumps(doc,indent=2,ensure_ascii=False),encoding='utf-8')
        print(f'Normalized {len(observations)} port observations to {args.output}; ignored {ignored_scripts} NSE script results.')
        return 0
    except (ValueError,OSError,ET.ParseError) as exc:
        print(f'Nmap import failed: {exc}',file=sys.stderr); return 2

if __name__=='__main__': raise SystemExit(main())
