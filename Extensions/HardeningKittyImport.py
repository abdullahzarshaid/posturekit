#!/usr/bin/env python3
"""Normalize a HardeningKitty Audit-mode CSV into evidence, version 0.6.

HardeningKitty itself is not bundled. The operator obtains and runs an approved,
pinned copy in Audit mode and provides its CSV output to this importer.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
VERSION='0.6';MAX=50*1024*1024
REQ=['ID','Category','Name','Severity','Result','Recommended','TestResult','SeverityFinding']
def sha256(p:Path)->str:
    h=hashlib.sha256();
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def main()->int:
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--input',type=Path,required=True);a.add_argument('--output',type=Path,required=True)
    a.add_argument('--engagement',required=True);a.add_argument('--asset-id',required=True);a.add_argument('--site-id',required=True)
    a.add_argument('--profile',required=True,help='Finding-list/baseline identifier used during the audit.')
    a.add_argument('--hardeningkitty-version',default='unknown')
    args=a.parse_args()
    try:
        if args.output.exists():raise ValueError('Choose a new output file.')
        if not args.input.is_file() or args.input.is_symlink():raise ValueError('Input must be a regular CSV file.')
        if args.input.stat().st_size>MAX:raise ValueError('CSV exceeds 50 MiB lab limit.')
        rows=[]
        with args.input.open('r',encoding='utf-8-sig',newline='') as f:
            r=csv.DictReader(f)
            if r.fieldnames!=REQ:raise ValueError(f'Unexpected HardeningKitty CSV columns: {r.fieldnames!r}')
            seen=set()
            for i,row in enumerate(r,2):
                rid=(row['ID'] or '').strip()
                if not rid:raise ValueError(f'Line {i}: missing ID.')
                key=rid.casefold()
                if key in seen:raise ValueError(f'Line {i}: duplicate ID {rid}.')
                seen.add(key)
                tr=(row['TestResult'] or '').strip()
                if tr not in ('Passed','Failed'):raise ValueError(f'Line {i}: unsupported TestResult {tr!r}.')
                rows.append({'id':rid,'category':row['Category'],'name':row['Name'],'source_severity':row['SeverityFinding'] or row['Severity'],
                             'observed':row['Result'],'recommended':row['Recommended'],'test_result':tr})
        doc={'schema_version':'1.0','tool_version':VERSION,'evidence_kind':'HardeningKittyAudit','engagement_id':args.engagement,
             'asset_id':args.asset_id,'site_id':args.site_id,'profile':args.profile,'hardeningkitty_version':args.hardeningkitty_version,
             'input_file':args.input.name,'input_sha256':sha256(args.input),'normalized_utc':datetime.now(timezone.utc).isoformat(),
             'results':rows,'limitations':['Imported Audit-mode results are configuration/baseline observations, not proof of exploitability.',
             'assessor-assigned severity is not inherited from the source audit tool. Applicability and important failures require analyst validation.',
             'HardeningKitty is not bundled by ; version, finding-list provenance, system language and execution context must be recorded.']}
        args.output.write_text(json.dumps(doc,indent=2,ensure_ascii=False),encoding='utf-8')
        print(f'Normalized {len(rows)} HardeningKitty audit rows to {args.output}')
        return 0
    except (OSError,ValueError,csv.Error) as e:
        print(f'HardeningKitty import failed: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
