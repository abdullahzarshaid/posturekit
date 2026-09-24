#!/usr/bin/env python3
"""Normalize the agentless CIM feasibility output into report-ready evidence.

This importer does not contact endpoints. CimSurvey.ps1 remains a reduced feasibility
survey; the imported records are observations/errors, not replacements for the full
Windows collector or proof of vulnerability.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

VERSION='0.6'; MAX_BYTES=30*1024*1024

def sha256(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=Path,required=True); ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--engagement',required=True); ap.add_argument('--asset-id',required=True); ap.add_argument('--site-id',required=True)
    ap.add_argument('--source-position',required=True,help='Management/vantage position from which the CIM session was initiated.')
    args=ap.parse_args()
    try:
        if args.output.exists(): raise ValueError('Choose a new output file.')
        if not args.input.is_file() or args.input.is_symlink(): raise ValueError('Input must be a regular JSON file.')
        if args.input.stat().st_size>MAX_BYTES: raise ValueError('CIM evidence exceeds the lab size limit.')
        doc=json.loads(args.input.read_text(encoding='utf-8-sig'))
        if doc.get('schema_version')!='1.0' or doc.get('tool_version')!=VERSION or doc.get('evidence_kind')!='AgentlessCimSubset':
            raise ValueError('Unsupported CIM survey document.')
        sources=doc.get('sources')
        if not isinstance(sources,list) or len(sources)>100: raise ValueError('Unexpected CIM source list.')
        observations=[]; seen=set()
        for i,src in enumerate(sources,1):
            if not isinstance(src,dict): raise ValueError('CIM source must be an object.')
            sid=str(src.get('id') or '')
            if not sid or sid in seen: raise ValueError('CIM source identifiers must be present and unique.')
            seen.add(sid)
            status=str(src.get('status') or '')
            if status not in ('Collected','Error','NotImplemented','Unsupported','NotApplicable'): raise ValueError(f'Unsupported CIM source status: {status}')
            data=src.get('data')
            if not isinstance(data,list): raise ValueError('CIM source data must be a list.')
            observations.append({'id':sid,'status':status,'data':data,'error':src.get('error'),'limitation':src.get('limitation')})
        out={'schema_version':'1.0','tool_version':VERSION,'evidence_kind':'CimObservations','engagement_id':args.engagement,
             'asset_id':args.asset_id,'site_id':args.site_id,'computer_name':doc.get('computer_name'),
             'source_position':args.source_position,'authentication':doc.get('authentication'),'use_ssl':doc.get('use_ssl'),
             'survey_timestamp_utc':doc.get('timestamp_utc'),'normalized_utc':datetime.now(timezone.utc).isoformat(),
             'input_file':args.input.name,'input_sha256':sha256(args.input),'observations':observations,
             'limitations':['Agentless CIM coverage is intentionally smaller than Collect.ps1.',
                            'Successful management-plane access does not prove network exposure from other security zones.',
                            'Observations require rule/applicability review before becoming findings.']}
        args.output.write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding='utf-8')
        print(f'Normalized {len(observations)} CIM source records to {args.output}')
        return 0
    except (OSError,ValueError,json.JSONDecodeError) as e:
        print(f'CIM import failed: {e}',file=sys.stderr); return 2
if __name__=='__main__': raise SystemExit(main())
