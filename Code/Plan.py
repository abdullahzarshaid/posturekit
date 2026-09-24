#!/usr/bin/env python3
"""Deployment-plan validator, version 0.6.

This tool does not contact endpoints or choose credentials. It validates an explicit
client-approved asset inventory and produces a machine-readable execution plan.
The purpose is to make large-estate deployment decisions visible before collection.
"""
from __future__ import annotations
import argparse, csv, json, ipaddress, re, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION='0.6'
METHODS={
    'ExistingManagement','WinRM','CIM','OfflineCollector','ExistingAgentData',
    'ManualException','NetworkOnly','Excluded','NotDetermined'
}
RETURN_METHODS={'RemoteSession','ManagementPlatform','EvidenceDrop','OfflineArchive','ExistingConsoleExport','ManualTransfer','NotApplicable','NotDetermined'}
BOOL={'true':True,'false':False,'1':True,'0':False,'yes':True,'no':False}
ID_RE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')
FIELDS=['asset_id','site','zone','hostname','fqdn','ip','os','role','domain','management_platform','execution_method','evidence_return','credential_profile','in_scope','criticality','owner','notes']

def clean(v:str)->str:return (v or '').strip()
def parse_bool(v:str)->bool:
    x=clean(v).casefold()
    if x not in BOOL: raise ValueError(f'Invalid in_scope boolean: {v!r}')
    return BOOL[x]
def validate_ip(v:str)->str:
    if not clean(v): return ''
    return str(ipaddress.ip_address(clean(v)))
def safe_csv(v:str)->str:
    t='' if v is None else str(v)
    return "'"+t if t.lstrip().startswith(('=','+','-','@')) or t.startswith(('\t','\r','\n')) else t

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--engagement',required=True)
    args=p.parse_args()
    try:
        if args.output.exists(): raise ValueError('Output directory already exists; use a new path.')
        if not args.inventory.is_file() or args.inventory.is_symlink(): raise ValueError('Inventory must be a regular CSV file.')
        rows=[]; seen=set(); unresolved=[]
        with args.inventory.open('r',encoding='utf-8-sig',newline='') as f:
            r=csv.DictReader(f)
            if r.fieldnames != FIELDS: raise ValueError('AssetInventory.csv columns do not match the required template exactly.')
            for n,row in enumerate(r,2):
                aid=clean(row['asset_id'])
                if not ID_RE.fullmatch(aid): raise ValueError(f'Line {n}: invalid asset_id.')
                if aid.casefold() in seen: raise ValueError(f'Line {n}: duplicate asset_id {aid}.')
                seen.add(aid.casefold())
                inscope=parse_bool(row['in_scope'])
                method=clean(row['execution_method']) or 'NotDetermined'
                ret=clean(row['evidence_return']) or 'NotDetermined'
                if method not in METHODS: raise ValueError(f'Line {n}: unsupported execution_method {method}.')
                if ret not in RETURN_METHODS: raise ValueError(f'Line {n}: unsupported evidence_return {ret}.')
                ip=validate_ip(row['ip'])
                if inscope and method=='Excluded': raise ValueError(f'Line {n}: in-scope asset cannot use Excluded method.')
                if not inscope and method not in ('Excluded','NotDetermined'): raise ValueError(f'Line {n}: out-of-scope asset must be Excluded or NotDetermined.')
                if inscope and method=='NotDetermined': unresolved.append(aid)
                if inscope and method not in ('NetworkOnly',) and ret=='NotDetermined': unresolved.append(aid)
                if not inscope and ret not in ('NotApplicable','NotDetermined'): raise ValueError(f'Line {n}: out-of-scope asset cannot define an evidence return channel.')
                if method=='NetworkOnly' and ret not in ('NotApplicable','NotDetermined'): raise ValueError(f'Line {n}: NetworkOnly asset should use NotApplicable evidence return; network evidence is handled by the scanner plane.')
                if method in ('WinRM','CIM') and not (clean(row['fqdn']) or clean(row['hostname'])):
                    unresolved.append(aid); row['notes']=clean(row['notes'])+' Missing hostname/FQDN required for remote planning.'
                if method=='ExistingManagement' and not clean(row['management_platform']):
                    unresolved.append(aid); row['notes']=clean(row['notes'])+' ExistingManagement selected but platform is not recorded.'
                rows.append({**{k:clean(row[k]) for k in FIELDS},'ip':ip,'execution_method':method,'evidence_return':ret,'in_scope':str(inscope).lower(),
                             'plan_status':'NeedsDecision' if aid in unresolved else ('Excluded' if not inscope else 'Planned')})
        args.output.mkdir(parents=True)
        with (args.output/'ExecutionPlan.csv').open('w',encoding='utf-8-sig',newline='') as f:
            fields=FIELDS+['plan_status'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader();
            for row in rows:w.writerow({k:safe_csv(row.get(k,'')) for k in fields})
        methods=Counter(r['execution_method'] for r in rows if r['in_scope']=='true')
        sites=Counter(r['site'] or '(unspecified)' for r in rows if r['in_scope']=='true')
        summary={'schema_version':'1.0','tool_version':VERSION,'evidence_kind':'ExecutionPlan','engagement_id':args.engagement,
                 'generated_utc':datetime.now(timezone.utc).isoformat(),'assets_total':len(rows),
                 'assets_in_scope':sum(r['in_scope']=='true' for r in rows),'methods':dict(methods),'sites':dict(sites),
                 'unresolved_assets':sorted(set(unresolved)),
                 'notice':'Planning output only. It does not authorize access, prove reachability, create credentials, or deploy software.'}
        (args.output/'ExecutionPlan.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(f"Planned {summary['assets_in_scope']} in-scope assets; unresolved: {len(summary['unresolved_assets'])}")
        return 3 if summary['unresolved_assets'] else 0
    except (OSError,ValueError,csv.Error) as e:
        print(f'Planning failed: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
