#!/usr/bin/env python3
"""Generate fictional evidence and run the real analyzer. No collection or network I/O."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('analyzer', ROOT / 'Code' / 'Analyze.py')
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New directory; refuses existing paths.')
    args = parser.parse_args()
    out = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='posturekit-synthetic-'))
    if args.output:
        out.mkdir(parents=True, exist_ok=False)
    batch_dir = out / 'batch'
    batch_dir.mkdir()
    targets = [{'asset_id': name, 'site_id': 'LAB', 'computer_name': name, 'enabled': True}
               for name in ('DEMO-PASS', 'DEMO-FAIL', 'DEMO-UNKNOWN')]
    scope = {'schema_version': '1.0', 'engagement_id': 'SYNTHETIC',
             'approved_for_lab': True, 'targets': targets}
    write_json(batch_dir / 'Scope.json', scope)
    scope_hash = digest(batch_dir / 'Scope.json')
    entries = []
    for target, observed in zip(targets, (True, False, None)):
        sources = []
        for source_id in sorted(analyzer.SOURCE_IDS):
            data = ([{'RequireSecuritySignature': observed}] if observed is not None else [{}]) if source_id == 'smbserver' else []
            sources.append({'id': source_id, 'status': 'Collected', 'data': data,
                            'note': 'SYNTHETIC: no real host was queried', 'error': None,
                            'returned_count': len(data), 'retained_count': len(data)})
        raw = {'schema_version': '1.0', 'tool_version': analyzer.VERSION,
               'evidence_kind': 'WindowsCollection', 'engagement_id': 'SYNTHETIC',
               'asset_id': target['asset_id'], 'site_id': 'LAB', 'scope_sha256': scope_hash,
               'collector_sha256': '0' * 64, 'collection_status': 'Complete',
               'started_utc': '2026-09-25T00:00:00Z', 'completed_utc': '2026-09-25T00:00:01Z',
               'host': {'computer_name': target['computer_name'], 'domain_role': 2, 'is_domain_controller': False},
               'sources': sources}
        name = 'Host.' + target['asset_id'] + '.json'
        write_json(batch_dir / name, raw)
        entries.append(dict(target, status='Complete', evidence_file=name, evidence_sha256=digest(batch_dir / name)))
    write_json(batch_dir / 'Batch.json', {
        'schema_version': '1.0', 'tool_version': analyzer.VERSION, 'evidence_kind': 'CollectionBatch',
        'batch_id': 'SYNTHETIC-DEMO', 'engagement_id': 'SYNTHETIC', 'scope_sha256': scope_hash,
        'collector_sha256': '0' * 64, 'completed_utc': '2026-09-25T00:00:02Z', 'targets': entries})
    write_json(out / 'demo-rules.json', {'schema_version': '1.0', 'profile_id': 'SYNTHETIC-SMB', 'rules': [{
        'id': 'DEMO-SMB', 'title': 'SMB signing required (synthetic policy)', 'source': 'smbserver',
        'field': 'RequireSecuritySignature', 'type': 'bool', 'expected': True}]})
    report = out / 'report'
    run = subprocess.run([sys.executable, str(ROOT / 'Code' / 'Analyze.py'), '--batch', str(batch_dir),
                          '--rules', str(out / 'demo-rules.json'), '--output', str(report)], capture_output=True, text=True)
    if run.returncode != 3:
        raise RuntimeError(f'Expected unresolved-data exit 3, got {run.returncode}: {run.stderr}')
    results = json.loads((report / 'Evidence.json').read_text(encoding='utf-8'))['tests']
    actual = {r['asset_id']: r['result'] for r in results}
    expected = {'DEMO-PASS': 'Pass', 'DEMO-FAIL': 'Fail', 'DEMO-UNKNOWN': 'Unknown'}
    if actual != expected:
        raise AssertionError(actual)
    verify = subprocess.run([sys.executable, str(ROOT / 'Code' / 'VerifyManifest.py'), str(report)],
                            capture_output=True, text=True)
    if verify.returncode != 0:
        raise RuntimeError(verify.stdout + verify.stderr)
    print('SYNTHETIC OFFLINE DEMO - no real hosts queried')
    print('Rule: RequireSecuritySignature must equal true')
    for name in expected:
        print(f'{name:14} {actual[name]}')
    print('Analyzer exit: 3 (missing value remains unresolved)')
    print('Report manifest: verified')
    print('No severity or exploitability is inferred.')
    print('Open:', report / 'Summary.html')
    print('Retained demo files:', out)


if __name__ == '__main__':
    main()
