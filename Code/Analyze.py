#!/usr/bin/env python3
"""PostureKit - evidence normalizer/evaluator, version 0.6.

Python 3.10+ standard library only. It reads evidence already collected in an
authorized lab or engagement. It does not scan networks, execute PowerShell,
query the internet, discover CVEs, or assign severity automatically.

The principal output is Evidence.json / Tests.csv: a report-ready evidence set
where every test record points back to a raw artifact and where incomplete
coverage stays visible.
"""
from __future__ import annotations
import argparse
import collections
import csv
import hashlib
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.6"
SOURCE_IDS = {
    'firewall', 'smbserver', 'smbclient', 'rdp', 'uac', 'localadmins',
    'localguest', 'tcplisteners', 'udpendpoints', 'connections', 'software',
    'hotfixes', 'addresses', 'defender', 'services',
    # security-configuration sources
    'patchlevel', 'lsa', 'wdigest', 'logonpolicy', 'nameresolution',
    'installerpolicy', 'powershelllogging', 'uacpolicy', 'smb1driver',
    'autorunpolicy', 'laps', 'passwordpolicy', 'bootintegrity',
    'updatesource', 'pointandprint', 'winrmconfig', 'credentialguard',
    'optionalfeatures', 'pscorelogging', 'lapsconfig',
    # directory evidence; NotApplicable on a workgroup host
    'domainidentity', 'domainpolicy', 'domainprivilegedgroups',
    'domaintrusts', 'kerberospolicy', 'gpoapplied',
    # wireless host-side configuration (Layer A)
    'wirelessadapters', 'wirelessinterface', 'wirelessprofiles', 'wirelessposture'
}
# A batch is only "Complete" when the core host sources are all present and good.
# Sources added later (security configuration, directory) are optional: a host that
# cannot produce one records Error or NotApplicable, which the status test catches.
# Requiring every known source would mark older evidence Partial the moment a new
# source is added, which would be a change in the record, not in the evidence.
REQUIRED_SOURCE_IDS = {
    'firewall', 'smbserver', 'smbclient', 'rdp', 'uac', 'localadmins',
    'localguest', 'tcplisteners', 'udpendpoints', 'connections', 'software',
    'hotfixes', 'addresses', 'defender', 'services'
}
DIRECTORY_SOURCE_IDS = {
    'domainidentity', 'domainpolicy', 'domainprivilegedgroups',
    'domaintrusts', 'kerberospolicy', 'gpoapplied'
}
SOURCE_STATUSES = {'Collected', 'Partial', 'Error', 'Unsupported', 'NotApplicable'}
TARGET_STATUSES = {'Pending', 'Excluded', 'NotAttempted', 'Error', 'Complete', 'Partial'}
RESULTS = {'Pass', 'Fail', 'Unknown', 'Error', 'Not tested', 'Not applicable', 'Inconclusive', 'Observation', 'Candidate'}
MAX_BYTES = 30 * 1024 * 1024
ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
HEX_RE = re.compile(r'[0-9a-f]{64}')


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON key: {key}')
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise ValueError(f'Expected a regular evidence file: {path}')
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f'JSON exceeds {MAX_BYTES} bytes: {path.name}')
    data = json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f'Non-finite JSON number: {value}')))
    if not isinstance(data, dict):
        raise ValueError(f'Expected a JSON object: {path.name}')
    return data


def safe_child(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.json', name):
        raise ValueError('Evidence must be a simple JSON filename, not a path or URL.')
    candidate = root / name
    if candidate.is_symlink() or candidate.resolve().parent != root.resolve():
        raise ValueError('Evidence path leaves the batch directory or is a symlink.')
    return candidate


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError('Missing timestamp.')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})', value)
    if not match:
        raise ValueError('Require an ISO timestamp with explicit timezone.')
    fraction = ((match.group(2) or '') + '000000')[:6]
    zone = '+00:00' if match.group(3) == 'Z' else match.group(3)
    return datetime.fromisoformat(match.group(1) + '.' + fraction + zone)


def _as_number(value: Any) -> Any:
    """Whole number from an int, or from text a rule has declared numeric.

    Windows reports several policy values as text (the built-in net accounts
    output, for example). Parsing happens only for rules that declare a numeric
    comparison kind, so nothing is coerced implicitly.
    """
    if type(value) is bool:
        return None
    if type(value) is int:
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit() or (text.startswith('-') and text[1:].isdigit()):
            return int(text)
    return None


def strict_value(value: Any, kind: str) -> Any:
    if kind == 'bool' and type(value) is bool:
        return value
    if kind == 'enum_bool':
        if type(value) is bool:
            return value
        if isinstance(value, str) and value.casefold() in ('true', 'false'):
            return value.casefold() == 'true'
    if kind == 'int' and type(value) is int:
        return value
    if kind == 'string' and isinstance(value, str):
        return value
    raise ValueError('Missing or unexpected evidence type; no implicit coercion.')


def load_rules(path: Path) -> dict[str, Any]:
    document = read_json(path)
    if document.get('schema_version') != '1.0' or not isinstance(document.get('profile_id'), str):
        raise ValueError('Unsupported rule document.')
    rules = document.get('rules')
    if not isinstance(rules, list) or not 1 <= len(rules) <= 100:
        raise ValueError('Require 1-100 declarative rules.')
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError('Each rule must be an object.')
        for key in ('id', 'title', 'source', 'field', 'type'):
            if not isinstance(rule.get(key), str) or not rule[key]:
                raise ValueError(f'Missing rule field: {key}')
        if rule['id'].casefold() in seen or rule['source'] not in SOURCE_IDS:
            raise ValueError('Duplicate rule ID or unsupported source.')
        seen.add(rule['id'].casefold())
        absent = rule.get('absent_means')
        if absent is not None:
            if (not isinstance(absent, dict)
                    or absent.get('result') not in RESULTS
                    or not isinstance(absent.get('interpretation'), str)
                    or not absent['interpretation'].strip()):
                raise ValueError('absent_means must state a valid result and a written interpretation.')
        if not ID_RE.fullmatch(rule['id']) or rule['type'] not in (
                'bool', 'enum_bool', 'int', 'string',
                'int_any', 'numeric_max', 'numeric_min', 'numeric_between'):
            raise ValueError('Invalid rule identifier or type.')
        if rule['type'] in ('int_any', 'numeric_between'):
            if (not isinstance(rule.get('expected'), list) or not rule['expected']
                    or not all(type(v) is int for v in rule['expected'])):
                raise ValueError('expected must be a non-empty list of integers for this rule type.')
            if rule['type'] == 'numeric_between' and len(rule['expected']) != 2:
                raise ValueError('numeric_between expects exactly two integers.')
        elif rule['type'] in ('numeric_max', 'numeric_min'):
            if type(rule.get('expected')) is not int:
                raise ValueError('expected must be an integer for a numeric threshold rule.')
        else:
            strict_value(rule.get('expected'), rule['type'])
        if 'selector' in rule and (not isinstance(rule['selector'], dict) or len(rule['selector']) != 1):
            raise ValueError('Selectors must contain exactly one field/value pair.')
        if 'selector' in rule and not all(isinstance(k, str) and isinstance(v, (str, int, bool)) for k, v in rule['selector'].items()):
            raise ValueError('Selector values must be simple scalar values.')
        if 'gate' in rule:
            gate = rule['gate']
            if not isinstance(gate, dict) or not isinstance(gate.get('field'), str):
                raise ValueError('Invalid rule gate.')
            if type(gate.get('enabled')) is not int or type(gate.get('disabled')) is not int or gate['enabled'] == gate['disabled']:
                raise ValueError('Gate values must be different integers.')
    return document


def validate_raw(raw: dict[str, Any], target: dict[str, Any], batch: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if raw.get('schema_version') != '1.0' or raw.get('tool_version') != VERSION or raw.get('evidence_kind') != 'WindowsCollection':
        raise ValueError('Unsupported host evidence schema or tool version.')
    for key in ('asset_id', 'site_id'):
        if raw.get(key) != target[key]:
            raise ValueError(f'Host evidence {key} mismatch.')
    for key in ('engagement_id', 'scope_sha256', 'collector_sha256'):
        if raw.get(key) != batch[key]:
            raise ValueError(f'Host evidence {key} mismatch.')
    host = raw.get('host')
    if not isinstance(host, dict) or str(host.get('computer_name', '')).casefold() != target['computer_name'].casefold():
        raise ValueError('Computer identity mismatch.')
    if type(host.get('domain_role')) is not int or host['domain_role'] not in range(6):
        raise ValueError('Missing or invalid host domain role.')
    if type(host.get('is_domain_controller')) is not bool or host['is_domain_controller'] != (host['domain_role'] in (4, 5)):
        raise ValueError('Domain-controller identity is inconsistent.')
    if raw.get('collection_status') not in ('Complete', 'Partial'):
        raise ValueError('Invalid host collection status.')
    for key in ('scope_sha256', 'collector_sha256'):
        if not isinstance(raw.get(key), str) or not HEX_RE.fullmatch(raw[key]):
            raise ValueError('Missing or malformed digest.')
    started, completed = parse_time(raw.get('started_utc')), parse_time(raw.get('completed_utc'))
    if completed < started:
        raise ValueError('Collection end precedes its start.')
    records = raw.get('sources')
    if not isinstance(records, list) or len(records) > 100:
        raise ValueError('Unexpected sources structure.')
    sources: dict[str, dict[str, Any]] = {}
    for source in records:
        if not isinstance(source, dict) or source.get('id') not in SOURCE_IDS:
            raise ValueError('Unrecognized source.')
        if source['id'] in sources or source.get('status') not in SOURCE_STATUSES:
            raise ValueError('Duplicate source or invalid collection status.')
        if not isinstance(source.get('data'), list) or not all(isinstance(row, dict) for row in source['data']):
            raise ValueError('Source data must be a list of objects.')
        if len(source['data']) > 5000:
            raise ValueError('Source exceeds the retained-row limit.')
        returned, retained = source.get('returned_count'), source.get('retained_count')
        if type(returned) is not int or type(retained) is not int or retained != len(source['data']) or returned < retained or retained < 0:
            raise ValueError('Inconsistent source row counts.')
        if source['status'] == 'Collected' and returned != retained:
            raise ValueError('A truncated source cannot be labelled Collected.')
        if source['status'] in ('Error', 'Unsupported', 'NotApplicable') and (returned or retained):
            raise ValueError('Uncollected source contains rows.')
        directory_na = source['id'] in DIRECTORY_SOURCE_IDS and not host.get('part_of_domain', False)
        if source['status'] == 'NotApplicable' and not directory_na and not (
                host['is_domain_controller'] and source['id'] in ('localadmins', 'localguest')):
            raise ValueError('Unsupported NotApplicable declaration.')
        if host['is_domain_controller'] and source['id'] in ('localadmins', 'localguest') and source['status'] == 'Collected':
            raise ValueError('Local SAM evidence must not substitute for AD assessment on a DC.')
        sources[source['id']] = source
    return sources


def make_test(*, test_id: str, phase: str, category: str, objective: str, method: str,
              site_id: str = '', asset_id: str = '', source_position: str = '', expected: Any = None,
              control_refs: str = '',
              observed: Any = None, result: str = 'Unknown', interpretation: str = '', severity: str = 'Not assigned',
              validation: str = 'Requires human review', evidence_file: str = '', evidence_pointer: str = '',
              evidence_sha256: str = '', timestamp_utc: str = '', limitations: str = '', reference: str = '') -> dict[str, Any]:
    if result not in RESULTS:
        raise ValueError(f'Unsupported result state: {result}')
    return {
        'test_id': test_id, 'phase': phase, 'category': category, 'site_id': site_id, 'asset_id': asset_id,
        'source_position': source_position, 'objective': objective, 'method': method,
        'control_refs': control_refs, 'expected': expected, 'observed': observed, 'result': result,
        'technical_interpretation': interpretation, 'severity': severity, 'validation': validation,
        'evidence_file': evidence_file, 'evidence_pointer': evidence_pointer,
        'evidence_sha256': evidence_sha256, 'timestamp_utc': timestamp_utc,
        'limitations': limitations, 'reference': reference,
    }


def evaluate_rule(rule: dict[str, Any], sources: dict[str, dict[str, Any]], asset_id: str, site_id: str,
                  evidence_file: str, evidence_hash: str, timestamp: str) -> dict[str, Any]:
    source = sources.get(rule['source'])
    base = dict(test_id=f'HOST.{asset_id}.{rule["id"]}', phase=rule.get('phase', 'host_configuration'),
                category=rule.get('category', rule['source']), site_id=site_id, asset_id=asset_id,
                source_position='Authenticated local Windows evidence', objective=rule['title'],
                method=rule.get('method', f'Compare {rule["source"]}.{rule["field"]} with the selected lab reference condition.'),
                expected=rule['expected'], severity='Not assigned', validation='Unvalidated lab reference check',
                control_refs='; '.join('%s %s' % (r.get('framework',''), r.get('control_id',''))
                                       for r in rule.get('control_refs', [])) or 'Not mapped',
                evidence_file=evidence_file, evidence_pointer=f"sources[id={rule['source']}].data",
                evidence_sha256=evidence_hash, timestamp_utc=timestamp,
                limitations=rule.get('applicability', 'Verify OS/role applicability and client exceptions before reporting.'),
                reference=rule.get('basis', 'Lab reference only'))
    if not source:
        return make_test(**base, result='Unknown', interpretation='Required source is absent from the host evidence.')
    state = source.get('status')
    if state != 'Collected':
        mapping = {'Error': 'Error', 'Unsupported': 'Not tested', 'NotApplicable': 'Not applicable', 'Partial': 'Unknown'}
        return make_test(**base, result=mapping.get(state, 'Unknown'),
                         interpretation=source.get('error') or source.get('note') or f'Source state: {state}')
    rows = source.get('data')
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return make_test(**base, result='Unknown', interpretation='Unexpected source data structure.')
    selector = rule.get('selector', {})
    selected = [row for row in rows if all(row.get(k) == v for k, v in selector.items())]
    if len(selected) != 1:
        return make_test(**base, result='Unknown', interpretation='Expected exactly one matching record; evidence is missing or ambiguous.')
    row = selected[0]
    if 'gate' in rule:
        gate = rule['gate']
        actual_gate = row.get(gate['field'])
        if type(actual_gate) is not int or actual_gate not in (gate['enabled'], gate['disabled']):
            return make_test(**base, result='Unknown', interpretation='Applicability gate cannot be determined.')
        if actual_gate == gate['disabled']:
            return make_test(**base, result='Not applicable', observed=row.get(rule['field']),
                             interpretation=f"{gate['field']} indicates the feature is disabled. This is not a reachability test.")
    observed = row.get(rule['field'])
    # A registry value that is not present is evidence in its own right: it means
    # the operating-system default applies. That is only ever interpreted when the
    # rule states the meaning explicitly, so no default is ever assumed silently.
    if observed is None:
        absent = rule.get('absent_means')
        if absent is None:
            return make_test(**base, observed=None, result='Unknown',
                             interpretation='The value is not present and the rule does not state '
                                            'what its absence means, so no determination is made.')
        if absent['result'] not in RESULTS:
            return make_test(**base, observed=None, result='Unknown',
                             interpretation='Invalid absent-value declaration in the rule set.')
        return make_test(**base, observed=None, result=absent['result'],
                         interpretation=absent['interpretation'])
    kind = rule['type']

    # Comparisons beyond equality. A threshold or an accepted-value set is stated
    # by the rule itself; the engine never decides that two values are equivalent.
    if kind in ('int_any', 'numeric_max', 'numeric_min', 'numeric_between'):
        number = _as_number(observed)
        if number is None:
            return make_test(**base, observed=observed, result='Unknown',
                             interpretation='The observed value is not a whole number, so the declared '
                                            'comparison cannot be applied.')
        if kind == 'int_any':
            ok = number in rule['expected']
            wording = 'one of %s' % (', '.join(str(v) for v in rule['expected']))
        elif kind == 'numeric_max':
            ok = number <= rule['expected']
            wording = 'at most %d' % rule['expected']
        elif kind == 'numeric_min':
            ok = number >= rule['expected']
            wording = 'at least %d' % rule['expected']
        else:
            low, high = rule['expected']
            ok = low <= number <= high
            wording = 'between %d and %d inclusive' % (low, high)
        return make_test(**base, observed=observed, result='Pass' if ok else 'Fail',
                         interpretation='Observed %s against a declared acceptable value of %s. '
                                        'Impact and exploitability are not established by this result.'
                                        % (number, wording))

    try:
        actual = strict_value(observed, kind)
        expected = strict_value(rule['expected'], kind)
    except ValueError as exc:
        return make_test(**base, observed=observed, result='Unknown', interpretation=str(exc))
    return make_test(**base, observed=observed, result='Pass' if actual == expected else 'Fail',
                     interpretation='Direct configuration comparison only. Impact/exploitability is not established by this result.')


def analyze_batch(batch_dir: Path, rule_doc: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    batch_dir = batch_dir.resolve()
    batch = read_json(safe_child(batch_dir, 'Batch.json'))
    scope_path = safe_child(batch_dir, 'Scope.json')
    scope = read_json(scope_path)
    if batch.get('schema_version') != '1.0' or batch.get('tool_version') != VERSION or batch.get('evidence_kind') != 'CollectionBatch':
        raise ValueError('Unsupported batch schema or tool version.')
    if scope.get('schema_version') != '1.0' or scope.get('approved_for_lab') is not True:
        raise ValueError('Missing approved lab scope.')
    if batch.get('scope_sha256') != sha256(scope_path) or batch.get('engagement_id') != scope.get('engagement_id'):
        raise ValueError('Scope digest or engagement mismatch.')
    targets = scope.get('targets')
    if not isinstance(targets, list) or not 1 <= len(targets) <= 20:
        raise ValueError('This tool expects 1-20 scoped assets.')
    approved: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError('Target is not an object.')
        for key in ('asset_id', 'site_id', 'computer_name'):
            if not isinstance(target.get(key), str) or not ID_RE.fullmatch(target[key]):
                raise ValueError(f'Invalid target {key}.')
        if type(target.get('enabled')) is not bool or target['asset_id'].casefold() in folded:
            raise ValueError('Invalid enabled flag or duplicate asset ID.')
        folded.add(target['asset_id'].casefold())
        approved[target['asset_id']] = target
    entries = batch.get('targets')
    if not isinstance(entries, list) or len(entries) > 20:
        raise ValueError('Invalid batch target list.')
    indexed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get('asset_id') not in approved or entry['asset_id'] in indexed:
            raise ValueError('Unknown or duplicate target in batch ledger.')
        if entry.get('status') not in TARGET_STATUSES:
            raise ValueError('Unrecognized batch target status.')
        target = approved[entry['asset_id']]
        if entry.get('site_id') != target['site_id'] or str(entry.get('computer_name', '')).casefold() != target['computer_name'].casefold():
            raise ValueError('Batch ledger identity mismatch.')
        indexed[entry['asset_id']] = entry
    assets: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for asset_id, target in approved.items():
        entry = indexed.get(asset_id, {})
        summary = {'asset_id': asset_id, 'site_id': target['site_id'], 'computer_name': target['computer_name'],
                   'status': 'NotAttempted', 'evidence': None, 'note': 'No completed collection available.'}
        if not target['enabled']:
            summary.update(status='Excluded', note='Excluded by the approved scope.')
        elif entry.get('status') in ('Complete', 'Partial'):
            try:
                path = safe_child(batch_dir, entry.get('evidence_file'))
                digest = sha256(path)
                if digest != entry.get('evidence_sha256'):
                    raise ValueError('Evidence digest mismatch.')
                raw = read_json(path)
                sources = validate_raw(raw, target, batch)
                complete = (entry['status'] == 'Complete' and raw['collection_status'] == 'Complete' and
                            REQUIRED_SOURCE_IDS.issubset(set(sources)) and all(s['status'] in ('Collected', 'NotApplicable') for s in sources.values()))
                summary.update(status='Complete' if complete else 'Partial', evidence=path.name,
                               note='Collection completeness refers only to this collector, not complete penetration-test coverage.')
                artifacts.append({'file': path.name, 'sha256': digest, 'kind': 'WindowsCollection', 'asset_id': asset_id})
                for rule in rule_doc['rules']:
                    tests.append(evaluate_rule(rule, sources, asset_id, target['site_id'], path.name, digest, raw['completed_utc']))
            except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
                summary.update(status='EvidenceRejected', note=str(exc))
        else:
            summary.update(status=entry.get('status', 'NotAttempted'), note=entry.get('error') or summary['note'])
        assets.append(summary)
    meta = {
        'engagement_id': batch['engagement_id'], 'batch_id': batch.get('batch_id'),
        'scope_sha256': batch['scope_sha256'], 'collector_sha256': batch.get('collector_sha256'),
        'profile_id': rule_doc['profile_id'], 'rules_notice': rule_doc.get('notice', ''),
        'batch_completed': bool(batch.get('completed_utc')), 'enabled_assets': sum(t['enabled'] for t in targets),
        'generated_utc': datetime.now(timezone.utc).isoformat(), 'tool_version': VERSION,
    }
    return assets, tests, meta, artifacts


def import_network(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'NetworkObservations':
        raise ValueError(f'Unsupported network evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'Network engagement mismatch: {path.name}')
    start, end = parse_time(doc.get('started_utc')), parse_time(doc.get('completed_utc'))
    if end < start:
        raise ValueError('Network evidence end precedes start.')
    rows = doc.get('results')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise ValueError('Unexpected network result list.')
    digest = sha256(path)
    tests: list[dict[str, Any]] = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError('Network result is not an object.')
        test_id = row.get('test_id') or f'NET{index:03d}'
        if not isinstance(test_id, str) or not ID_RE.fullmatch(test_id):
            raise ValueError('Invalid network test ID.')
        connected = row.get('connected')
        if type(connected) is not bool:
            raise ValueError('Network connected value must be boolean after an attempted test.')
        expected = row.get('expected')
        if expected not in ('Reachable', 'Blocked'):
            raise ValueError('Invalid network expected state.')
        if connected and expected == 'Reachable':
            result, interpretation = 'Pass', 'TCP connection succeeded from the designated source, matching the expected reachable path.'
        elif connected and expected == 'Blocked':
            result, interpretation = 'Fail', 'TCP connection succeeded from a source where the approved expectation was Blocked. Validate service identity and policy before reporting.'
        else:
            result, interpretation = 'Inconclusive', 'No TCP connection was established. This alone does not prove segmentation because service state, routing, filtering, or another cause may explain the result.'
        tests.append(make_test(
            test_id=f'NET.{test_id}', phase='active_network', category='segmentation_reachability',
            site_id=str(doc.get('source_site_id') or ''), asset_id='',
            source_position=str(doc.get('source_context') or ''),
            objective=f"Validate TCP reachability from {doc.get('source_asset_id')} to {row.get('target_ip')}:{row.get('port')}",
            method='Bounded TCP connect from an explicitly approved source; no service payload or authentication.',
            expected=expected, observed={'connected': connected, 'target_ip': row.get('target_ip'), 'port': row.get('port'),
                                        'local_endpoint': row.get('local_endpoint'), 'elapsed_ms': row.get('elapsed_ms'), 'error': row.get('error')},
            result=result, interpretation=interpretation, validation='Network-path observation; policy and service state require human review.',
            evidence_file=path.name, evidence_pointer=f'results[{index-1}]', evidence_sha256=digest,
            timestamp_utc=str(row.get('timestamp_utc') or doc.get('completed_utc')),
            limitations='Result is specific to this source address/interface, route, time and target service.',
            reference='Approved source-to-target matrix'))
    artifact = {'file': path.name, 'sha256': digest, 'kind': 'NetworkObservations', 'asset_id': doc.get('source_asset_id')}
    return tests, artifact


def import_updates(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'WuaOfflineUpdateApplicability':
        raise ValueError(f'Unsupported update evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'Update engagement mismatch: {path.name}')
    digest = sha256(path)
    updates = doc.get('updates')
    if not isinstance(updates, list) or len(updates) > 10000:
        raise ValueError('Unexpected update result list.')
    tests = [make_test(
        test_id=f'UPD.{doc.get("computer_name")}.SUMMARY', phase='patch_applicability', category='microsoft_updates',
        site_id=str(doc.get('site_id') or ''), asset_id=str(doc.get('asset_id') or doc.get('computer_name') or ''), source_position='Local Windows Update Agent offline scan',
        objective='Record applicable missing Microsoft security-related updates represented by the supplied signed offline catalogue.',
        method='Windows Update Agent offline scan with operator-supplied Microsoft-signed Wsusscn2.cab.',
        expected='Review applicable missing security-related updates', observed={'missing_applicable_count': len(updates), 'cab_sha256': doc.get('cab_sha256')},
        result='Observation', interpretation='This records patch applicability within the catalogue scope; it is not complete CVE coverage or proof of exploitability.',
        validation='Review catalogue date/scope and selected update applicability.', evidence_file=path.name, evidence_pointer='updates',
        evidence_sha256=digest, timestamp_utc=str(doc.get('completed_utc') or ''),
        limitations='Microsoft security-related update metadata only; third-party products and unsupported content are outside this evidence source.',
        reference='Microsoft WUA offline scanning')]
    for i, update in enumerate(updates, 1):
        if not isinstance(update, dict):
            raise ValueError('Update record is not an object.')
        tests.append(make_test(
            test_id=f'UPD.{doc.get("computer_name")}.{i:04d}', phase='patch_applicability', category='microsoft_updates',
            site_id=str(doc.get('site_id') or ''), asset_id=str(doc.get('asset_id') or doc.get('computer_name') or ''), source_position='Local Windows Update Agent offline scan',
            objective='Review an applicable missing Microsoft update.', method='Windows Update Agent offline applicability result.',
            expected='Applicable security-related updates should be reviewed/remediated under the client patch policy.',
            observed={'title': update.get('Title'), 'kb': update.get('KBArticleIDs'), 'msrc_severity': update.get('MsrcSeverity'),
                      'update_id': update.get('UpdateID'), 'revision': update.get('RevisionNumber')},
            result='Candidate', interpretation='Applicable missing update candidate. Validate support state, supersedence, exception and actual security relevance before creating a vulnerability finding.',
            validation='Requires analyst validation.', evidence_file=path.name, evidence_pointer=f'updates[{i-1}]', evidence_sha256=digest,
            timestamp_utc=str(doc.get('completed_utc') or ''), limitations='No exploitability conclusion is made.', reference='Microsoft WUA offline scanning'))
    return tests, {'file': path.name, 'sha256': digest, 'kind': 'WuaOfflineUpdateApplicability', 'asset_id': doc.get('asset_id') or doc.get('computer_name')}


def import_nmap(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'NmapObservations':
        raise ValueError(f'Unsupported normalized Nmap evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'Nmap engagement mismatch: {path.name}')
    digest = sha256(path)
    observations = doc.get('observations')
    if not isinstance(observations, list) or len(observations) > 50000:
        raise ValueError('Unexpected Nmap observation list.')
    tests: list[dict[str, Any]] = []
    for i, item in enumerate(observations, 1):
        if not isinstance(item, dict):
            raise ValueError('Nmap observation is not an object.')
        host = str(item.get('address') or '')
        port = item.get('port')
        state = str(item.get('state') or '')
        tests.append(make_test(
            test_id=f'NMAP.{i:05d}', phase='active_network', category='service_exposure', site_id=str(doc.get('source_site_id') or ''),
            source_position=str(doc.get('source_position') or ''), objective=f'Record observed {item.get("protocol")}/{port} state on {host} from the designated scanner.',
            method='Imported Nmap XML generated separately by the operator; this package does not ship or execute Nmap.',
            expected='Observation only', observed=item, result='Observation',
            interpretation='Port/service observation from one scanning position. An open port is not automatically a vulnerability.',
            validation='Correlate with intended exposure, host evidence and any maintained vulnerability scanner findings.', evidence_file=path.name,
            evidence_pointer=f'observations[{i-1}]', evidence_sha256=digest, timestamp_utc=str(doc.get('completed_utc') or ''),
            limitations='Service/version identification can be uncertain and is source-position specific. No NSE/vulnerability-script conclusion is inferred by the importer.',
            reference='Nmap XML observation'))
    return tests, {'file': path.name, 'sha256': digest, 'kind': 'NmapObservations', 'asset_id': doc.get('source_asset_id')}


def import_cim(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'CimObservations':
        raise ValueError(f'Unsupported CIM evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'CIM engagement mismatch: {path.name}')
    digest=sha256(path); rows=doc.get('observations')
    if not isinstance(rows,list) or len(rows)>100:
        raise ValueError('Unexpected CIM observation list.')
    tests=[]; seen=set()
    for i,row in enumerate(rows,1):
        if not isinstance(row,dict): raise ValueError('Invalid CIM observation record.')
        rid=str(row.get('id') or '')
        if not rid or rid in seen: raise ValueError('CIM observation IDs must be unique.')
        seen.add(rid)
        status=str(row.get('status') or '')
        if status=='Collected': result='Observation'
        elif status=='Error': result='Error'
        elif status in ('NotImplemented','Unsupported'): result='Not tested'
        elif status=='NotApplicable': result='Not applicable'
        else: raise ValueError(f'Unsupported CIM observation status: {status}')
        tests.append(make_test(
            test_id=f'CIM.{doc.get("asset_id")}.{rid}', phase='host_collection', category='agentless_cim',
            site_id=str(doc.get('site_id') or ''), asset_id=str(doc.get('asset_id') or ''),
            source_position=str(doc.get('source_position') or ''), objective=f'Record agentless CIM source {rid}.',
            method=f'Imported agentless CIM subset using {doc.get("authentication")}; SSL={doc.get("use_ssl")}.',
            expected='Observation only', observed={'status':status,'data':row.get('data'),'error':row.get('error')}, result=result,
            interpretation='Agentless management-plane evidence only; it does not establish exploitability or exposure from other zones.',
            validation='Compare against the full collector or another independent source when the observation becomes material to a finding.',
            evidence_file=path.name,evidence_pointer=f'observations[{i-1}]',evidence_sha256=digest,
            timestamp_utc=str(doc.get('normalized_utc') or doc.get('survey_timestamp_utc') or ''),
            limitations=str(row.get('limitation') or 'Reduced CIM subset.'), reference='agentless CIM feasibility survey'))
    return tests, {'file':path.name,'sha256':digest,'kind':'CimObservations','asset_id':doc.get('asset_id')}


def import_hardeningkitty(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'HardeningKittyAudit':
        raise ValueError(f'Unsupported HardeningKitty evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'HardeningKitty engagement mismatch: {path.name}')
    digest=sha256(path); rows=doc.get('results')
    if not isinstance(rows,list) or len(rows)>5000:
        raise ValueError('Unexpected HardeningKitty result list.')
    tests=[]
    for i,row in enumerate(rows,1):
        if not isinstance(row,dict) or row.get('test_result') not in ('Passed','Failed'):
            raise ValueError('Invalid HardeningKitty result record.')
        rid=str(row.get('id') or i)
        tests.append(make_test(
            test_id=f'HK.{doc.get("asset_id")}.{rid}', phase='host_configuration', category='baseline_audit',
            site_id=str(doc.get('site_id') or ''), asset_id=str(doc.get('asset_id') or ''),
            source_position='Local/approved HardeningKitty Audit-mode result',
            objective=str(row.get('name') or f'HardeningKitty check {rid}'),
            method=f'Imported HardeningKitty Audit result using profile {doc.get("profile")}.',
            expected=row.get('recommended'), observed=row.get('observed'),
            result='Pass' if row.get('test_result')=='Passed' else 'Fail',
            interpretation='Configuration/baseline comparison only. A failed benchmark check is not automatic proof of exploitability.',
            validation='Verify OS/role/language applicability, finding-list provenance and any client exception before reporting.',
            evidence_file=path.name,evidence_pointer=f'results[{i-1}]',evidence_sha256=digest,timestamp_utc=str(doc.get('normalized_utc') or ''),
            limitations='assessor-assigned severity is not inherited from HardeningKitty. The source list and execution context determine applicability.',
            reference=f'HardeningKitty profile {doc.get("profile")}'))
    return tests, {'file':path.name,'sha256':digest,'kind':'HardeningKittyAudit','asset_id':doc.get('asset_id')}


def import_wireless_air(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'WirelessAirObservations':
        raise ValueError(f'Unsupported normalized wireless-air evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'Wireless-air engagement mismatch: {path.name}')
    digest = sha256(path); rows = doc.get('observations')
    if not isinstance(rows, list) or len(rows) > 50000:
        raise ValueError('Unexpected wireless-air observation list.')
    ctl = 'NIST SP 800-53 Rev 5 AC-18'
    tests = []
    for i, o in enumerate(rows, 1):
        if not isinstance(o, dict):
            raise ValueError('Wireless-air observation is not an object.')
        cls = str(o.get('classification') or '')
        essid = o.get('essid') or '(hidden)'
        if cls == 'RogueOrEvilTwin':
            result, obj = 'Fail', f"Unauthorized access point broadcasting corporate ESSID '{essid}'"
            interp = 'A radio broadcasting a corporate ESSID is not on the authorized-access-point list. This is a rogue or evil-twin candidate that can harvest credentials or bridge clients; confirm the BSSID against the authorized inventory.'
        elif o.get('open') and o.get('corporate_essid'):
            result, obj = 'Fail', f"Corporate ESSID '{essid}' observed with no encryption"
            interp = 'A corporate ESSID is being broadcast open (unencrypted). Traffic and association are unprotected.'
        elif o.get('wps_enabled') and cls in ('AuthorizedAP',):
            result, obj = 'Fail', f"WPS enabled on authorized access point for '{essid}'"
            interp = 'Wi-Fi Protected Setup is enabled and is subject to PIN brute-force; it should be disabled on corporate access points.'
        elif cls == 'Hidden':
            result, obj = 'Observation', 'Hidden-SSID access point observed'
            interp = 'A non-broadcast SSID was seen. Hidden SSID is not a security control; recorded as an observation.'
        elif cls == 'Open':
            result, obj = 'Observation', f"Open external network '{essid}' observed"
            interp = 'An open network not on the corporate list was seen in the environment; recorded for context.'
        else:
            result, obj = 'Observation', f"Access point '{essid}' observed"
            interp = 'Access-point observation from one physical position. Not a vulnerability by itself.'
        tests.append(make_test(
            test_id=f'AIR.{i:05d}', phase='active_wireless', category='wireless_air',
            site_id=str(doc.get('source_site_id') or ''), source_position=str(doc.get('source_position') or ''),
            objective=obj, method='Imported over-the-air capture (airodump-ng/wash) generated separately by the operator; this package neither transmits nor captures radio.',
            control_refs=ctl, expected='Authorized, encrypted, WPS-disabled', observed=o, result=result,
            interpretation=interp, validation='Confirm the BSSID against the authorized inventory and corroborate on-site before reporting.',
            evidence_file=path.name, evidence_pointer=f'observations[{i-1}]', evidence_sha256=digest,
            timestamp_utc=str(doc.get('completed_utc') or ''),
            limitations='One position and time window; rogue classification depends on the authorized-access-point allowlist being complete.',
            reference='Over-the-air Wi-Fi observation (Layer B)'))
    return tests, {'file': path.name, 'sha256': digest, 'kind': 'WirelessAirObservations', 'asset_id': doc.get('source_site_id')}


def import_wireless_controller(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'WirelessControllerConfig':
        raise ValueError(f'Unsupported wireless-controller evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'Wireless-controller engagement mismatch: {path.name}')
    digest = sha256(path)
    ctl = 'NIST SP 800-53 Rev 5 AC-18'
    site = str(doc.get('site_id') or ''); pos = str(doc.get('source_position') or '')
    ts = str(doc.get('normalized_utc') or '')
    controller = doc.get('controller') or {}
    corp_vlans = set(doc.get('corporate_vlans') or [])
    wlans = doc.get('wlans')
    if not isinstance(wlans, list) or not wlans:
        raise ValueError('Wireless-controller evidence has no WLANs.')
    tests = []

    def rec(tid, obj, result, observed, interp):
        return make_test(test_id=tid, phase='wireless_controller', category='wireless_controller', site_id=site,
                         source_position=pos, objective=obj, method='Imported wireless-controller configuration intake completed by the operator from the client export.',
                         control_refs=ctl, expected='Secure controller configuration', observed=observed, result=result,
                         interpretation=interp, validation='Confirm against the live controller and any documented exception before reporting.',
                         evidence_file=path.name, evidence_pointer='controller/wlans', evidence_sha256=digest, timestamp_utc=ts,
                         limitations='Configuration review only; does not prove runtime enforcement.', reference='Wireless controller configuration (Layer C)')

    tests.append(rec('CTRL.rogue_detection', 'Controller rogue-access-point detection is enabled',
                     'Pass' if controller.get('rogue_detection_enabled') else 'Fail',
                     {'rogue_detection_enabled': controller.get('rogue_detection_enabled')},
                     'Rogue-AP detection identifies unauthorized radios impersonating corporate SSIDs.'))
    tests.append(rec('CTRL.wips', 'Wireless intrusion prevention (WIPS) is enabled',
                     'Pass' if controller.get('wips_enabled') else 'Fail',
                     {'wips_enabled': controller.get('wips_enabled')},
                     'WIPS detects and can contain over-the-air attacks such as evil twins and deauthentication floods.'))
    for i, w in enumerate(wlans, 1):
        ssid = str(w.get('ssid') or f'wlan{i}'); purpose = str(w.get('purpose') or ''); sec = str(w.get('security') or '')
        pmf = str(w.get('pmf') or ''); vlan = w.get('vlan'); iso = w.get('client_isolation')
        base = f'CTRL.{i}'
        if sec == 'open':
            tests.append(rec(f'{base}.open', f"WLAN '{ssid}' is not an open (unencrypted) network", 'Fail',
                             {'ssid': ssid, 'security': sec}, 'An open SSID exposes association and traffic; it must be encrypted.'))
        if purpose == 'corporate':
            tests.append(rec(f'{base}.auth', f"Corporate WLAN '{ssid}' uses 802.1X (enterprise), not a pre-shared key",
                             'Pass' if 'enterprise' in sec else 'Fail', {'ssid': ssid, 'security': sec},
                             'A corporate SSID should authenticate with 802.1X; a shared key is recoverable off any endpoint.'))
        if purpose == 'guest':
            tests.append(rec(f'{base}.isolation', f"Guest WLAN '{ssid}' enforces client isolation",
                             'Pass' if iso is True else ('Fail' if iso is False else 'Unknown'), {'ssid': ssid, 'client_isolation': iso},
                             'Guest client isolation prevents guest devices reaching each other; absence enables lateral movement.'))
            if isinstance(vlan, int):
                tests.append(rec(f'{base}.vlan', f"Guest WLAN '{ssid}' is on a VLAN separate from corporate",
                                 'Fail' if vlan in corp_vlans else 'Pass', {'ssid': ssid, 'vlan': vlan, 'corporate_vlans': sorted(corp_vlans)},
                                 'A guest SSID sharing a corporate VLAN bridges untrusted devices into the corporate segment.'))
            else:
                tests.append(rec(f'{base}.vlan', f"Guest WLAN '{ssid}' VLAN separation from corporate", 'Unknown',
                                 {'ssid': ssid, 'vlan': None}, 'No VLAN was recorded for this guest SSID, so separation cannot be determined.'))
        tests.append(rec(f'{base}.pmf', f"WLAN '{ssid}' requires management-frame protection (PMF)",
                         'Pass' if pmf == 'required' else ('Fail' if pmf == 'disabled' else 'Observation'),
                         {'ssid': ssid, 'pmf': pmf}, 'PMF (802.11w) resists deauthentication and management-frame spoofing; "optional" leaves legacy clients unprotected.'))
    return tests, {'file': path.name, 'sha256': digest, 'kind': 'WirelessControllerConfig', 'asset_id': site}


def import_greenbone(path: Path, engagement: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    doc = read_json(path)
    if doc.get('schema_version') != '1.0' or doc.get('tool_version') != VERSION or doc.get('evidence_kind') != 'GreenboneObservations':
        raise ValueError(f'Unsupported normalized Greenbone evidence: {path.name}')
    if doc.get('engagement_id') != engagement:
        raise ValueError(f'Greenbone engagement mismatch: {path.name}')
    digest = sha256(path); rows = doc.get('observations')
    if not isinstance(rows, list) or len(rows) > 200000:
        raise ValueError('Unexpected Greenbone observation list.')
    ctl = 'NIST SP 800-53 Rev 5 RA-5'
    tests = []
    for i, o in enumerate(rows, 1):
        if not isinstance(o, dict):
            raise ValueError('Greenbone observation is not an object.')
        host = str(o.get('host') or ''); port = str(o.get('port') or '')
        name = str(o.get('name') or 'Scanner detection')
        actionable = bool(o.get('actionable'))
        result = 'Candidate' if actionable else 'Observation'
        interp = ('Network vulnerability-scanner detection that an analyst must confirm before it is reported as a finding; '
                  'an open detection is not a confirmed exploited vulnerability.') if actionable else \
                 'Informational scanner result recorded for context.'
        tests.append(make_test(
            test_id=f'VULN.{i:05d}', phase='active_network', category='network_vulnerability',
            site_id=str(doc.get('source_site_id') or ''), source_position=str(doc.get('source_position') or ''),
            objective=f'{name} on {host}:{port}' if host else name,
            method='Imported Greenbone/GVM report generated separately by the operator; this package does not run or ship a scanner.',
            control_refs=ctl, expected='No unconfirmed high or medium exposure on in-scope hosts', observed=o, result=result,
            interpretation=interp, validation='Confirm against the host evidence and manual testing; assign severity from the confirmed impact, not the scanner score.',
            evidence_file=path.name, evidence_pointer=f'observations[{i-1}]', evidence_sha256=digest,
            timestamp_utc=str(doc.get('completed_utc') or ''),
            limitations='One scanning position; scanner false positives/negatives are possible and its severity is not adopted as assessor-assigned severity.',
            reference='Greenbone/GVM network vulnerability scan'))
    return tests, {'file': path.name, 'sha256': digest, 'kind': 'GreenboneObservations', 'asset_id': doc.get('source_site_id')}


def merge_manual(path: Path, tests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise ValueError('Manual validation input must be a regular CSV file.')
    allowed={'Verified','Disputed','Not verified'}
    by_id={t['test_id']:t for t in tests}
    seen=set(); count=0; artifacts=[]; seen_artifacts=set()
    with path.open('r',encoding='utf-8-sig',newline='') as stream:
        reader=csv.DictReader(stream)
        required=['test_id','verification_status','verification_method','verification_observed','evidence_file','evidence_sha256','reviewer','notes']
        if reader.fieldnames != required:
            raise ValueError('Manual validation CSV columns do not match the template exactly.')
        for row in reader:
            tid=(row.get('test_id') or '').strip()
            if not tid: continue
            if tid in seen: raise ValueError(f'Duplicate manual validation test_id: {tid}')
            seen.add(tid)
            if tid not in by_id: raise ValueError(f'Manual validation references unknown test_id: {tid}')
            status=(row.get('verification_status') or '').strip()
            if status not in allowed: raise ValueError(f'Invalid manual verification_status for {tid}.')
            evidence=(row.get('evidence_file') or '').strip(); claimed=(row.get('evidence_sha256') or '').strip().lower()
            actual=''
            if evidence:
                ep=Path(evidence)
                if ep.is_absolute() or '..' in ep.parts:
                    raise ValueError(f'Manual evidence path for {tid} must be relative to the Manual.csv directory.')
                full=(path.parent/ep).resolve()
                if path.parent.resolve() not in full.parents:
                    raise ValueError(f'Manual evidence path for {tid} leaves the validation directory.')
                if not full.is_file() or full.is_symlink():
                    raise ValueError(f'Manual evidence file for {tid} is missing or not a regular file: {evidence}')
                actual=sha256(full)
                if not HEX_RE.fullmatch(claimed) or actual != claimed:
                    raise ValueError(f'Manual evidence SHA-256 mismatch for {tid}.')
                key=(evidence,actual)
                if key not in seen_artifacts:
                    artifacts.append({'file':evidence,'sha256':actual,'kind':'ManualEvidence','asset_id':''})
                    seen_artifacts.add(key)
            elif status in ('Verified','Disputed'):
                raise ValueError(f'{status} manual validation for {tid} requires a hashed evidence file.')
            elif claimed:
                raise ValueError(f'Manual evidence SHA-256 provided without evidence_file for {tid}.')
            by_id[tid]['manual_validation']={
                'status':status,'method':row.get('verification_method') or '',
                'observed':row.get('verification_observed') or '',
                'evidence_file':evidence,'evidence_sha256':actual,
                'reviewer':row.get('reviewer') or '', 'notes':row.get('notes') or ''}
            count+=1
    artifacts.insert(0,{'file':path.name,'sha256':sha256(path),'kind':'ManualValidation','asset_id':'','records':count})
    return artifacts

def csv_safe(value: Any) -> str:
    if value is None:
        return ''
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_safe(row.get(key)) for key in fields})


def render_html(assets: list[dict[str, Any]], tests: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    def e(value: Any) -> str:
        return html.escape(str(value), quote=True)
    def table(rows: list[dict[str, Any]], columns: list[str]) -> str:
        header = ''.join(f'<th>{e(c.replace("_", " "))}</th>' for c in columns)
        body = ''.join('<tr>' + ''.join(f'<td>{e(row.get(c, ""))}</td>' for c in columns) + '</tr>' for row in rows)
        return f'<table><thead><tr>{header}</tr></thead><tbody>{body}</table>'
    counts = dict(collections.Counter(t['result'] for t in tests))
    coverage = dict(collections.Counter(a['status'] for a in assets))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'">
<title>Evidence review</title><style>body{{font:14px/1.45 Arial,sans-serif;max-width:1250px;margin:28px auto;padding:0 18px;color:#172b3a}}table{{border-collapse:collapse;width:100%;table-layout:fixed}}th,td{{padding:7px;border:1px solid #ccd5dc;vertical-align:top;overflow-wrap:anywhere}}th{{background:#edf2f5}}.w{{padding:10px;background:#fff4d6;border-left:5px solid #947000}}</style></head><body>
<h1>Evidence review - tool {e(VERSION)}</h1><p class="w"><strong>Evidence package, not a client report.</strong> Test records remain subject to human validation. No automatic CVE, exploitability or severity conclusion is created.</p>
<p>Engagement: {e(meta['engagement_id'])}<br>Generated: {e(meta['generated_utc'])}<br>Results: {e(counts)}<br>Host coverage: {e(coverage)}</p>
<h2>Host collection coverage</h2>{table(assets,['asset_id','site_id','computer_name','status','evidence','note'])}
<h2>Normalized test records</h2>{table(tests,['test_id','phase','category','site_id','asset_id','objective','result','observed','expected','validation','evidence_file'])}
<p>Use Evidence.json as the authoritative normalized input for downstream report tooling. Raw artifacts and hashes remain required for traceability.</p></body></html>'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', type=Path, required=True)
    parser.add_argument('--rules', type=Path, default=Path(__file__).with_name('Rules.json'))
    parser.add_argument('--network', type=Path, action='append', default=[])
    parser.add_argument('--updates', type=Path, action='append', default=[])
    parser.add_argument('--nmap', type=Path, action='append', default=[])
    parser.add_argument('--hardeningkitty', type=Path, action='append', default=[])
    parser.add_argument('--cim', type=Path, action='append', default=[])
    parser.add_argument('--wireless-air', type=Path, action='append', default=[], help='Normalized over-the-air Wi-Fi evidence (Layer B) from WirelessAirImport.py')
    parser.add_argument('--wireless-controller', type=Path, action='append', default=[], help='Normalized wireless-controller evidence (Layer C) from WirelessControllerImport.py')
    parser.add_argument('--greenbone', type=Path, action='append', default=[], help='Normalized Greenbone/GVM network vulnerability evidence from GreenboneImport.py')
    parser.add_argument('--manual', type=Path, help='Optional completed Manual.csv template; merged without changing technical results.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
            raise ValueError('Output must be a new or empty directory; existing evidence is never overwritten.')
        rules = load_rules(args.rules)
        assets, tests, meta, artifacts = analyze_batch(args.batch, rules)
        meta['rules_sha256'] = sha256(args.rules)
        for path in args.network:
            new, artifact = import_network(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.updates:
            new, artifact = import_updates(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.nmap:
            new, artifact = import_nmap(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.hardeningkitty:
            new, artifact = import_hardeningkitty(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.cim:
            new, artifact = import_cim(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.wireless_air:
            new, artifact = import_wireless_air(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.wireless_controller:
            new, artifact = import_wireless_controller(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        for path in args.greenbone:
            new, artifact = import_greenbone(path.resolve(), meta['engagement_id']); tests.extend(new); artifacts.append(artifact)
        ids = [t['test_id'] for t in tests]
        if len(ids) != len(set(ids)):
            raise ValueError('Duplicate normalized test_id detected.')
        if args.manual:
            artifacts.extend(merge_manual(args.manual.resolve(), tests))
        out = args.output.resolve(); batch_path = args.batch.resolve()
        if out == batch_path or batch_path in out.parents or out in batch_path.parents:
            raise ValueError('Use a report directory separate from the evidence directory.')
        args.output.mkdir(parents=True, exist_ok=True)
        fields = ['test_id','phase','category','site_id','asset_id','source_position','objective','method','control_refs','expected','observed','result',
                  'technical_interpretation','severity','validation','evidence_file','evidence_pointer','evidence_sha256','timestamp_utc','limitations','reference','manual_validation']
        write_csv(args.output/'Coverage.csv', assets, ['asset_id','site_id','computer_name','status','evidence','note'])
        write_csv(args.output/'Tests.csv', tests, fields)
        write_csv(args.output/'Artifacts.csv', artifacts, ['file','sha256','kind','asset_id'])
        package = {'schema_version':'1.0','tool_version':VERSION,'evidence_kind':'NormalizedAssessmentEvidence',
                   'metadata':meta,'coverage':assets,'tests':tests,'artifacts':artifacts,
                   'downstream_notice':'Suitable as structured input for the approved reporting workflow. Raw evidence, analyst validation and engagement scope remain authoritative.'}
        (args.output/'Evidence.json').write_text(json.dumps(package, indent=2, ensure_ascii=False), encoding='utf-8')
        (args.output/'Summary.html').write_text(render_html(assets, tests, meta), encoding='utf-8')
        hashes=[]
        for f in sorted(args.output.iterdir()):
            if f.is_file() and f.name != 'Manifest.txt': hashes.append(f'{sha256(f)}  {f.name}')
        (args.output/'Manifest.txt').write_text('\n'.join(hashes)+'\n', encoding='utf-8')
        print(f'Normalized evidence written to {args.output}. Human validation remains required.')
        unresolved = any(a['status'] not in ('Complete','Excluded') for a in assets) or any(t['result'] in ('Unknown','Error','Not tested','Inconclusive','Candidate') for t in tests)
        return 3 if unresolved else 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        print(f'Analysis failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
