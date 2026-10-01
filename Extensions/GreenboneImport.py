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
THREATS = {'critical', 'high', 'medium', 'low', 'log', 'false positive', 'alarm', 'debug', ''}
ACTIONABLE_THREATS = ('critical', 'high', 'medium', 'low', 'alarm')

# Heuristic only. Greenbone has no single "credentialed" flag in the report XML, so the
# importer looks for the well-known login-status NVT names. A match sets the indicator;
# no match leaves it null (unknown). The analyst confirms from the task's credential
# configuration before relying on it.
CREDENTIALED_SUCCESS_MARKERS = ('smb log-in', 'smb login', 'ssh login', 'ssh log-in', 'login successful', 'log-in successful')
CREDENTIALED_FAILURE_MARKERS = ('login failed', 'log-in failed', 'could not log in', 'could not login', 'authentication failed')


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def _text(el, tag):
    if el is None:
        return ''
    c = el.find(tag)
    return (c.text or '').strip() if c is not None and c.text else ''


def locate_report(root):
    """Return the <report> element or raise if the document is not a GVM report.

    Accepts a bare <report> root or a <get_reports_response> wrapping one. GVM exports
    often nest a second <report> inside the outer one; the innermost report that holds
    <results> or <result_count> is used. Any other document is rejected so that an
    unrelated XML file can never yield a successful zero-result import.
    """
    tag = (root.tag or '').split('}')[-1]
    if tag == 'get_reports_response':
        candidate = root.find('report')
    elif tag == 'report':
        candidate = root
    else:
        raise ValueError(f'Not a Greenbone/GVM report: root element is <{tag}>, expected <report> or <get_reports_response>.')
    if candidate is None:
        raise ValueError('Not a Greenbone/GVM report: <get_reports_response> holds no <report>.')
    inner = candidate.find('report')
    if inner is not None and (inner.find('results') is not None or inner.find('result_count') is not None):
        candidate = inner
    if candidate.find('results') is None and candidate.find('result_count') is None:
        raise ValueError('Not a Greenbone/GVM report: no <results> or <result_count> under <report>.')
    return candidate


def scan_status(report, task):
    """Scan completeness fields, read from report/scan_run_status or task/status."""
    status = _text(report, 'scan_run_status') or _text(task, 'status')
    progress = _text(task, 'progress') or _text(report, 'task/progress')
    return {
        'scan_run_status': status or None,
        'scan_start': _text(report, 'scan_start') or None,
        'scan_end': _text(report, 'scan_end') or None,
        'progress': progress or None,
        'task_name': _text(task, 'name') or None,
        'hosts_count': _text(report, 'hosts/count') or None,
        'result_count_full': _text(report, 'result_count/full') or None,
        'result_count_filtered': _text(report, 'result_count/filtered') or None,
        'filter_text': _text(report, 'filters/term') or None,
    }


INCOMPLETE_STATUSES = ('running', 'requested', 'queued', 'stopped', 'interrupted')


def completion_state(status):
    """Tri-state scan completeness: (True|False|None, basis text).

    True only when scan_run_status is Done AND scan_end is present. False when the
    task is Running/Requested/Queued/Stopped/Interrupted. None when the status or
    the end time is absent (or the status is not a recognised state): the export
    does not say whether the scan finished, and that must never read as True.
    """
    raw = status.get('scan_run_status')
    state = (raw or '').strip().lower()
    end = status.get('scan_end')
    if state == 'done' and end:
        return True, 'scan_run_status Done and scan_end %s present' % end
    if state in INCOMPLETE_STATUSES:
        progress = status.get('progress')
        return False, 'scan_run_status %s at %s percent; the export was taken before the task completed' % (
            raw, progress if progress is not None else 'unknown')
    if state == 'done':
        return None, 'scan_run_status Done but no scan_end is recorded, so completion cannot be confirmed'
    if not state:
        return None, 'no scan_run_status or task status in the export'
    return None, 'scan_run_status %s is not a recognised terminal state' % raw


def credentialed_indicator(names):
    """Heuristic: true if a login-success NVT is present, false if a login-failure NVT is
    present (and no success), null when neither appears. Documented as heuristic."""
    success = failure = False
    for name in names:
        low = (name or '').lower()
        if any(m in low for m in CREDENTIALED_FAILURE_MARKERS):
            failure = True
        elif any(m in low for m in CREDENTIALED_SUCCESS_MARKERS):
            success = True
    if success:
        return True
    if failure:
        return False
    return None


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
        report = locate_report(root)
        task = report.find('task')
        status = scan_status(report, task)
        # results sit at report/results/result; fall back to any <result> under the report
        results = report.findall('results/result') or report.findall('.//results/result') or report.findall('.//result')
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
            qod = _text(r, 'qod/value')
            record = {
                'host': host, 'port': port, 'name': name, 'threat': threat,
                'severity_cvss': severity or cvss, 'nvt_oid': oid,
                'cves': sorted(set(cves)),
                'actionable': tl in ACTIONABLE_THREATS,
            }
            if qod:
                record['qod'] = qod
            obs.append(record)
        limitations = [
            'Network vulnerability scanner output from one scanning position; an open detection is not a confirmed exploited vulnerability.',
            'Greenbone/GVM feed currency and scan configuration determine coverage; false positives and false negatives are possible.',
            'No exploitation was performed and the scanner severity is not adopted as assessor-assigned severity.',
        ]
        scan_complete, basis = completion_state(status)
        if scan_complete is False:
            limitations.append('scan export taken before the task completed; status %s at %s percent'
                               % (status['scan_run_status'], status['progress'] if status['progress'] is not None else 'unknown'))
        elif scan_complete is None:
            limitations.append('scan completion not established: %s; results must not be treated as full coverage' % basis)
        doc = {
            'schema_version': '1.0', 'tool_version': VERSION, 'evidence_kind': 'GreenboneObservations',
            'engagement_id': args.engagement, 'source_site_id': args.source_site,
            'source_position': args.source_position, 'completed_utc': datetime.now(timezone.utc).isoformat(),
            'input_file': args.input.name, 'input_sha256': sha256(args.input),
            'scan_complete': scan_complete,
            'scan_completion_basis': basis,
            'credentialed_indicator': credentialed_indicator([o['name'] for o in obs]),
            'credentialed_indicator_note': ('Heuristic: derived from login-status NVT names in the results (true = a login-success '
                                            'NVT is present, false = a login-failure NVT is present, null = neither). Confirm '
                                            'against the task credential configuration before relying on it.'),
            'result_count': len(obs), 'observations': obs,
            'limitations': limitations,
        }
        doc.update(status)
        args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding='utf-8')
        by = {}
        for o in obs:
            by[o['threat'] or 'None'] = by.get(o['threat'] or 'None', 0) + 1
        print(f'Wrote {args.output} : {len(obs)} results {by} scan_run_status={status["scan_run_status"]} scan_complete={scan_complete}')
        return 0
    except (ValueError, OSError, ET.ParseError) as exc:
        print(f'Import failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
