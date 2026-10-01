#!/usr/bin/env python3
"""Regenerate Manifest.txt for a derived output folder.

Usage: python Code/SealDerived.py <derived dir>

Analyze.py writes a Manifest.txt covering the files it produced. Later steps
(ToFindings.py's findings.json, completed review and disposition files copied
in by the analyst) are not covered until the folder is sealed again. This tool
rewrites Manifest.txt so it names every regular top-level file now present,
in the same "sha256  name" form Code/VerifyManifest.py checks.

It refuses to run on a raw collection batch (a folder holding Batch.json).
Raw evidence is sealed by the collector at collection time; re-sealing it here
would silently legitimise any later edit to the evidence.
"""
from __future__ import annotations
import hashlib
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def seal(derived_dir) -> list[str]:
    """Write Manifest.txt for the folder and return the file names it covers.
    Raises ValueError for a missing folder or a raw batch folder."""
    folder = Path(derived_dir).resolve()
    if not folder.is_dir():
        raise ValueError('Derived folder does not exist: %s' % folder)
    if (folder / 'Batch.json').exists():
        raise ValueError('Refusing to seal %s: it holds Batch.json, so it is a raw collection batch. '
                         'Raw batches are sealed by the collector and are never re-sealed here.' % folder)
    names = []
    lines = []
    for item in sorted(folder.iterdir()):
        if not item.is_file() or item.is_symlink() or item.name == 'Manifest.txt':
            continue
        lines.append('%s  %s' % (sha256(item), item.name))
        names.append(item.name)
    if not names:
        raise ValueError('Nothing to seal: %s holds no regular files.' % folder)
    (folder / 'Manifest.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return names


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print('Usage: python Code/SealDerived.py <derived dir>', file=sys.stderr)
        return 2
    try:
        names = seal(argv[0])
    except (ValueError, OSError) as exc:
        print('Seal failed: %s' % exc, file=sys.stderr)
        return 2
    print('Manifest.txt written for %s: %d files sealed (%s)' % (argv[0], len(names), ', '.join(names)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
