#!/usr/bin/env python3
"""Verify a SHA-256 Manifest.txt without modifying evidence."""
from pathlib import Path
import argparse,hashlib,re,sys
RX=re.compile(r"^([0-9a-fA-F]{64})  ([^/\\]+)$")
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('directory');a=ap.parse_args();raw=Path(a.directory)
    if not raw.is_dir() or raw.is_symlink(): print('Evidence directory missing, not a directory, or is a symlink',file=sys.stderr);return 2
    d=raw.resolve();m=d/'Manifest.txt'
    if not m.is_file() or m.is_symlink(): print('Manifest.txt missing or invalid',file=sys.stderr);return 2
    bad=0; seen=set()
    for n,line in enumerate(m.read_text(encoding='utf-8-sig').splitlines(),1):
        if not line.strip(): continue
        x=RX.match(line)
        if not x: print(f'line {n}: malformed');bad+=1;continue
        expected,name=x.groups()
        if name in seen: print(f'{name}: duplicate');bad+=1;continue
        seen.add(name);p=d/name
        if not p.is_file() or p.is_symlink(): print(f'{name}: MISSING OR INVALID');bad+=1;continue
        actual=sha(p)
        if actual.lower()!=expected.lower(): print(f'{name}: HASH MISMATCH');bad+=1
        else: print(f'{name}: OK')
    if not seen: print('Manifest contains no evidence entries'); bad+=1
    actual_files={p.name for p in d.iterdir() if p.is_file() and not p.is_symlink() and p.name!='Manifest.txt'}
    extras=sorted(actual_files-seen)
    for name in extras: print(f'{name}: UNMANIFESTED'); bad+=1
    return 1 if bad else 0
if __name__=='__main__': raise SystemExit(main())
