import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'Code' / 'VerifyManifest.py'

class ManifestTests(unittest.TestCase):
    def test_empty_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'Manifest.txt').write_text('')
            result = subprocess.run([sys.executable, str(TOOL), td], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_valid_then_tampered(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); data = b'synthetic evidence'
            (root / 'proof.txt').write_bytes(data)
            (root / 'Manifest.txt').write_text(hashlib.sha256(data).hexdigest() + '  proof.txt\n')
            self.assertEqual(subprocess.run([sys.executable, str(TOOL), td], capture_output=True).returncode, 0)
            (root / 'proof.txt').write_bytes(b'changed')
            self.assertNotEqual(subprocess.run([sys.executable, str(TOOL), td], capture_output=True).returncode, 0)
