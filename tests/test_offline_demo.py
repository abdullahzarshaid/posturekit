import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class OfflineDemoTests(unittest.TestCase):
    def test_demo_and_overwrite_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'demo'
            command = [sys.executable, str(ROOT / 'examples' / 'offline_demo.py'), '--output', str(output)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn('DEMO-UNKNOWN   Unknown', first.stdout)
            report = output / 'report' / 'Evidence.json'
            before = report.read_bytes()
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(before, report.read_bytes())


if __name__ == '__main__':
    unittest.main()
