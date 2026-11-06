# SPDX-License-Identifier: GPL-3.0-or-later
"""Check published pilot evidence without opening a network connection."""
import hashlib
import json
from pathlib import Path
import unittest

from compare import compare


class EvidenceTests(unittest.TestCase):
    def test_published_pilots_reanalyze(self):
        root = Path(__file__).parent / 'results'
        for name in ('loopback-pilot-2026-11-05', 'loopback-pilot-2026-11-05-after-fix',
                     'loopback-pilot-2026-11-06-integrated'):
            with self.subTest(collection=name):
                directory = root / name
                corpus_bytes = (directory / 'corpus.json').read_bytes()
                corpus = json.loads(corpus_bytes)
                saved = json.loads((directory / 'summary.json').read_text())
                actual = compare(corpus)
                # Artifact digests bind collection-time code; feature values
                # must still reproduce if implementation-only code changes.
                for result in (saved, actual):
                    result.pop('analysis_sha256')
                    result.pop('observer_sha256')
                self.assertEqual(saved, actual)
                self.assertEqual(actual['pair_count'], 6)
                ledger = json.loads((directory / 'ledger.json').read_text())
                self.assertEqual(len(ledger), 12)
                self.assertTrue(all(x['status'] == 'passed' for x in ledger))
                provenance = json.loads((directory / 'provenance.json').read_text())
                self.assertEqual(provenance['raw_input_file_sha256'], hashlib.sha256(corpus_bytes).hexdigest())

    def test_integrated_collection_provenance_and_health(self):
        root = Path(__file__).parent
        directory = root / 'results' / 'loopback-pilot-2026-11-06-integrated'
        manifest = json.loads((directory / 'manifest.json').read_text())
        historical = json.loads((root / 'results' / 'loopback-pilot-2026-11-05-after-fix' /
                                 'manifest.json').read_text())
        self.assertEqual(manifest['phantom_sha'], 'f52273b183e7f9f4a99549804b4f43a3ca3e959d')
        self.assertEqual(manifest['stock_sha'], historical['stock_sha'])
        self.assertEqual(manifest['workload'], historical['workload'])
        self.assertEqual(manifest['runner_sha256'], historical['runner_sha256'])
        self.assertEqual(manifest['runner_sha256'], hashlib.sha256((root / 'loopback_pilot.py').read_bytes()).hexdigest())
        for binary in ('stock-client', 'stock-server'):
            self.assertEqual(manifest['binary_hashes'][binary], historical['binary_hashes'][binary])
        ledger = json.loads((directory / 'ledger.json').read_text())
        self.assertEqual(len(ledger), 12)
        for run in ledger:
            self.assertEqual(run['status'], 'passed')
            health = run['health']
            self.assertEqual(health['received'], health['forwarded'])
            self.assertEqual(health['socket_drops'], 0)
            self.assertTrue(health['remote_witness'])
            self.assertEqual(health['client_exit'], 0)


if __name__ == '__main__':
    unittest.main()
