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
        for name in ('loopback-pilot-2026-11-05', 'loopback-pilot-2026-11-05-after-fix'):
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


if __name__ == '__main__':
    unittest.main()
