# SPDX-License-Identifier: GPL-3.0-or-later
import copy
import json
import unittest

from compare import compare, reject_duplicate_keys
from observer import ContractError


def corpus():
    base = dict(schema='phantom-matched-run-01', implementation='stock-mosh',
                session_id='stock-1', pair_id='pair-1', build_sha='a' * 40,
                binary_sha256='b' * 64, workload_sha256='c' * 64,
                network_profile='loopback-no-impairment', acquisition_profile='fixture-v1',
                observation_duration_ms=1000, evidence_kind='synthetic',
                observation_ok=True, session_functioning=True, capture_dropped_packets=0,
                packets=[dict(time_ms=100, udp_payload_bytes=50, direction=1),
                         dict(time_ms=500, udp_payload_bytes=100, direction=-1)])
    candidate = copy.deepcopy(base)
    candidate.update(implementation='phantom-draft-01', session_id='phantom-1', build_sha='d' * 40)
    return [base, candidate]


class ComparisonTests(unittest.TestCase):
    def test_equal_runs_and_fixed_window(self):
        report = compare(corpus())
        self.assertEqual(report['pair_count'], 1)
        self.assertEqual(report['pairs'][0]['stock']['packets_per_second'], 2)
        self.assertEqual(report['pairs'][0]['stock']['udp_payload_bytes_per_second'], 150)
        self.assertEqual(set(report['mean_paired_difference'].values()), {0})
        self.assertEqual(report['evidence_kind'], 'synthetic')

    def test_delta(self):
        runs = corpus()
        runs[1]['packets'][0]['udp_payload_bytes'] += 20
        self.assertEqual(compare(runs)['mean_paired_difference']['mean_payload_bytes'], 10)

    def test_reject_invalid(self):
        changes = [('observation_ok', False), ('observation_ok', 1),
                   ('session_functioning', False), ('capture_dropped_packets', 1),
                   ('capture_dropped_packets', False), ('capture_dropped_packets', None),
                   ('observation_duration_ms', 0), ('observation_duration_ms', float('nan')),
                   ('observation_duration_ms', True), ('observation_duration_ms', 200),
                   ('build_sha', 'master'), ('packets', []), ('packets', [None]),
                   ('packets', [{'time_ms': 0, 'udp_payload_bytes': 1, 'direction': 1, 'label': True}]),
                   ('network_profile', 'different'), ('workload_sha256', 'd' * 64),
                   ('evidence_kind', 'real-terminal-capture'), ('session_id', 'stock-1')]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                runs = corpus()
                runs[1][field] = value
                with self.assertRaises(ContractError):
                    compare(runs)

    def test_unmatched_duplicate_and_unknown_field(self):
        for runs in ([], corpus()[:1], corpus() + corpus()):
            with self.assertRaises(ContractError):
                compare(runs)
        runs = corpus()
        runs[0]['label'] = 'secret'
        with self.assertRaises(ContractError):
            compare(runs)

    def test_multiple_pairs_and_build_drift(self):
        runs = corpus()
        other = corpus()
        for run in other:
            run['pair_id'] = 'pair-2'
            run['session_id'] += '-2'
        self.assertEqual(compare(runs + other)['pair_count'], 2)
        other[0]['build_sha'] = 'e' * 40
        with self.assertRaises(ContractError):
            compare(runs + other)

    def test_duplicate_json_keys(self):
        with self.assertRaises(ContractError):
            json.loads('{"a": 1, "a": 2}', object_pairs_hook=reject_duplicate_keys)


if __name__ == '__main__':
    unittest.main()
