# SPDX-License-Identifier: GPL-3.0-or-later
import unittest
from observer import ContractError, passive_features, score_fixed_threshold, validate_partition


class ObserverTests(unittest.TestCase):
    def packets(self):
        return [{'time_ms': 10, 'udp_payload_bytes': 40, 'direction': 1},
                {'time_ms': 20, 'udp_payload_bytes': 80, 'direction': -1}]

    def test_observable_features(self):
        features = passive_features(self.packets())
        self.assertEqual(features['mean_payload_bytes'], 60)
        self.assertEqual(features['direction_runs'], 2)
        shifted = self.packets()
        for row in shifted:
            row['time_ms'] += 9999
        self.assertEqual(features, passive_features(shifted))

    def test_privileged_fields_rejected(self):
        for name in ('session_id', 'rtt', 'epoch', 'ack_epoch', 'moshwatch_pid', 'label', 'migration_truth', 'capture_host'):
            rows = self.packets(); rows[0][name] = 1
            with self.assertRaises(ContractError):
                passive_features(rows)

    def test_incomplete_or_bad_capture(self):
        for rows in ([], list(reversed(self.packets())), [{'time_ms': 0}]):
            with self.assertRaises(ContractError):
                passive_features(rows)
        for field, value in (('time_ms', float('nan')), ('direction', True), ('udp_payload_bytes', -1)):
            rows = self.packets(); rows[0][field] = value
            with self.assertRaises(ContractError):
                passive_features(rows)

    def partition(self):
        return [{'split': split, 'session': 's' + str(i), 'domain': 'd' + str(i)}
                for i, split in enumerate(('train', 'validation', 'test'))]

    def test_whole_session_and_domain_holdout(self):
        validate_partition(self.partition(), 'domain')
        for axis in ('session', 'domain'):
            rows = self.partition(); rows[2][axis] = rows[0][axis]
            with self.assertRaises(ContractError):
                validate_partition(rows, 'domain')

    def score(self, **overrides):
        flags = dict(threshold=0.5, threshold_frozen_before_test=True,
                     observation_ok=True, sessions_functioning=True, independent_units=True)
        flags.update(overrides)
        return score_fixed_threshold([0.9, 0.2, 0.8, 0.1], [True, True, False, False], **flags)

    def test_counts_and_uncertainty(self):
        result = self.score()
        self.assertEqual(result['tpr'], 0.5); self.assertEqual(result['fpr'], 0.5)
        self.assertLess(result['fpr_wilson_95'][0], 0.5); self.assertGreater(result['fpr_wilson_95'][1], 0.5)
        self.assertIn('no automatic', result['claim'])

    def test_invalid_observation_is_not_a_win(self):
        for flag in ('threshold_frozen_before_test', 'observation_ok', 'sessions_functioning', 'independent_units'):
            with self.assertRaises(ContractError):
                self.score(**{flag: False})
        with self.assertRaises(ContractError):
            self.score(threshold=float('inf'))


if __name__ == '__main__':
    unittest.main()
