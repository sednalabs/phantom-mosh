# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict passive-view inputs and frozen-threshold scoring, not a trained detector.

Synthetic guard tests are not evidence of fingerprint resistance. Caller
attestations cannot prove honest collection, observation health or independence.
"""
import math
from collections import Counter


class ContractError(ValueError):
    pass


def passive_features(packets):
    if not packets:
        raise ContractError('empty observation is not a privacy result')
    times, lengths, directions = [], [], []
    for packet in packets:
        if set(packet) != {'time_ms', 'udp_payload_bytes', 'direction'}:
            raise ContractError('undeclared observer field or incomplete packet')
        time, size, direction = packet['time_ms'], packet['udp_payload_bytes'], packet['direction']
        if isinstance(time, bool) or not isinstance(time, (float, int)) or not math.isfinite(time) or time < 0:
            raise ContractError('invalid observation timestamp')
        if type(size) is not int or not 0 <= size <= 65507:
            raise ContractError('invalid UDP payload length')
        if type(direction) is not int or direction not in (-1, 1):
            raise ContractError('direction must be observer-defined -1 or +1')
        if times and time < times[-1]:
            raise ContractError('capture must be ordered before feature extraction')
        times.append(float(time)); lengths.append(size); directions.append(direction)
    gaps = [b - a for a, b in zip(times, times[1:])]
    return {
        'packet_count': float(len(packets)),
        'mean_payload_bytes': sum(lengths) / len(lengths),
        'max_payload_bytes': float(max(lengths)),
        'direction_balance': sum(directions) / len(directions),
        'direction_runs': float(1 + sum(a != b for a, b in zip(directions, directions[1:]))),
        'duration_ms': times[-1] - times[0],
        'mean_gap_ms': sum(gaps) / len(gaps) if gaps else 0.0,
        'max_gap_ms': max(gaps, default=0.0),
    }


def validate_partition(rows, held_out='session'):
    """Evaluator-only grouping: always disjoint whole sessions plus chosen domain."""
    if held_out not in {'session', 'domain', 'workload', 'collection'}:
        raise ContractError('unknown challenge axis')
    seen = {'session': {}, held_out: {}}
    counts = Counter()
    for row in rows:
        split = row.get('split')
        if split not in {'train', 'validation', 'test'}:
            raise ContractError('invalid split')
        counts[split] += 1
        for axis, assignments in seen.items():
            group = row.get(axis)
            if not isinstance(group, str) or not group:
                raise ContractError('missing evaluator grouping identity')
            previous = assignments.setdefault(group, split)
            if previous != split:
                raise ContractError('group leaks across partitions: ' + axis)
    if any(counts[split] == 0 for split in ('train', 'validation', 'test')):
        raise ContractError('train, validation and untouched test partitions required')


def wilson(successes, trials):
    """95% descriptive Wilson interval. Clustered windows are NOT independent trials."""
    if trials <= 0 or not 0 <= successes <= trials:
        raise ContractError('invalid binomial counts')
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return [max(0.0, centre - radius), min(1.0, centre + radius)]


def score_fixed_threshold(scores, labels, *, threshold, threshold_frozen_before_test,
                          observation_ok, sessions_functioning, independent_units):
    flags = (threshold_frozen_before_test, observation_ok, sessions_functioning, independent_units)
    if any(flag is not True for flag in flags):
        raise ContractError('invalid observation, unsealed threshold or dependent evaluation units')
    if not scores or len(scores) != len(labels):
        raise ContractError('missing or mismatched outcomes')
    if isinstance(threshold, bool) or not isinstance(threshold, (float, int)) or not math.isfinite(threshold):
        raise ContractError('invalid threshold')
    for score, label in zip(scores, labels):
        if type(label) is not bool or isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score):
            raise ContractError('invalid score or label')
    positives = sum(labels); negatives = len(labels) - positives
    if not positives or not negatives:
        raise ContractError('target and realistic background samples are both required')
    tp = sum(score >= threshold and label for score, label in zip(scores, labels))
    fp = sum(score >= threshold and not label for score, label in zip(scores, labels))
    return {
        'threshold': threshold, 'positive_units': positives, 'negative_units': negatives,
        'true_positives': tp, 'false_positives': fp, 'tpr': tp / positives, 'fpr': fp / negatives,
        'tpr_wilson_95': wilson(tp, positives), 'fpr_wilson_95': wilson(fp, negatives),
        'claim': 'descriptive counts only; no automatic privacy acceptance',
    }
