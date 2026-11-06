# SPDX-License-Identifier: GPL-3.0-or-later
"""Matched passive metadata summaries, NOT a classifier or privacy acceptance gate."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

from observer import ContractError, passive_features

MATCH_FIELDS = ('pair_id', 'workload_sha256', 'network_profile',
                'acquisition_profile', 'observation_duration_ms', 'evidence_kind')
FIELDS = {'schema', 'implementation', 'session_id', 'build_sha', 'binary_sha256',
          'observation_ok', 'session_functioning', 'capture_dropped_packets',
          'packets', *MATCH_FIELDS}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def validate(run):
    if not isinstance(run, dict) or set(run) != FIELDS:
        raise ContractError('unexpected or missing run fields')
    if run['schema'] != 'phantom-matched-run-01':
        raise ContractError('unknown run schema')
    if run['implementation'] not in ('stock-mosh', 'phantom-draft-01'):
        raise ContractError('unknown implementation')
    if run['evidence_kind'] not in ('synthetic', 'real-terminal-capture'):
        raise ContractError('unknown evidence kind')
    for field in ('session_id', 'pair_id', 'network_profile', 'acquisition_profile'):
        if not isinstance(run[field], str) or not run[field].strip():
            raise ContractError('missing identity: ' + field)
    for field, length in (('build_sha', 40), ('binary_sha256', 64), ('workload_sha256', 64)):
        if not isinstance(run[field], str) or not re.fullmatch('[0-9a-f]{%d}' % length, run[field]):
            raise ContractError('invalid digest: ' + field)
    if run['observation_ok'] is not True or run['session_functioning'] is not True:
        raise ContractError('failed observation/session must be reported, not scored')
    if type(run['capture_dropped_packets']) is not int or run['capture_dropped_packets'] != 0:
        raise ContractError('unknown or nonzero capture drops')
    duration = run['observation_duration_ms']
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
        raise ContractError('invalid observation window')
    if not isinstance(run['packets'], list) or any(not isinstance(p, dict) for p in run['packets']):
        raise ContractError('packets must be an array of objects')
    features = passive_features(run['packets'])
    if run['packets'][-1]['time_ms'] > duration:
        raise ContractError('packet outside declared relative observation window')
    # Denominators use the collection window, not first/last packet timestamps.
    features['packets_per_second'] = len(run['packets']) * 1000 / duration
    features['udp_payload_bytes_total'] = sum(p['udp_payload_bytes'] for p in run['packets'])
    features['udp_payload_bytes_per_second'] = features['udp_payload_bytes_total'] * 1000 / duration
    return features


def compare(runs):
    if not isinstance(runs, list) or not runs:
        raise ContractError('at least one matched pair required')
    pairs, sessions, builds, kinds = {}, set(), {}, set()
    for run in runs:
        features = validate(run)
        identity = run['session_id']
        if identity in sessions:
            raise ContractError('session reused; independent sessions required')
        sessions.add(identity)
        implementation = run['implementation']
        build = (run['build_sha'], run['binary_sha256'])
        if builds.setdefault(implementation, build) != build:
            raise ContractError('build changed within comparison')
        kinds.add(run['evidence_kind'])
        pair = pairs.setdefault(run['pair_id'], {})
        if implementation in pair:
            raise ContractError('duplicate implementation in pair')
        pair[implementation] = (run, features)
    if len(kinds) != 1:
        raise ContractError('cannot mix synthetic and empirical evidence')
    results = []
    for pair_id, pair in sorted(pairs.items()):
        if set(pair) != {'stock-mosh', 'phantom-draft-01'}:
            raise ContractError('unmatched pair: ' + pair_id)
        stock, stock_features = pair['stock-mosh']
        phantom, phantom_features = pair['phantom-draft-01']
        if any(stock[field] != phantom[field] for field in MATCH_FIELDS):
            raise ContractError('unmatched collection conditions: ' + pair_id)
        results.append({'pair_id': pair_id, 'stock': stock_features, 'phantom': phantom_features,
                        'phantom_minus_stock': {k: phantom_features[k] - stock_features[k]
                                                for k in stock_features}})
    return {'schema': 'phantom-matched-summary-01', 'evidence_kind': kinds.pop(),
            'pair_count': len(results), 'corpus_digest': digest(runs),
            'analysis_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'observer_sha256': hashlib.sha256(Path(__file__).with_name('observer.py').read_bytes()).hexdigest(),
            'builds': {k: {'build_sha': v[0], 'binary_sha256': v[1]} for k, v in builds.items()},
            'pairs': results,
            'mean_paired_difference': {k: statistics.mean(p['phantom_minus_stock'][k] for p in results)
                                       for k in results[0]['stock']},
            'claim': 'Descriptive paired metadata only. No identification, activity, linkage, or privacy result. Health and independence are collector attestations.'}


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path, help='JSON array of matched normalized runs')
    args = parser.parse_args()
    try:
        raw = args.corpus.read_bytes()
        report = compare(json.loads(raw, object_pairs_hook=reject_duplicate_keys))
        report['input_file_sha256'] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(2, 'comparison rejected: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
