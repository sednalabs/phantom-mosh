#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject runner selections outside the reviewed free-public-repository set.

Requires PyYAML. This source check is a review guard, not an account spending
control: changing this check or another workflow can bypass it.
"""
from pathlib import Path
import re
import sys
import yaml

# Standard images only. Do not add large/xlarge, groups or organization runners.
# https://docs.github.com/en/actions/reference/runners/github-hosted-runners
ALLOWED = frozenset({'ubuntu-latest', 'ubuntu-22.04', 'ubuntu-24.04',
                     'macos-15', 'macos-15-intel'})
MATRIX = re.compile(r'\$\{\{\s*matrix\.([a-zA-Z_][a-zA-Z_0-9]*)\s*\}\}')


class RunnerError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, int, bool)) or key in result:
            raise RunnerError('duplicate or non-scalar YAML key')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def labels_for(job):
    if not isinstance(job, dict) or 'uses' in job:
        raise RunnerError('reusable job requires a separate audited runner contract')
    runner = job.get('runs-on')
    if isinstance(runner, str) and runner in ALLOWED:
        return {runner}
    match = MATRIX.fullmatch(runner) if isinstance(runner, str) else None
    if not match:
        raise RunnerError('runner must be an allowed literal or an explicit static matrix axis')
    axis = match.group(1)
    strategy = job.get('strategy', {})
    matrix = strategy.get('matrix') if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        raise RunnerError('dynamic runner matrix is not allowed')
    values = matrix.get(axis, [])
    includes = matrix.get('include', [])
    if not isinstance(values, list) or not isinstance(includes, list):
        raise RunnerError('runner axis and matrix include must be static arrays')
    candidates = list(values)
    for row in includes:
        if not isinstance(row, dict) or (not values and axis not in row):
            raise RunnerError('incomplete runner selection in matrix include')
        if axis in row:
            candidates.append(row[axis])
    if not candidates or any(not isinstance(v, str) or v not in ALLOWED for v in candidates):
        raise RunnerError('matrix can select an unapproved runner')
    return set(candidates)


def validate(text):
    workflow = yaml.load(text, Loader=UniqueLoader)
    jobs = workflow.get('jobs') if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict) or not jobs:
        raise RunnerError('workflow has no explicit jobs')
    return {name: labels_for(job) for name, job in jobs.items()}


def main():
    directory = Path(sys.argv[1] if len(sys.argv) == 2 else '.github/workflows')
    files = sorted(directory.glob('*.yml')) + sorted(directory.glob('*.yaml'))
    if not files:
        raise RunnerError('no workflow files found')
    for path in files:
        try:
            jobs = validate(path.read_text())
        except (RunnerError, yaml.YAMLError) as error:
            raise RunnerError(f'{path}: {error}') from error
        for job, labels in jobs.items():
            print(f'{path.name}:{job}: {", ".join(sorted(labels))}')
    print(f'PASS free public runner policy: {len(files)} workflows')


if __name__ == '__main__':
    try:
        main()
    except RunnerError as error:
        raise SystemExit(str(error))
