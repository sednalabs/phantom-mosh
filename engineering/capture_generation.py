#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record the actual checkout, not an assumed PR-head test generation."""
import json
import os
from pathlib import Path
import subprocess
import sys


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: capture_generation.py OUTPUT.json')
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    pr = event.get('pull_request', {})
    checkout = git('rev-parse', 'HEAD')
    head = pr.get('head', {}).get('sha')
    merge = pr.get('merge_commit_sha')
    record = {
        'schema': 'phantom-ci-generation-v1',
        'repository': os.environ.get('GITHUB_REPOSITORY'),
        'run_id': os.environ.get('GITHUB_RUN_ID'),
        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'event': os.environ.get('GITHUB_EVENT_NAME'),
        'host_event_sha': os.environ.get('GITHUB_SHA'),
        'checkout_sha': checkout,
        'checkout_tree_sha': git('rev-parse', 'HEAD^{tree}'),
        'checkout_parent_shas': git('show', '-s', '--format=%P', 'HEAD').split(),
        'pr_head_sha': head,
        'pr_base_sha': pr.get('base', {}).get('sha'),
        'pr_merge_sha_at_event': merge,
        'generation_kind': 'pr_head' if head == checkout else 'synthetic_merge' if merge == checkout else 'other_or_push',
        'workflow_blob': git('rev-parse', 'HEAD:.github/workflows/phantom-record.yml'),
        'tracked_tree_clean': not bool(git('diff', '--name-only', 'HEAD')),
    }
    if not record['tracked_tree_clean']:
        raise SystemExit('refusing test-generation evidence for a dirty tracked tree')
    out = Path(sys.argv[1]); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
