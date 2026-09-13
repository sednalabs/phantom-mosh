# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from check_runners import ALLOWED, RunnerError, validate


class RunnerTests(unittest.TestCase):
    def test_literals(self):
        for label in ALLOWED:
            self.assertEqual(validate('jobs:\n  test:\n    runs-on: ' + label)['test'], {label})

    def test_static_matrix_including_extra_rows(self):
        text = '''jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-15]
        include:
          - {os: macos-15-intel, crypto: auto}
'''
        self.assertEqual(validate(text)['test'], {'ubuntu-24.04', 'macos-15', 'macos-15-intel'})
        with self.assertRaises(RunnerError):
            validate(text.replace('macos-15-intel', 'macos-15-large'))

    def test_disallowed_runner_forms(self):
        for value in ('self-hosted', 'macos-15-large', 'macos-15-xlarge', 'ubuntu-16core', 'macos-12',
                      '[self-hosted, linux]', '{group: paid, labels: ubuntu-24.04}',
                      '${{ inputs.runner }}', '${{ vars.RUNNER }}', '${{ matrix.os || "ubuntu-24.04" }}'):
            with self.subTest(value=value), self.assertRaises(RunnerError):
                validate('jobs:\n  test:\n    runs-on: ' + value)

    def test_dynamic_and_incomplete_matrices(self):
        for value in ('${{ fromJSON(needs.setup.outputs.matrix) }}',
                      '{include: [{compiler: gcc}]}', '{os: [macos-15-xlarge]}'):
            with self.assertRaises(RunnerError):
                validate('jobs:\n  test:\n    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix: ' + value)

    def test_duplicate_keys_and_reusable_jobs_rejected(self):
        for text in ('jobs: {test: {runs-on: ubuntu-24.04, runs-on: paid}}',
                     'jobs: {test: {uses: other/repo/.github/workflows/build.yml@main}}',
                     'jobs: {}'):
            with self.assertRaises(RunnerError):
                validate(text)


if __name__ == '__main__':
    unittest.main()
