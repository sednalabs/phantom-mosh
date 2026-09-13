#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

DRIVER = str(Path(sys.argv.pop(1)).resolve())
FAKE = str(Path(__file__).with_name('fake_ssh.py').resolve())
KEY = b'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='phantom-ssh-')
        self.root = Path(self.temp.name)
        self.record = self.root / 'record.json'
        self.env = dict(os.environ, PHANTOM_TEST_RECORD=str(self.record))

    def tearDown(self):
        self.temp.cleanup()

    def command(self, case='success', timeout=1000, ssh=FAKE, server="/tmp/a server'; echo BAD; '", cancel=-1):
        return [DRIVER, ssh, case, server, '', str(timeout), str(cancel), 'no-udp']

    def run_case(self, case, expected=1, **kw):
        start = time.monotonic()
        result = subprocess.run(self.command(case, **kw), env=self.env, capture_output=True, timeout=4)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(result.returncode, expected, result.stderr.decode())
        self.assertNotIn(KEY, result.stdout + result.stderr)
        if self.record.exists():
            record = json.loads(self.record.read_text())
            self.assertFalse(Path('/proc', str(record['pid'])).exists(), 'SSH child not reaped')
            if 'descendant' in record:
                # A killed grandchild may await init reaping. It must not run.
                for _ in range(50):
                    path = Path('/proc', str(record['descendant']), 'stat')
                    if not path.exists() or path.read_text().split(') ')[1].startswith('Z'):
                        break
                    time.sleep(0.01)
                else:
                    self.fail('SSH descendant survived cleanup')
        return result

    def test_success_and_stderr_redaction(self):
        for case in ('success', 'fragmented', 'stderr', 'orphan-success'):
            with self.subTest(case=case):
                self.run_case(case, expected=0)

    def test_failures_after_or_before_valid_output(self):
        for case in ('nonzero', 'signalled', 'empty', 'malformed', 'delayed-trailer', 'flood',
                     'eof-stall', 'stall', 'trickle', 'descendant'):
            with self.subTest(case=case):
                self.run_case(case)

    def test_configuration_and_option_injection(self):
        for case in ('-oProxyCommand=oops', 'host;whoami', 'user\nhost', 'host name', ''):
            with self.subTest(case=case):
                self.run_case(case)
                self.assertFalse(self.record.exists())
        self.run_case('success', ssh='/does/not/exist')
        self.assertFalse(self.record.exists())
        for timeout in (0, 120001, -1):
            self.run_case('success', timeout=timeout)
        self.run_case('success', server='-bad')
        self.assertFalse(self.record.exists())

    def test_command_quoting_and_noninteractive_policy(self):
        path = "/tmp/a server'; echo BAD; '"
        self.run_case('success', expected=0, server=path)
        args = json.loads(self.record.read_text())['argv']
        self.assertEqual(shlex.split(args[-1]), ['exec', path, '--startup-profile', 'phantom-mosh/v3/draft-01'])
        for flag in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'ControlMaster=no',
                     'ClearAllForwardings=yes', 'PermitLocalCommand=no', 'ForwardAgent=no',
                     'ForwardX11=no', 'ForkAfterAuthentication=no', 'RemoteCommand=none'):
            self.assertIn(flag, args)

    def test_unrelated_descriptors_not_inherited(self):
        marker = self.root / 'sensitive-handle'
        with marker.open('w') as handle:
            result = subprocess.run(self.command(), env=self.env, pass_fds=(handle.fileno(),),
                                    capture_output=True, timeout=4)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(str(marker), json.loads(self.record.read_text())['fds'])

    def test_cancellation_and_borrowed_descriptor(self):
        for before in (False, True):
            with self.subTest(before=before):
                self.record.unlink(missing_ok=True)
                reader, writer = os.pipe()
                try:
                    if before:
                        os.write(writer, b'cancel')
                    child = subprocess.Popen(self.command('stall', timeout=2000, cancel=reader),
                                             env=self.env, pass_fds=(reader,), stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
                    if not before:
                        for _ in range(100):
                            if self.record.exists():
                                break
                            time.sleep(0.01)
                        self.assertTrue(self.record.exists())
                        os.write(writer, b'cancel')
                    out, err = child.communicate(timeout=3)
                    self.assertEqual(child.returncode, 1, err.decode())
                    self.assertIn(b'cancelled', err)
                    self.assertEqual(os.read(reader, 6), b'cancel')
                    if before:
                        self.assertFalse(self.record.exists())
                    else:
                        pid = json.loads(self.record.read_text())['pid']
                        self.assertFalse(Path('/proc', str(pid)).exists())
                finally:
                    os.close(reader); os.close(writer)
                    if 'child' in locals() and child.poll() is None:
                        child.kill(); child.wait()

    def test_interrupted_waits_and_closed_standard_input(self):
        self.env['PHANTOM_TEST_INTERRUPTS'] = '1'
        self.run_case('success', expected=0)
        self.run_case('stall')
        self.env.pop('PHANTOM_TEST_INTERRUPTS')
        self.env['PHANTOM_TEST_CLOSED_STDIN'] = '1'
        self.run_case('success', expected=0)

    def test_auto_reaping_is_rejected(self):
        self.env['PHANTOM_TEST_IGNORE_SIGCHLD'] = '1'
        self.run_case('success')
        self.assertFalse(self.record.exists())


if __name__ == '__main__':
    unittest.main()
