#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the new supervisor profile with a simulated SSH executable.

These cases validate process/decoder composition, NOT SSH authentication.
"""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from session_process_test import children, check, reap


def main():
    server, driver = (str(Path(p).resolve()) for p in sys.argv[1:3])
    check(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'test subreaper unavailable')
    try:
        with tempfile.TemporaryDirectory(prefix='phantom-session-supervisor-') as temp:
            fake = Path(temp) / 'ssh-fixture'
            fake.write_text('''#!''' + sys.executable + '''
import os, shlex, subprocess, sys
command = shlex.split(sys.argv[-1])
if command != ['exec', ''' + repr(server) + ''', '--session-profile', 'phantom-mosh/session/draft-01']:
    sys.exit(91)
if 'StrictHostKeyChecking=yes' not in sys.argv or 'BatchMode=yes' not in sys.argv:
    sys.exit(92)
env = dict(os.environ, SSH_CONNECTION='127.0.0.1 45000 127.0.0.1 22')
mode = os.environ.get('PHANTOM_TEST_SESSION_MODE', 'ok')
args = command[1:] + ['--startup-ms', '300' if mode != 'ok' else '2000', '--drain-ms', '100']
if mode == 'ok':
    os.execve(args[0], args, env)
proc = subprocess.run(args, env=env, capture_output=True, timeout=3)
if proc.returncode:
    sys.exit(93)
os.write(1, proc.stdout)
if mode == 'trailing':
    os.write(1, b'extra')
sys.exit(17 if mode == 'nonzero' else 0)
''')
            fake.chmod(0o700)
            for mode in ('ok', 'nonzero', 'trailing'):
                env = dict(os.environ, PHANTOM_TEST_SESSION_MODE=mode)
                proc = subprocess.run([driver, '--ssh', str(fake), '/dev/null', server], env=env,
                                      capture_output=True, timeout=6)
                check(proc.returncode == (0 if mode == 'ok' else 1), 'incorrect supervisor admission')
                check(mode == 'ok' or b'PASS' not in proc.stdout, 'failed SSH startup admitted a session')
                reap()
        print('PASS new SSH profile dispatch, live UDP after admission, nonzero exit and trailing-output rejection')
    finally:
        for pid in children():
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        for pid in children():
            try: os.waitpid(pid, 0)
            except ChildProcessError: pass


if __name__ == '__main__':
    main()
