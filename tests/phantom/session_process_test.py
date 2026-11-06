#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detached-process lifecycle tests. Synthetic SSH_CONNECTION is not authentication.

An isolated Linux subreaper owns the test daemons, including failure cleanup.
No session secret is placed in argv/environment or printed in test diagnostics.
"""
import ctypes
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

PROFILE = 'phantom-mosh/session/draft-01'
SERVER = str(Path(sys.argv[1]).resolve())
DRIVER = str(Path(sys.argv[2]).resolve())


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def children():
    # Some sandbox procfs implementations omit /task/*/children.
    result = set()
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = dict(line.split(':', 1) for line in (entry / 'status').read_text().splitlines() if ':' in line)
            if int(fields.get('PPid', -1)) == os.getpid():
                result.add(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def reap(timeout=5):
    deadline = time.monotonic() + timeout
    statuses = []
    while children():
        for pid in children():
            try:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found:
                    statuses.append(status)
            except ChildProcessError:
                pass
        if not children():
            break
        check(time.monotonic() < deadline, 'session process did not exit within its lifetime')
        time.sleep(0.01)
    check(all(os.WIFEXITED(s) and os.WEXITSTATUS(s) == 0 for s in statuses), 'session daemon failed')


def launch(*options, host='127.0.0.1'):
    env = dict(os.environ, SSH_CONNECTION=f'{host} 45000 {host} 22')
    proc = subprocess.run([SERVER, '--session-profile', PROFILE, *options], env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    check(proc.returncode == 0 and not proc.stderr, 'server startup rejected the test channel')
    parts = proc.stdout.decode('ascii').strip().split(' ')
    check(len(parts) == 8 and parts[:5] == ['PHANTOM', 'SESSION', PROFILE, 'server', 'client'], 'invalid address-bound offer')
    check(parts[5] == host and 0 < int(parts[6]) < 65536 and len(parts[7]) == 43, 'invalid endpoint or key encoding')
    deadline = time.monotonic() + 1
    while not children() and time.monotonic() < deadline:
        time.sleep(0.01)
    check(len(children()) == 1, 'test did not adopt exactly one detached session')
    pid = next(iter(children()))
    check(parts[7].encode() not in Path(f'/proc/{pid}/cmdline').read_bytes(), 'secret in arguments')
    check(parts[7].encode() not in Path(f'/proc/{pid}/environ').read_bytes(), 'secret in environment')
    handles = {p.name for p in Path(f'/proc/{pid}/fd').iterdir()}
    check(handles == {'0', '1', '2', '4'}, 'unexpected inherited daemon descriptor')
    return proc.stdout, (host, int(parts[6])), pid


def run_client(frame, mode='close'):
    proc = subprocess.run([DRIVER, mode], input=frame, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    check(proc.returncode == 0 and b'PASS live session' in proc.stdout, 'live session client failed: ' + proc.stderr.decode(errors='replace'))


def main():
    libc = ctypes.CDLL(None, use_errno=True)
    check(libc.prctl(36, 1, 0, 0, 0) == 0, 'test requires Linux child subreaping')
    try:
        # No confirmation: the absolute startup lease expires despite UDP input.
        _, address, _ = launch('--startup-ms', '1000')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as junk:
            for _ in range(20):
                junk.sendto(bytes(1201), address)
                junk.sendto(bytes(49), address)
                time.sleep(0.01)
        reap()
        # Return-path proof, migration and authenticated close on real sockets.
        frame, _, _ = launch('--startup-ms', '5000', '--drain-ms', '100')
        run_client(frame)
        reap()
        # A confirmed daemon remains alive after the SSH-like parent and client
        # exit; its optional idle budget, not their process lifetime, ends it.
        frame, _, _ = launch('--startup-ms', '5000', '--idle-ms', '1500')
        run_client(frame, 'leave')
        check(bool(children()), 'confirmed session died with startup parent')
        reap()
        frame, _, pid = launch('--startup-ms', '5000')
        run_client(frame, 'leave')
        os.kill(pid, signal.SIGTERM)
        reap()
        # IPv6 is a separate real transport exercise, not just parsing.
        frame, _, _ = launch('--startup-ms', '5000', '--drain-ms', '100', host='::1')
        run_client(frame)
        reap()
        # Invalid setup fails before any detached owner is created.
        env = dict(os.environ, SSH_CONNECTION='127.0.0.1 1 127.0.0.1 22')
        for args in (['--session-profile', 'wrong'], ['--session-profile', PROFILE, '--startup-ms', '0']):
            result = subprocess.run([SERVER, *args], env=env, capture_output=True, timeout=3)
            check(result.returncode != 0 and not result.stdout and not children(), 'invalid setup created a session')
        env.pop('SSH_CONNECTION')
        result = subprocess.run([SERVER, '--session-profile', PROFILE], env=env, capture_output=True, timeout=3)
        check(result.returncode != 0 and not result.stdout and not children(), 'missing SSH context accepted')
        # An abandoned output consumer cannot leave an unconfirmed live daemon.
        env['SSH_CONNECTION'] = '127.0.0.1 1 127.0.0.1 22'
        proc = subprocess.Popen([SERVER, '--session-profile', PROFILE, '--startup-ms', '100'], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        proc.stdout.close()
        proc.wait(timeout=3)
        # Daemon may exit cleanly by lease or fail on its private startup pipe.
        deadline = time.monotonic() + 3
        while children():
            for pid in children():
                try: os.waitpid(pid, os.WNOHANG)
                except ChildProcessError: pass
            check(time.monotonic() < deadline, 'abandoned startup leaked daemon')
            time.sleep(0.01)
        print('PASS detached startup expiry, IPv4/IPv6 confirmation, migration, close, idle, signal, descriptor isolation and abandoned output')
    finally:
        for pid in children():
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        for pid in children():
            try: os.waitpid(pid, 0)
            except ChildProcessError: pass


if __name__ == '__main__':
    main()
