#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real OpenSSH -> actual detached C++ server -> channel probe -> close.

Uses only disposable loopback keys/configuration. Never reads or changes the
operator's trust files. A missing local sshd is an explicit skip, not a pass.
"""
import ctypes
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def check(value, message):
    if not value:
        raise RuntimeError(message)


def children():
    result = set()
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            for line in (entry / 'status').read_text().splitlines():
                if line.startswith('PPid:') and int(line.split()[1]) == os.getpid():
                    result.add(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def finish_sessions(exclude):
    deadline = time.monotonic() + 5
    while True:
        for pid in children() - exclude:
            try:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found:
                    check(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                          'detached session did not close cleanly')
            except ChildProcessError:
                pass
        if not children() - exclude:
            return
        check(time.monotonic() < deadline, 'detached session survived close drain')
        time.sleep(0.01)


def main():
    server, probe = (str(Path(p).resolve()) for p in sys.argv[1:3])
    required = '--required' in sys.argv[3:]
    keygen = shutil.which('ssh-keygen')
    sshd = shutil.which('sshd') or next((str(p) for p in (Path('/usr/sbin/sshd'), Path('/sbin/sshd')) if p.is_file()), None)
    if not keygen or not sshd or not Path('/usr/bin/ssh').is_file():
        print('OpenSSH tools unavailable: real session integration not run')
        return 1 if required else 77
    check(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'Linux test subreaper required')
    user = pwd.getpwuid(os.geteuid()).pw_name
    with tempfile.TemporaryDirectory(prefix='phantom-session-ssh-') as temp:
        root = Path(temp)
        for name in ('host', 'identity', 'wrong'):
            subprocess.run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)],
                           check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=10)
        (root / 'authorized').write_bytes((root / 'identity.pub').read_bytes())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        hostkey = (root / 'host.pub').read_text().split()
        pin = f'[127.0.0.1]:{port} {hostkey[0]} {hostkey[1]}\n'
        known = root / 'known_hosts'; known.write_text(pin)
        daemon_config = root / 'sshd_config'
        daemon_config.write_text(f'''ListenAddress 127.0.0.1
Port {port}
HostKey {root / 'host'}
PidFile {root / 'pid'}
AuthorizedKeysFile {root / 'authorized'}
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin yes
AllowUsers {user}
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
LogLevel ERROR
''')
        config = root / 'client_config'
        # The alias deliberately is not a routable/DNS hostname. The UDP peer
        # must come from authenticated remote startup, not this alias.
        config.write_text(f'''Host phantom-session-fixture
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {root / 'identity'}
  IdentitiesOnly yes
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  ProxyCommand none
  ProxyJump none
  CanonicalizeHostname no
''')
        executable = root / "server with 'quotes'; $literal"
        executable.symlink_to(server)
        with (root / 'sshd.log').open('wb') as log:
            daemon = subprocess.Popen([sshd, '-D', '-e', '-f', str(daemon_config)],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
            try:
                ready = False
                for _ in range(100):
                    check(daemon.poll() is None, 'fixture sshd exited during setup')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1) as conn:
                            ready = conn.recv(64).startswith(b'SSH-2.0-')
                        break
                    except OSError:
                        time.sleep(0.02)
                check(ready, 'fixture sshd did not become ready')
                args = [probe, '--server', str(executable), '--ssh-config', str(config), 'phantom-session-fixture']
                # Unknown trust fails before a remote session can be admitted.
                known.write_text('')
                result = subprocess.run(args, capture_output=True, timeout=15)
                check(result.returncode != 0 and not result.stdout, 'unknown host accepted')
                check(known.read_text() == '', 'unknown host enrolled automatically')
                known.write_text(pin)
                result = subprocess.run(args, capture_output=True, timeout=15)
                check(result.returncode == 0 and b'confirmed over UDP and closed' in result.stdout,
                      'real server/probe exchange failed (secret-bearing output suppressed)')
                check(known.read_text() == pin, 'known-hosts file modified')
                finish_sessions({daemon.pid})
                print('PASS real SSH alias, quoted server path, authenticated numeric offer, detached C++ owner, UDP confirmation and acknowledged close')
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    daemon.kill(); daemon.wait(timeout=3)
                for pid in children():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for pid in children():
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
