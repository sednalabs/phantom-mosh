#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Isolated real-OpenSSH tests. Never use or change the developer's SSH keys/config."""
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    driver = str(Path(sys.argv[1]).resolve())
    required = '--required' in sys.argv[2:]
    ssh = shutil.which('ssh')
    keygen = shutil.which('ssh-keygen')
    sshd = shutil.which('sshd') or next((str(p) for p in (Path('/usr/sbin/sshd'), Path('/sbin/sshd')) if p.is_file()), None)
    if not all((ssh, keygen, sshd)):
        print('OpenSSH integration tools unavailable')
        return 1 if required else 77
    here = Path(__file__).resolve().parent
    user = pwd.getpwuid(os.geteuid()).pw_name
    with tempfile.TemporaryDirectory(prefix='phantom-real-ssh-') as temp:
        root = Path(temp)
        for name in ('host', 'client', 'wrong'):
            subprocess.run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)],
                           check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=10)
        (root / 'authorized_keys').write_bytes((root / 'client.pub').read_bytes())
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
        config = root / 'sshd_config'
        config.write_text(f'''ListenAddress 127.0.0.1
Port {port}
HostKey {root / 'host'}
PidFile {root / 'pid'}
AuthorizedKeysFile {root / 'authorized_keys'}
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
        # All relaxed sshd settings apply only to this loopback fixture and its
        # disposable keys. The CLIENT's strict verification is never disabled.
        known = root / 'known_hosts'
        host = (root / 'host.pub').read_text().split()
        pinned = f'[127.0.0.1]:{port} {host[0]} {host[1]}\n'
        known.write_text(pinned)
        client_config = root / 'client_config'
        def configure(identity='client'):
            client_config.write_text(f'''Host fixture
  HostName 127.0.0.1
  Port {port}
  User {user}
  IdentityFile {root / identity}
  IdentitiesOnly yes
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking no
  ControlMaster auto
  ControlPath {root / 'unused-control-socket'}
  PermitLocalCommand yes
  LocalCommand touch {root / 'must-not-exist'}
''')
        configure()
        # The executable name deliberately exercises remote-shell token quoting.
        server = root / "server with 'quotes'; $literal"
        server.write_text('#!' + sys.executable + '\nimport sys, os\nsys.path.insert(0, ' + repr(str(here))
                          + ')\nfrom ssh_fixture_server import main\nos._exit(main())\n')
        server.chmod(0o700)
        bad_server = root / 'nonzero-server'
        bad_server.write_text('#!' + sys.executable + '\nimport os\nos.write(1, '
                              + repr(b'PHANTOM CONNECT phantom-mosh/v3/draft-01 server client 60000 '
                                     b'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n')
                              + ')\nos._exit(17)\n')
        bad_server.chmod(0o700)
        with (root / 'sshd.log').open('wb') as log:
            daemon = subprocess.Popen([sshd, '-D', '-e', '-f', str(config)],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
            try:
                ready = False
                for _ in range(100):
                    if daemon.poll() is not None:
                        raise RuntimeError('test sshd exited: ' + (root / 'sshd.log').read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1) as connection:
                            ready = connection.recv(64).startswith(b'SSH-2.0-')
                            break
                    except OSError:
                        time.sleep(0.02)
                check(ready, 'test sshd did not become ready')
                def run(expect, executable=server, udp=True):
                    result = subprocess.run([driver, ssh, 'fixture', str(executable), str(client_config),
                                             '5000', '-1', 'udp' if udp else 'no-udp'],
                                            capture_output=True, timeout=8)
                    check(result.returncode == expect, 'real SSH outcome: ' + result.stderr.decode())
                    check(not (root / 'must-not-exist').exists(), 'SSH LocalCommand was not suppressed')
                    check(not (root / 'unused-control-socket').exists(), 'unexpected persistent SSH master')
                    return result
                known.write_text('')
                run(1); check(known.read_text() == '', 'unknown host was enrolled automatically')
                wrong = (root / 'wrong.pub').read_text().split()
                known.write_text(f'[127.0.0.1]:{port} {wrong[0]} {wrong[1]}\n')
                run(1)
                known.write_text(pinned); configure('wrong'); run(1)
                configure(); run(1, executable=bad_server, udp=False)
                run(0)
                check(known.read_text() == pinned, 'host trust file changed')
                print('PASS real SSH: pinned host, unknown/changed host, bad identity, exit status, encrypted UDP')
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    daemon.kill(); daemon.wait(timeout=3)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
