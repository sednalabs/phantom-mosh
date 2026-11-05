#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real OpenSSH -> detached PTY/SSP server -> experimental terminal client.

Uses only disposable loopback keys/configuration. Never reads or changes the
operator's trust files. A missing local sshd is an explicit skip, not a pass.
"""
import ctypes
import fcntl
import struct
import termios
import os
from pathlib import Path
import pwd
import shutil
import shlex
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


def is_server(pid, server):
    """Identify the adopted Phantom daemon, not unrelated sshd descendants."""
    try:
        return Path(f'/proc/{pid}/exe').resolve() == Path(server).resolve()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False


def finish_sessions(exclude, server, observed, expected_exit=0, timeout=5):
    deadline = time.monotonic() + timeout
    server_pids = set(observed)
    server_seen = bool(observed)
    while True:
        adopted = children() - exclude
        for pid in adopted:
            if pid not in server_pids and is_server(pid, server):
                server_pids.add(pid)
                server_seen = True
        for pid in adopted:
            try:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found and pid in server_pids:
                    check(os.WIFEXITED(status) and os.WEXITSTATUS(status) == expected_exit,
                          f'detached Phantom session did not close cleanly: wait status {status}')
            except ChildProcessError:
                pass
        if not children() - exclude:
            check(server_seen, 'detached Phantom session was not observed')
            return
        check(time.monotonic() < deadline, 'detached session descendants survived close drain')
        time.sleep(0.01)


def main():
    server, probe, control_server, control_probe = (str(Path(p).resolve()) for p in sys.argv[1:5])
    required = '--required' in sys.argv[5:]
    for invalid_port in ('0', '65536', '-1', 'bad', '12x'):
        invalid = subprocess.run([probe, '--udp-port', invalid_port, 'unused'], capture_output=True, timeout=3)
        check(invalid.returncode != 0 and b'invalid UDP port override' in invalid.stderr,
              'invalid UDP port reached SSH startup')
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
                result = subprocess.run(args, input=b"sleep 60 & printf 'PHANTOM-PTY-%s\\n' \"$((6*7))\"; stty size; exit\n", capture_output=True, timeout=15)
                check(result.returncode != 0 and not result.stdout, 'unknown host accepted')
                check(known.read_text() == '', 'unknown host enrolled automatically')
                known.write_text(pin)
                # Application selection is explicit in authenticated SSH startup.
                mismatch = [probe, '--server', control_server, '--ssh-config', str(config), 'phantom-session-fixture']
                wrong_app = subprocess.run(mismatch, capture_output=True, timeout=15)
                check(wrong_app.returncode != 0 and not wrong_app.stdout, 'terminal accepted control-only server')
                mismatch = [control_probe, '--server', server, '--ssh-config', str(config), 'phantom-session-fixture']
                wrong_app = subprocess.run(mismatch, capture_output=True, timeout=15)
                check(wrong_app.returncode != 0 and not wrong_app.stdout, 'probe launched terminal application')
                client = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                observed = set()
                deadline = time.monotonic() + 10
                while not observed and time.monotonic() < deadline and client.poll() is None:
                    observed = {pid for pid in children() if is_server(pid, server)}
                    time.sleep(0.01)
                check(observed, 'detached terminal server was not observed while active')
                stdout, stderr = client.communicate(b"sleep 60 & printf 'PHANTOM-PTY-%s\\n' \"$((6*7))\"; stty size; exit\n", timeout=15)
                result = subprocess.CompletedProcess(args, client.returncode, stdout, stderr)
                check(result.returncode == 0 and b'PHANTOM-PTY-42' in result.stdout and b'24 80' in result.stdout,
                      'real SSH-to-PTY terminal exchange failed (output suppressed)')
                check(known.read_text() == pin, 'known-hosts file modified')
                finish_sessions({daemon.pid}, server, observed)
                # A configured server drain longer than the client-close wait
                # must complete, rather than hitting the frontend's 5s deadline.
                long_drain = root / 'long-drain-server'
                long_drain.write_text('#!/bin/sh\nexec ' + shlex.quote(server) + ' "$@" --drain-ms 6000\n')
                long_drain.chmod(0o700)
                long_args = [probe, '--server', str(long_drain), '--ssh-config', str(config), 'phantom-session-fixture']
                client = subprocess.Popen(long_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                observed = set()
                deadline = time.monotonic() + 10
                while not observed and time.monotonic() < deadline and client.poll() is None:
                    observed = {pid for pid in children() if is_server(pid, server)}
                    time.sleep(0.01)
                check(observed, 'long-drain terminal not observed')
                stdout, stderr = client.communicate(b'exit\n', timeout=15)
                check(client.returncode == 0, 'long-drain terminal client failed')
                finish_sessions({daemon.pid}, server, observed, timeout=10)
                # A successfully authenticated SSH startup whose UDP peer never
                # confirms must expire and clean the already-owned shell.
                command = 'exec ' + shlex.quote(str(executable)) + ' --terminal-profile phantom-mosh/terminal/draft-01 --startup-ms 1000'
                startup = subprocess.run(['/usr/bin/ssh', '-n', '-T', '-F', str(config),
                                          '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                          'phantom-session-fixture', command], capture_output=True, timeout=15)
                check(startup.returncode == 0 and startup.stdout.startswith(b'PHANTOM SESSION '),
                      'unconfirmed terminal startup failed')
                # Secret-bearing offer is never printed, persisted or reused.
                del startup
                observed = {pid for pid in children() if is_server(pid, server)}
                check(observed, 'unconfirmed terminal server not observed')
                finish_sessions({daemon.pid}, server, observed, expected_exit=2)
                # Exercise the actual client raw-mode/resize path using a local
                # PTY, then require its original termios after clean remote exit.
                master, slave = os.openpty()
                try:
                    original = termios.tcgetattr(slave)
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
                    client = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    observed = set()
                    deadline = time.monotonic() + 10
                    while not observed and time.monotonic() < deadline and client.poll() is None:
                        observed = {pid for pid in children() if is_server(pid, server)}
                        time.sleep(0.01)
                    check(observed, 'interactive terminal server not observed')
                    deadline = time.monotonic() + 5
                    while termios.tcgetattr(slave)[3] & termios.ICANON:
                        check(time.monotonic() < deadline and client.poll() is None, 'client never entered raw mode')
                        time.sleep(0.01)
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 31, 91, 0, 0))
                    client.send_signal(signal.SIGWINCH)
                    time.sleep(0.2)
                    os.write(master, b"printf 'RESIZE:%s\\n' \"$(stty size)\"; exit\n")
                    stdout, stderr = client.communicate(timeout=15)
                    check(client.returncode == 0 and b'RESIZE:31 91' in stdout, 'remote resize or shutdown failed')
                    check(termios.tcgetattr(slave) == original, 'client failed to restore original terminal mode')
                    finish_sessions({daemon.pid}, server, observed)
                    # Terminate the client while a foreground job is running;
                    # raw mode and ordinary descendant cleanup must still finish.
                    client = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    observed = set()
                    deadline = time.monotonic() + 10
                    while not observed and time.monotonic() < deadline and client.poll() is None:
                        observed = {pid for pid in children() if is_server(pid, server)}
                        time.sleep(0.01)
                    check(observed, 'signal-test terminal server not observed')
                    deadline = time.monotonic() + 5
                    while termios.tcgetattr(slave)[3] & termios.ICANON:
                        check(time.monotonic() < deadline and client.poll() is None, 'signal client never entered raw mode')
                        time.sleep(0.01)
                    os.write(master, b"sleep 60\n")
                    time.sleep(0.2)
                    client.send_signal(signal.SIGTERM)
                    stdout, stderr = client.communicate(timeout=10)
                    check(client.returncode == 0, 'client signal shutdown failed')
                    check(termios.tcgetattr(slave) == original, 'signal failed to restore original terminal mode')
                    finish_sessions({daemon.pid}, server, observed)
                    # Cancellation while SSH is waiting for its protocol banner
                    # must unwind the local supervisor without ever entering raw mode.
                    with socket.socket() as stalled:
                        stalled.bind(('127.0.0.1', 0)); stalled.listen(1); stalled.settimeout(5)
                        stalled_config = root / 'stalled_client_config'
                        stalled_config.write_text(f"Host stalled-fixture\n  HostName 127.0.0.1\n  Port {stalled.getsockname()[1]}\n")
                        client = subprocess.Popen([probe, '--ssh-config', str(stalled_config), 'stalled-fixture'],
                                                  stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        connection, _ = stalled.accept()
                        with connection:
                            client.send_signal(signal.SIGTERM)
                            stdout, stderr = client.communicate(timeout=3)
                            check(client.returncode != 0, 'cancelled startup claimed success')
                            check(termios.tcgetattr(slave) == original, 'startup cancellation changed terminal mode')
                            connection.settimeout(2)
                            while connection.recv(1024):
                                pass

                finally:
                    os.close(master); os.close(slave)
                print('PASS real SSH terminal profile, PTY command/output, pipe EOF, resize, SIGTERM/raw-mode restoration, background and foreground job cleanup')
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
