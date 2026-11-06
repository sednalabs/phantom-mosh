#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Wall-clock recovery of a real SSH-launched PTY through a userspace UDP relay.

Only disposable loopback fixtures are used. This is not kernel NAT or WAN
validation. No payload, secret-bearing offer or terminal transcript is retained.
"""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

from terminal_ssh_test import check, children, finish_sessions, is_server


class Relay:
    """Stable client destination, separately replaceable server-facing socket."""
    def __init__(self, target_file):
        self.target_file = target_file
        self.inside = self.bind()
        self.outside = self.bind()
        self.port = self.inside.getsockname()[1]
        self.retired = []
        self.client = None
        self.target = None
        self.lock = threading.Lock()
        self.stopping = False
        self.error = None
        self.blackout = False
        self.impair = False
        self.drop_server_controls = False
        self.control_drops = 0
        self.pending = []
        self.last_client_packet = None
        self.received = self.forwarded = self.dropped = self.duplicates = 0
        self.reordered = self.socket_drops = self.remaps = 0
        self.sequence = {1: 0, -1: 0}
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    @staticmethod
    def bind():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, 40, 1)  # Linux SO_RXQ_OVFL
        return sock

    def send(self, sock, data, destination):
        check(sock.sendto(data, destination) == len(data), 'short relay datagram send')
        self.forwarded += 1

    def set_impairment(self, *, blackout=False, impair=False):
        with self.lock:
            self.blackout, self.impair = blackout, impair

    def lose_close_acknowledgements(self):
        # Arm only after a computed terminal witness on a fresh, unimpaired
        # session. With no path change, subsequent server control is CLOSED.
        # Control records are exactly 32 record bytes + 17 session bytes; SSP
        # DATA additionally contains timing/fragment headers and cannot match.
        with self.lock:
            self.drop_server_controls = True

    def remap(self):
        with self.lock:
            new = self.bind()
            check(new.getsockname()[1] != self.outside.getsockname()[1], 'relay source port did not change')
            check(self.last_client_packet is not None, 'no old-path packet available')
            self.retired.append((self.outside, self.last_client_packet))
            self.outside = new
            self.remaps += 1
            # A remap loses packets held by the old path; count them explicitly.
            self.dropped += len(self.pending)
            self.pending.clear()

    def delayed_old_path(self):
        with self.lock:
            check(self.retired and self.target, 'missing retired path')
            old, data = self.retired[-1]
            self.send(old, data, self.target)
            self.duplicates += 1

    def run(self):
        try:
            while not self.stopping:
                with self.lock:
                    if self.target is None and self.target_file.exists():
                        text = self.target_file.read_text()
                        if text:
                            self.target = ('127.0.0.1', int(text))
                    sockets = [self.inside, self.outside] + [s for s, _ in self.retired]
                ready, _, _ = select.select(sockets, [], [], 0.01)
                with self.lock:
                    now = time.monotonic()
                    for sock in ready:
                        data, ancillary, flags, sender = sock.recvmsg(65535, 128)
                        check(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'truncated relay receive')
                        for level, kind, value in ancillary:
                            if level == socket.SOL_SOCKET and kind == 40:
                                self.socket_drops = max(self.socket_drops, struct.unpack('I', value)[0])
                        check(0 < len(data) <= 1200, 'datagram exceeded encrypted record budget')
                        self.received += 1
                        if sock is self.inside:
                            check(sender[0] == '127.0.0.1', 'unexpected client address')
                            check(self.client is None or self.client == sender, 'client socket changed during remap')
                            self.client = sender
                            self.last_client_packet = data
                            send_sock, destination, direction = self.outside, self.target, 1
                        else:
                            check(sender == self.target, 'unexpected server address')
                            if sock is not self.outside:
                                # Old path delivery must not become an alternate live route.
                                self.dropped += 1
                                continue
                            send_sock, destination, direction = self.inside, self.client, -1
                        check(destination is not None, 'relay endpoint unavailable')
                        self.sequence[direction] += 1
                        serial = self.sequence[direction]
                        if self.drop_server_controls and direction == -1 and len(data) == 49:
                            self.control_drops += 1
                            self.dropped += 1
                            continue
                        if self.blackout or (self.impair and serial % 7 == 0):
                            self.dropped += 1
                            continue
                        if self.impair and serial % 5 == 0:
                            self.pending.append((now + 0.12, send_sock, data, destination))
                            self.reordered += 1
                            continue
                        self.send(send_sock, data, destination)
                        if self.impair and serial % 3 == 0:
                            self.send(send_sock, data, destination)
                            self.duplicates += 1
                    pending, self.pending = self.pending, []
                    for deadline, sock, data, destination in pending:
                        if deadline > now:
                            self.pending.append((deadline, sock, data, destination))
                        elif self.blackout:
                            self.dropped += 1
                        else:
                            self.send(sock, data, destination)
        except Exception as exc:
            self.error = str(exc)

    def close(self):
        self.stopping = True
        self.thread.join(2)
        check(not self.thread.is_alive(), 'relay did not stop')
        for sock in [self.inside, self.outside] + [s for s, _ in self.retired]:
            sock.close()
        self.dropped += len(self.pending)
        self.pending.clear()
        self.retired.clear()
        self.last_client_packet = None
        check(not self.error, 'relay failed: ' + str(self.error))
        check(not self.socket_drops, 'unplanned relay receive-queue drops')
        check(self.received + self.duplicates == self.forwarded + self.dropped, 'relay ledger mismatch')


def drain(master, output, timeout=0.02):
    if select.select([master], [], [], timeout)[0]:
        try:
            output.extend(os.read(master, 65536))
        except OSError:
            pass
        check(len(output) < 1024 * 1024, 'bounded test transcript exceeded')


def witness(master, output, client, relay, expected, timeout=25):
    start = time.monotonic()
    while expected not in output:
        check(client.poll() is None, 'terminal client exited before computed witness')
        check(not relay.error, 'relay failed: ' + str(relay.error))
        check(time.monotonic() - start < timeout, 'computed recovery witness timed out (output suppressed)')
        drain(master, output)
    return round(time.monotonic() - start, 3)


def cleanup_owned_children():
    # This dedicated runner is the subreaper, so only its own descendants qualify.
    deadline = time.monotonic() + 3
    while children() and time.monotonic() < deadline:
        for pid in children():
            try:
                found, _ = os.waitpid(pid, os.WNOHANG)
                if not found:
                    os.kill(pid, signal.SIGKILL)
            except (ChildProcessError, ProcessLookupError):
                pass
        time.sleep(0.02)
    check(not children(), 'test-owned descendants survived fixture cleanup')


def main():
    server, client_path = (str(Path(p).resolve()) for p in sys.argv[1:3])
    required = '--required' in sys.argv[3:]
    keygen = shutil.which('ssh-keygen')
    sshd = shutil.which('sshd') or next((str(p) for p in (Path('/usr/sbin/sshd'), Path('/sbin/sshd')) if p.is_file()), None)
    if not keygen or not sshd or not Path('/usr/bin/ssh').is_file():
        print('OpenSSH unavailable: wall-clock terminal recovery not run')
        return 1 if required else 77
    check(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'Linux test subreaper required')
    with tempfile.TemporaryDirectory(prefix='phantom-terminal-recovery-') as temp:
        root = Path(temp)
        for name in ('host', 'identity'):
            subprocess.run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)],
                           check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=10)
        (root / 'authorized').write_bytes((root / 'identity.pub').read_bytes())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        hostkey = (root / 'host.pub').read_text().split()
        pin = f'[127.0.0.1]:{port} {hostkey[0]} {hostkey[1]}\n'
        (root / 'known_hosts').write_text(pin)
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
AllowUsers {pwd.getpwuid(os.geteuid()).pw_name}
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
LogLevel ERROR
''')
        config = root / 'client_config'
        config.write_text(f'''Host phantom-recovery-fixture
  HostName 127.0.0.1
  Port {port}
  User {pwd.getpwuid(os.geteuid()).pw_name}
  IdentityFile {root / 'identity'}
  IdentitiesOnly yes
  UserKnownHostsFile {root / 'known_hosts'}
  GlobalKnownHostsFile /dev/null
  ProxyCommand none
  ProxyJump none
  CanonicalizeHostname no
''')
        target = root / 'target_port'
        wrapper = root / 'server_wrapper'
        wrapper.write_text('#!/usr/bin/env python3\nimport subprocess,sys,pathlib\n'
                           + 'p=subprocess.run(' + repr([server]) + '+sys.argv[1:],capture_output=True)\n'
                           + 'if p.returncode: sys.exit(p.returncode)\n'
                           + 'fields=p.stdout.split()\n'
                           + 'assert fields[:2]==[b"PHANTOM",b"SESSION"] and len(fields)==8\n'
                           + 'assert fields[5]==b"127.0.0.1"\n'
                           + 'pathlib.Path(' + repr(str(target)) + ').write_text(fields[6].decode())\n'
                           + 'sys.stdout.buffer.write(p.stdout)\n')
        wrapper.chmod(0o700)
        daemon = client = relay = None
        master, slave = os.openpty()
        original = termios.tcgetattr(slave)
        try:
            with (root / 'sshd.log').open('wb') as log:
                daemon = subprocess.Popen([sshd, '-D', '-e', '-f', str(daemon_config)],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
                ready = False
                for _ in range(100):
                    check(daemon.poll() is None, 'fixture sshd exited')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1) as conn:
                            ready = conn.recv(64).startswith(b'SSH-2.0-')
                        break
                    except OSError:
                        time.sleep(0.02)
                check(ready, 'fixture sshd did not become ready')
                relay = Relay(target)
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
                args = [client_path, '--server', str(wrapper), '--ssh-config', str(config),
                        '--udp-host', '127.0.0.1', '--udp-port', str(relay.port), 'phantom-recovery-fixture']
                client = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=subprocess.DEVNULL,
                                          env=dict(os.environ, LANG='C.UTF-8', LC_ALL='C.UTF-8', TERM='xterm-256color'))
                output = bytearray()
                deadline = time.monotonic() + 12
                while termios.tcgetattr(slave)[3] & termios.ICANON:
                    check(client.poll() is None and time.monotonic() < deadline, 'client raw-mode startup failed')
                    drain(master, output)
                os.write(master, b"n=0; printf 'READY:%s\\n' \"$((6*7))\"\n")
                witness(master, output, client, relay, b'READY:42', timeout=12)
                observed = {pid for pid in children() if is_server(pid, server)}
                check(observed, 'real detached terminal server not observed')
                original_client = relay.client
                output.clear()
                relay.set_impairment(impair=True)
                relay.remap()
                os.write(master, b"n=$((n+1)); printf 'FIRST:%s\\n' \"$n\"\n")
                first = witness(master, output, client, relay, b'FIRST:1')
                relay.set_impairment()
                relay.delayed_old_path()
                output.clear()
                relay.set_impairment(blackout=True)
                relay.remap()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 31, 91, 0, 0))
                client.send_signal(signal.SIGWINCH)
                os.write(master, b"n=$((n+1)); printf 'SECOND:%s\\n' \"$n\"; stty size; printf '\\342\\234\\223:%s\\n' \"$((7*7))\"\n")
                blackout_start = time.monotonic()
                while time.monotonic() - blackout_start < 2:
                    check(client.poll() is None and not relay.error, 'session failed during blackout')
                    drain(master, output)
                check(b'SECOND:2' not in output, 'blackout did not withhold remote output')
                relay.set_impairment(impair=True)
                second = witness(master, output, client, relay, b'SECOND:2')
                witness(master, output, client, relay, b'31 91')
                witness(master, output, client, relay, '\u2713:49'.encode())
                relay.set_impairment()
                relay.delayed_old_path()
                output.clear()
                os.write(master, b"n=$((n+1)); printf 'FINAL:%s\\n' \"$n\"; exit 7\n")
                witness(master, output, client, relay, b'FINAL:3')
                deadline = time.monotonic() + 15
                while client.poll() is None and time.monotonic() < deadline:
                    drain(master, output)
                check(client.poll() == 7, 'recovered terminal did not preserve remote exit status 7')
                check(termios.tcgetattr(slave) == original, 'client failed to restore local termios')
                check(relay.client == original_client, 'client source endpoint changed')
                check((root / 'known_hosts').read_text() == pin, 'known-hosts file modified')
                finish_sessions({daemon.pid}, server, observed)
                check(relay.remaps == 2 and relay.dropped and relay.duplicates and relay.reordered,
                      'requested relay impairments did not occur')
                relay.close()
                print(json.dumps(dict(scope='wall-clock launched PTY, userspace IPv4 loopback relay',
                                      first_recovery_seconds=first, second_after_blackout_seconds=second,
                                      blackout_seconds=2, remaps=relay.remaps, received=relay.received,
                                      forwarded=relay.forwarded, deliberate_drops=relay.dropped,
                                      duplicates=relay.duplicates, delayed_datagrams=relay.reordered,
                                      socket_drops=relay.socket_drops, computed_witnesses=True,
                                      stable_client_endpoint=True, raw_mode_restored=True, client_exit=7)))
                relay = None
                # A separate healthy session isolates loss of encrypted CLOSED
                # replies from SSP completion. Remote exit 0 must not hide a
                # channel close timeout, and the final screen must still drain.
                target.unlink()
                relay = Relay(target)
                args = [client_path, '--server', str(wrapper), '--ssh-config', str(config),
                        '--udp-host', '127.0.0.1', '--udp-port', str(relay.port), 'phantom-recovery-fixture']
                client = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=subprocess.PIPE,
                                          env=dict(os.environ, LANG='C.UTF-8', LC_ALL='C.UTF-8', TERM='xterm-256color'))
                output.clear()
                deadline = time.monotonic() + 12
                while termios.tcgetattr(slave)[3] & termios.ICANON:
                    check(client.poll() is None and time.monotonic() < deadline, 'close-loss raw-mode startup failed')
                    drain(master, output)
                os.write(master, b"printf 'CLOSE-READY:%s\\n' \"$((6*7))\"\n")
                witness(master, output, client, relay, b'CLOSE-READY:42', timeout=12)
                observed = {pid for pid in children() if is_server(pid, server)}
                check(observed, 'close-loss terminal server not observed')
                relay.lose_close_acknowledgements()
                output.clear()
                os.write(master, b"printf 'CLOSE-FINAL:%s\\n' \"$((7*7))\"; exit 0\n")
                deadline = time.monotonic() + 15
                while client.poll() is None and time.monotonic() < deadline:
                    drain(master, output)
                drain(master, output)
                check(client.poll() == 1, 'lost close acknowledgement reported remote success')
                stderr = client.stderr.read()
                client.stderr.close()
                check(b'terminal channel close was not acknowledged' in stderr,
                      'close-loss session failed before channel completion')
                check(b'CLOSE-FINAL:49' in output, 'close-loss final computed output was not drained')
                check(termios.tcgetattr(slave) == original, 'close-loss failed to restore local termios')
                check(relay.control_drops > 0, 'no encrypted close acknowledgements were dropped')
                finish_sessions({daemon.pid}, server, observed)
                relay.close()
                relay = None
                print('PASS lost channel close acknowledgements return failure after final output and termios restoration')
        finally:
            relay_error = None
            if client and client.poll() is None:
                client.terminate()
                try:
                    client.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    client.kill(); client.wait()
            if relay:
                try:
                    relay.close()
                except RuntimeError as exc:
                    relay_error = exc
            if daemon:
                daemon.terminate()
                try:
                    daemon.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    daemon.kill(); daemon.wait()
            os.close(master); os.close(slave)
            cleanup_owned_children()
            if relay_error is not None and sys.exc_info()[0] is None:
                raise relay_error
    return 0


if __name__ == '__main__':
    sys.exit(main())
