#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled loopback terminal metadata pilot. Never writes payloads or keys.

Requires Linux, disposable sshd support, and prebuilt client/server binaries.
The UDP relay adds scheduling overhead; this is not a passive network tap.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import threading
import time

from compare import compare, digest

WINDOW = 12
WORKLOAD = {'window_seconds': WINDOW, 'warmup': "printf 'WARM:%s\\n' \"$((6*7))\"\n",
            'typing': [[2, "printf 'RESULT:%s\\n' \"$((6*7))\"\n"],
                       [4, "printf 'RESULT:%s\\n' \"$((7*7))\"\n"],
                       [6, "printf 'RESULT:%s\\n' \"$((8*7))\"\n"]]}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Relay:
    def __init__(self, target_file):
        self.target_file = target_file
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.setsockopt(socket.SOL_SOCKET, 40, 1)  # Linux SO_RXQ_OVFL
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.error = None
        self.start = None
        self.rows = []
        self.received = self.forwarded = self.drops = 0
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        target = client = None
        try:
            while not self.stop:
                if target is None:
                    if not self.target_file.exists():
                        time.sleep(0.01)
                        continue
                    port_text = self.target_file.read_text()
                    if not port_text:
                        time.sleep(0.01)
                        continue
                    target = ('127.0.0.1', int(port_text))
                try:
                    data, ancillary, flags, sender = self.sock.recvmsg(65535, 128)
                except socket.timeout:
                    continue
                now = time.monotonic()
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise RuntimeError('truncated relay observation')
                for level, kind, value in ancillary:
                    if level == socket.SOL_SOCKET and kind == 40:
                        self.drops = max(self.drops, struct.unpack('I', value)[0])
                if sender == target:
                    if client is None:
                        raise RuntimeError('unsolicited server datagram')
                    destination, direction = client, -1
                else:
                    if sender[0] != '127.0.0.1' or (client is not None and client != sender):
                        raise RuntimeError('unexpected relay sender')
                    client = sender
                    destination, direction = target, 1
                self.received += 1
                length = len(data)
                if self.sock.sendto(data, destination) != length:
                    raise RuntimeError('short UDP relay send')
                self.forwarded += 1
                del data
                start = self.start
                if start is not None and 0 <= now - start <= WINDOW:
                    self.rows.append(dict(time_ms=(now-start)*1000,
                                          udp_payload_bytes=length, direction=direction))
        except Exception as exc:
            self.error = str(exc)

    def close(self):
        self.stop = True
        self.thread.join(2)
        self.sock.close()
        if self.thread.is_alive() or self.error or self.drops or self.received != self.forwarded:
            raise RuntimeError('relay health failure: ' + str(self.error))


def read_output(master, output, timeout=0.02):
    if select.select([master], [], [], timeout)[0]:
        try:
            output.extend(os.read(master, 65536))
        except OSError:
            pass


def run_session(args, root, config, implementation, workload, number):
    target = root / f'port-{number}'
    relay = Relay(target)
    env = dict(os.environ, TERM='xterm-256color', LANG='C.UTF-8', LC_ALL='C.UTF-8',
               MOSH_PREDICTION_DISPLAY='never')
    client = None
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    try:
        if implementation == 'stock-mosh':
            result = subprocess.run([args.stock_server, 'new', '-i', '127.0.0.1',
                                     '-l', 'LANG=C.UTF-8', '--', '/bin/sh', '-i'],
                                    env=env, capture_output=True, timeout=10)
            offer = re.search(rb'MOSH CONNECT (\d+) ([A-Za-z0-9+/]+)', result.stdout)
            if result.returncode or offer is None:
                raise RuntimeError('stock startup failed; secret-bearing output suppressed')
            target.write_text(offer[1].decode())
            env['MOSH_KEY'] = offer[2].decode()  # stock Mosh's standard bootstrap API
            command = [args.stock_client, '127.0.0.1', str(relay.port)]
            del result, offer
        else:
            wrapper = root / f'server-wrapper-{number}'
            wrapper.write_text('#!/usr/bin/env python3\nimport subprocess,sys,pathlib\n'
                               + 'p=subprocess.run(' + repr([args.phantom_server])
                               + '+sys.argv[1:],capture_output=True)\n'
                               + 'if p.returncode: sys.exit(p.returncode)\n'
                               + 'fields=p.stdout.split()\n'
                               + 'assert fields[:2]==[b"PHANTOM",b"SESSION"] and len(fields)==8\n'
                               + 'assert fields[5]==b"127.0.0.1"\n'
                               + 'pathlib.Path(' + repr(str(target)) + ').write_text(fields[6].decode())\n'
                               + 'sys.stdout.buffer.write(p.stdout)\n')
            wrapper.chmod(0o700)
            command = [args.phantom_client, '--server', str(wrapper), '--ssh-config', str(config),
                       '--udp-host', '127.0.0.1', '--udp-port', str(relay.port), 'pilot']
        client = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=subprocess.DEVNULL, env=env)
        env.pop('MOSH_KEY', None)
        output = bytearray()
        # Both clients receive the same warmup after reaching raw mode.
        deadline = time.monotonic() + 12
        while termios.tcgetattr(slave)[3] & termios.ICANON:
            if client.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('client failed before raw-mode startup')
            read_output(master, output)
        os.write(master, WORKLOAD['warmup'].encode())
        while b'WARM:42' not in output:
            if client.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('remote warmup witness missing')
            read_output(master, output)
        output.clear()
        time.sleep(0.5)
        start = relay.start = time.monotonic()
        schedule = list(WORKLOAD['typing']) if workload == 'typing' else []
        while time.monotonic() - start < WINDOW:
            if client.poll() is not None or relay.error:
                raise RuntimeError('session failed during measurement')
            elapsed = time.monotonic() - start
            while schedule and elapsed >= schedule[0][0]:
                os.write(master, schedule.pop(0)[1].encode())
            read_output(master, output)
        if workload == 'typing' and any(f'RESULT:{n}'.encode() not in output for n in (42, 49, 56)):
            raise RuntimeError('computed remote workload witness missing')
        os.write(master, b"printf 'DONE:%s\\n' \"$((9*7))\"; exit\n")
        deadline = time.monotonic() + 15
        while client.poll() is None and time.monotonic() < deadline:
            read_output(master, output)
        # Drain the final terminal frame already buffered in the local PTY.
        for _ in range(5):
            read_output(master, output)
        if client.poll() != 0 or b'DONE:63' not in output:
            raise RuntimeError('remote completion witness or clean client exit missing')
        del output
        relay.close()
        return relay.rows, {'received': relay.received, 'forwarded': relay.forwarded,
                            'socket_drops': relay.drops, 'remote_witness': True, 'client_exit': 0}
    finally:
        if client and client.poll() is None:
            client.terminate()
            try:
                client.wait(timeout=8)
            except subprocess.TimeoutExpired:
                client.kill(); client.wait()
        if relay.thread.is_alive():
            relay.stop = True; relay.thread.join(2); relay.sock.close()
        os.close(master); os.close(slave)


def cleanup_children():
    """Reap/terminate only descendants adopted by this dedicated test runner."""
    for attempt in range(100):
        live = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry/'status').read_text()
                parent = re.search(r'^PPid:\s+(\d+)', status, re.M)
                if not parent or int(parent[1]) != os.getpid():
                    continue
                pid = int(entry.name)
                found, _ = os.waitpid(pid, os.WNOHANG)
                if not found:
                    live.append(pid)
            except (OSError, ChildProcessError):
                continue
        if not live:
            return
        for pid in live:
            try:
                os.kill(pid, signal.SIGTERM if attempt < 50 else signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.02)
    raise RuntimeError('test descendants did not exit')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stock-client', 'stock-server', 'phantom-client', 'phantom-server', 'stock-sha', 'phantom-sha'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('Linux subreaper required for test-owned session cleanup')
    for revision in (args.stock_sha, args.phantom_sha):
        if not re.fullmatch('[0-9a-f]{40}', revision):
            parser.error('source revisions must be full lowercase Git SHAs')
    if args.pairs < 1:
        parser.error('pairs must be positive')
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = {name: sha(getattr(args, name.replace('-', '_'))) for name in
                ('stock-client', 'stock-server', 'phantom-client', 'phantom-server')}
    manifest = {'schema': 'loopback-pilot-01', 'workload': WORKLOAD, 'pairs_per_workload': args.pairs,
                'workloads': ['idle', 'typing'], 'order': 'alternate implementation order by pair index',
                'binary_hashes': binaries, 'stock_sha': args.stock_sha, 'phantom_sha': args.phantom_sha,
                'runner_sha256': sha(__file__), 'kernel': os.uname().release,
                'limitations': ['loopback userspace relay, not passive tap', 'no classifier or privacy result',
                                'upstream source build, not packaged-release qualification',
                                'small pilot, not the planned 30-pair/60-second campaign']}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    runs, ledger = [], []
    daemon = None
    with tempfile.TemporaryDirectory(prefix='phantom-matched-pilot-') as temp:
        root = Path(temp)
        for name in ('host', 'identity'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root/name)], check=True)
        (root/'authorized').write_bytes((root/'identity.pub').read_bytes())
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        key = (root/'host.pub').read_text().split()
        (root/'known').write_text(f'[127.0.0.1]:{port} {key[0]} {key[1]}\n')
        user = pwd.getpwuid(os.geteuid()).pw_name
        (root/'sshd').write_text(f'ListenAddress 127.0.0.1\nPort {port}\nHostKey {root}/host\nPidFile {root}/pid\nAuthorizedKeysFile {root}/authorized\nStrictModes no\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers {user}\nAllowTcpForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\nLogLevel ERROR\n')
        config = root/'ssh'
        config.write_text(f'Host pilot\n HostName 127.0.0.1\n Port {port}\n User {user}\n IdentityFile {root}/identity\n IdentitiesOnly yes\n UserKnownHostsFile {root}/known\n GlobalKnownHostsFile /dev/null\n StrictHostKeyChecking yes\n ProxyCommand none\n ProxyJump none\n')
        daemon = subprocess.Popen([shutil.which('sshd') or '/usr/sbin/sshd', '-D', '-e', '-f', str(root/'sshd')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if daemon.poll() is not None:
                    raise RuntimeError('disposable sshd startup failed')
                try:
                    with socket.create_connection(('127.0.0.1', port), 0.1):
                        break
                except OSError:
                    time.sleep(0.02)
            serial = 0
            for workload in manifest['workloads']:
                for pair in range(args.pairs):
                    order = ['stock-mosh', 'phantom-draft-01']
                    if pair % 2:
                        order.reverse()
                    for implementation in order:
                        serial += 1
                        pair_id = f'{workload}-{pair+1}'
                        row = {'pair_id': pair_id, 'implementation': implementation}
                        try:
                            packets, health = run_session(args, root, config, implementation, workload, serial)
                            prefix = 'stock' if implementation == 'stock-mosh' else 'phantom'
                            runs.append(dict(schema='phantom-matched-run-01', implementation=implementation,
                                             pair_id=pair_id, session_id=f'session-{serial}',
                                             build_sha=getattr(args, prefix+'_sha'),
                                             binary_sha256=digest({k: binaries[prefix+'-'+k] for k in ['client','server']}),
                                             workload_sha256=digest({'workload':workload, 'spec':WORKLOAD}),
                                             network_profile='loopback-relay-no-added-impairment-v1',
                                             acquisition_profile='userspace-udp-relay-v1',
                                             observation_duration_ms=WINDOW*1000,
                                             evidence_kind='real-terminal-capture', observation_ok=True,
                                             session_functioning=True, capture_dropped_packets=0, packets=packets))
                            row.update(status='passed', health=health)
                        except Exception as exc:
                            row.update(status='failed', error=str(exc))
                            raise
                        finally:
                            ledger.append(row)
                            (args.output/'ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
                            (args.output/'corpus.json').write_text(json.dumps(runs,indent=2)+'\n')
                        print(pair_id, implementation, 'passed', len(packets), 'datagrams', flush=True)
        finally:
            daemon.terminate(); daemon.wait(timeout=5)
            cleanup_children()
    report = compare(runs)
    (args.output/'summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
