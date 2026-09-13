#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""TEST ONLY: finite SSH startup producer and independent UDP responder.

The responder has a three-second lease. It is not the production server,
terminal integration, or a model for Python secret custody.
"""
import base64
import hmac
import os
import select
import socket
import sys
import time
from reference import aead, block, expand

PROFILE = 'phantom-mosh/v3/draft-01'
PAYLOAD = bytes([1, 3, 3, 7])


def record(root, direction):
    master = hmac.digest(PROFILE.encode(), root, 'sha256')
    traffic = expand(master, direction, 32)
    key = expand(traffic, b'traffic key', 32)
    iv = expand(traffic, b'traffic iv', 12)
    hp = expand(traffic, b'header protection', 32)
    cipher = aead(key, iv, bytes(8), bytes(8) + PAYLOAD)
    mask = block(hp, int.from_bytes(cipher[:4], 'little'), cipher[4:16])[:8]
    return mask + cipher  # packet number zero XOR mask


def main():
    if sys.argv[1:] != ['--startup-profile', PROFILE]:
        return 2
    root = os.urandom(32)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    port = udp.getsockname()[1]
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_r)
            os.setsid()
            with open(os.devnull, 'r+b', buffering=0) as null:
                for fd in (0, 1, 2):
                    os.dup2(null.fileno(), fd)
            expected = record(root, b'client to server')
            response = record(root, b'server to client')
            os.write(ready_w, b'R'); os.close(ready_w)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                udp.settimeout(max(0.001, deadline - time.monotonic()))
                data, peer = udp.recvfrom(1201)
                if hmac.compare_digest(data, expected):
                    udp.sendto(response, peer)
                    break
        except (OSError, TimeoutError):
            pass
        finally:
            udp.close()
            os._exit(0)
    os.close(ready_w); udp.close()
    if not select.select([ready_r], [], [], 1)[0] or os.read(ready_r, 1) != b'R':
        os.close(ready_r)
        os.kill(pid, 9); os.waitpid(pid, 0)
        return 3
    os.close(ready_r)
    offer = ('PHANTOM CONNECT ' + PROFILE + ' server client ' + str(port) + ' '
             + base64.b64encode(root).decode().rstrip('=') + '\n').encode()
    if os.write(1, offer) != len(offer):
        os.kill(pid, 9); os.waitpid(pid, 0)
        return 4
    # sshd must observe EOF and success while the bounded UDP responder runs.
    return 0


if __name__ == '__main__':
    os._exit(main())
