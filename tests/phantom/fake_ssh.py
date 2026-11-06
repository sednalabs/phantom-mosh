#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deliberately faulty child for process-lifecycle tests; never a crypto provider."""
import json
import os
from pathlib import Path
import signal
import sys
import time

KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
OFFER = ('PHANTOM CONNECT phantom-mosh/v3/draft-01 server client 60000 ' + KEY + '\n').encode()
args = sys.argv[1:]
case = args[args.index('--') + 1]
record = {'pid': os.getpid(), 'group': os.getpgrp(), 'argv': args, 'fds': []}
for fd in Path('/proc/self/fd').iterdir():
    try:
        record['fds'].append(os.readlink(fd))
    except FileNotFoundError:
        pass
Path(os.environ['PHANTOM_TEST_RECORD']).write_text(json.dumps(record))

if case in ('descendant', 'orphan-success'):
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if case == 'orphan-success':
            os.close(1)
        time.sleep(60)
        os._exit(0)
    record['descendant'] = child
    Path(os.environ['PHANTOM_TEST_RECORD']).write_text(json.dumps(record))
    os.write(1, OFFER)
    os._exit(0)
if case == 'empty':
    os._exit(0)
if case == 'stderr':
    for _ in range(200):
        os.write(2, OFFER * 100)
if case == 'malformed':
    os.write(1, b'banner\n' + OFFER)
    time.sleep(60)
if case == 'flood':
    while True:
        os.write(1, b'X' * 4096)
if case == 'stall':
    time.sleep(60)
if case == 'trickle':
    for byte in OFFER:
        os.write(1, bytes([byte]))
        time.sleep(0.05)
if case == 'fragmented':
    for byte in OFFER:
        os.write(1, bytes([byte]))
    os._exit(0)
os.write(1, OFFER)
if case == 'nonzero':
    os._exit(23)
if case == 'signalled':
    os.kill(os.getpid(), signal.SIGTERM)
if case == 'eof-stall':
    os.close(1)
    time.sleep(60)
if case == 'delayed-trailer':
    time.sleep(0.06)
    os.write(1, b'additional bytes\n')

os._exit(0)
