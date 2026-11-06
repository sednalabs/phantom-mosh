#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent draft-02 status-only wire vectors, not a cryptographic oracle."""
import subprocess
import sys


def decode(frame):
    if len(frame) != 6 or frame[:4] != b'PTS\x02':
        raise ValueError('not a status-only draft-02 state')
    kind, value = frame[4:]
    if kind == 1:
        return value
    if kind == 2 and 0 < value < 65:
        return min(255, 128 + value)
    raise ValueError('invalid final status')


expected = ['505453020100', '505453020107', '5054530201ff', '505453020209']
actual = subprocess.check_output([sys.argv[1], '--vectors'], text=True, timeout=5).splitlines()
if actual != expected:
    raise RuntimeError('draft-02 encoder differs from independent fixed vectors')
if [decode(bytes.fromhex(value)) for value in actual] != [0, 7, 255, 137]:
    raise RuntimeError('status decoder differs from expected process results')
print('independent terminal status vectors passed')
