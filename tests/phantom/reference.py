#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Slow, test-only independent arithmetic wire oracle. Never use in a transport.

ChaCha/Poly1305 here avoid checking OpenSSL against itself. RFC vectors anchor
both the primitive implementation and the eight-byte header-mask composition.
"""
import hmac
import json
import struct
import subprocess
import sys

MASK32 = (1 << 32) - 1


def block(key, counter, nonce):
    state = list(struct.unpack('<4I', b'expand 32-byte k') + struct.unpack('<8I', key)
                 + (counter,) + struct.unpack('<3I', nonce))
    x = state.copy()

    def qr(a, b, c, d):
        def rotate(v, n):
            return ((v << n) & MASK32) | (v >> (32 - n))
        x[a] = (x[a] + x[b]) & MASK32; x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & MASK32; x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & MASK32; x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & MASK32; x[b] = rotate(x[b] ^ x[c], 7)

    for _ in range(10):
        for quartet in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            qr(*quartet)
    return struct.pack('<16I', *((a + b) & MASK32 for a, b in zip(x, state)))


def aead(key, nonce, aad, plaintext):
    cipher = bytearray()
    for offset in range(0, len(plaintext), 64):
        stream = block(key, 1 + offset // 64, nonce)
        cipher.extend(a ^ b for a, b in zip(plaintext[offset:offset + 64], stream))
    poly_key = block(key, 0, nonce)[:32]
    r = int.from_bytes(poly_key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(poly_key[16:], 'little')
    auth = aad + bytes((-len(aad)) % 16) + cipher + bytes((-len(cipher)) % 16)
    auth += struct.pack('<QQ', len(aad), len(cipher))
    accumulator = 0
    for offset in range(0, len(auth), 16):
        accumulator = ((accumulator + int.from_bytes(auth[offset:offset + 16] + b'\x01', 'little')) * r) % ((1 << 130) - 5)
    return bytes(cipher) + ((accumulator + s) % (1 << 128)).to_bytes(16, 'little')


def expand(key, info, length):
    output = previous = b''
    for index in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(key, previous + info + bytes([index]), 'sha256')
        output += previous
    return output[:length]


def record(direction, payload, pn=0, epoch=0, ack=0):
    master = hmac.digest(b'phantom-mosh/v3/draft-01', bytes(range(32)), 'sha256')
    traffic = expand(master, direction, 32)
    for _ in range(epoch):
        traffic = expand(traffic, b'traffic update', 32)
    key, iv, hp = (expand(traffic, label, length) for label, length in
                   ((b'traffic key', 32), (b'traffic iv', 12), (b'header protection', 32)))
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, 'big')))
    aad = pn.to_bytes(8, 'big')
    cipher = aead(key, nonce, aad, struct.pack('>II', epoch, ack) + payload)
    mask = block(hp, int.from_bytes(cipher[:4], 'little'), cipher[4:16])[:8]
    return bytes(a ^ b for a, b in zip(aad, mask)) + cipher


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    hp = bytes.fromhex('25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4')
    sample = bytes.fromhex('5e5cd55c41f69080575d7999c25a5bfb')
    check(block(hp, int.from_bytes(sample[:4], 'little'), sample[4:])[:5].hex() == 'aefefe7d03', 'RFC9001 mask')
    expected = bytes.fromhex('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691')
    actual = aead(bytes(range(128, 160)), bytes.fromhex('070000004041424344454647'),
                  bytes.fromhex('50515253c0c1c2c3c4c5c6c7'),
                  b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
    check(actual == expected, 'RFC8439 AEAD')
    expected_records = {
        'empty_client': record(b'client to server', b'').hex(),
        'hello_server': record(b'server to client', b'hello').hex(),
        'client_epoch_one': record(b'client to server', b'epoch one', 1, 1, 0).hex(),
        'server_epoch_one': record(b'server to client', b'ack one', 1, 1, 1).hex(),
        'client_epoch_two': record(b'client to server', b'epoch two', 2, 2, 1).hex(),
        'server_epoch_two': record(b'server to client', b'ack two', 2, 2, 2).hex(),
        'maximum_client_epoch_three': record(b'client to server', b'Q' * 1168, 3, 3, 2).hex(),
    }
    if len(sys.argv) == 2:
        result = subprocess.run([sys.argv[1], '--vectors'], check=True, capture_output=True, text=True, timeout=10)
        check(json.loads(result.stdout) == expected_records, 'independent whole-record comparison')
    print(json.dumps(expected_records, sort_keys=True))
    print('PASS independent integer ChaCha/Poly1305 + whole-record oracle')


if __name__ == '__main__':
    main()
