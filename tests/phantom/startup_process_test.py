#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Local process/pipe/UDP integration, not an SSH authentication test.

Only public test fixtures enter the Python process. The production reader is
C++, and the independent record oracle is test-only arithmetic code.
"""
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from reference import record

HELPER = sys.argv.pop(1)
KEY = b'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
PREFIX = b'PHANTOM CONNECT phantom-mosh/v3/draft-01 server client '


def offer(port=60000):
    return PREFIX + str(port).encode('ascii') + b' ' + KEY + b'\n'


class StartupProcessTests(unittest.TestCase):
    def start(self, fd, timeout=1000, interrupt=False):
        args = [HELPER, str(fd), str(timeout)]
        if interrupt:
            args.append('interrupt')
        child = subprocess.Popen(args, pass_fds=(fd,), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotIn(KEY.decode('ascii'), ' '.join(child.args))
        self.addCleanup(self.stop, child)
        return child

    @staticmethod
    def stop(child):
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)

    def rejected(self, child, timeout=3):
        out, err = child.communicate(timeout=timeout)
        self.assertEqual(child.returncode, 1)
        self.assertEqual(out, b'')
        self.assertEqual(err, b'startup rejected\n')
        self.assertNotIn(KEY, out + err)

    def test_pipe_to_encrypted_udp(self):
        for fragmented in (False, True):
            with self.subTest(fragmented=fragmented), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                peer.bind(('127.0.0.1', 0))
                peer.settimeout(3)
                read_fd, write_fd = os.pipe()
                try:
                    child = self.start(read_fd, timeout=2000)
                finally:
                    os.close(read_fd)
                try:
                    frame = offer(peer.getsockname()[1])
                    if fragmented:
                        for offset in range(0, len(frame), 3):
                            os.write(write_fd, frame[offset:offset + 3])
                            time.sleep(0.001)
                    else:
                        os.write(write_fd, frame)
                finally:
                    os.close(write_fd)
                incoming, address = peer.recvfrom(1201)
                self.assertEqual(incoming, record(b'client to server', b'startup handoff'))
                peer.sendto(record(b'server to client', b'handoff confirmed'), address)
                out, err = child.communicate(timeout=3)
                self.assertEqual((child.returncode, out, err), (0, b'handoff confirmed\n', b''))

    def test_stream_socket_handoff(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0))
            peer.settimeout(3)
            sender, receiver = socket.socketpair()
            try:
                child = self.start(receiver.fileno())
                receiver.close()
                sender.sendall(offer(peer.getsockname()[1]))
                sender.shutdown(socket.SHUT_WR)
                incoming, address = peer.recvfrom(1201)
                self.assertEqual(incoming, record(b'client to server', b'startup handoff'))
                peer.sendto(record(b'server to client', b'handoff confirmed'), address)
                out, err = child.communicate(timeout=3)
                self.assertEqual((child.returncode, out, err), (0, b'handoff confirmed\n', b''))
            finally:
                sender.close()
                receiver.close()

    def test_malformed_and_trailing_output(self):
        invalid = [b'', offer()[:-1], offer() + b'\n', b'banner\n' + offer(),
                   offer() + offer(), b'x' * 1024,
                   offer().replace(b'draft-01', b'draft-02'),
                   b'MOSH CONNECT 60000 ' + KEY + b'\n']
        for value in invalid:
            with self.subTest(length=len(value)):
                read_fd, write_fd = os.pipe()
                try:
                    child = self.start(read_fd)
                finally:
                    os.close(read_fd)
                try:
                    os.write(write_fd, value)
                finally:
                    os.close(write_fd)
                self.rejected(child)
        # A second read carrying trailing text must also invalidate the offer.
        read_fd, write_fd = os.pipe()
        try:
            child = self.start(read_fd)
        finally:
            os.close(read_fd)
        try:
            os.write(write_fd, offer())
            time.sleep(0.03)
            os.write(write_fd, b'late output')
        finally:
            os.close(write_fd)
        self.rejected(child)

    def test_eof_required_and_deadline_interruptions(self):
        for data, interrupt in ((b'', False), (offer()[:10], False), (offer(), False), (b'', True)):
            with self.subTest(length=len(data), interrupted=interrupt):
                read_fd, write_fd = os.pipe()
                try:
                    child = self.start(read_fd, timeout=150, interrupt=interrupt)
                finally:
                    os.close(read_fd)
                try:
                    os.write(write_fd, data)
                    # Writer stays open: a line terminator alone cannot admit a session.
                    self.rejected(child)
                finally:
                    os.close(write_fd)

    def test_trickling_does_not_restart_deadline(self):
        read_fd, write_fd = os.pipe()
        try:
            child = self.start(read_fd, timeout=150)
        finally:
            os.close(read_fd)
        stop = threading.Event()

        def trickle():
            try:
                for byte in offer():
                    if stop.is_set():
                        break
                    os.write(write_fd, bytes([byte]))
                    stop.wait(0.05)
            except BrokenPipeError:
                pass
            finally:
                os.close(write_fd)

        writer = threading.Thread(target=trickle)
        writer.start()
        try:
            self.rejected(child, timeout=3)
        finally:
            stop.set()
            writer.join(timeout=2)
            self.assertFalse(writer.is_alive())

    def test_parameters_and_descriptor_type(self):
        for timeout in (0, -1, 120001):
            read_fd, write_fd = os.pipe()
            try:
                child = self.start(read_fd, timeout=timeout)
            finally:
                os.close(read_fd)
            try:
                self.rejected(child)
            finally:
                os.close(write_fd)
        with open(os.devnull, 'rb') as device:
            self.rejected(self.start(device.fileno()))
        with tempfile.TemporaryFile() as regular:
            self.rejected(self.start(regular.fileno()))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            self.rejected(self.start(datagram.fileno()))

    def test_unauthenticated_reply_rejected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0))
            peer.settimeout(3)
            read_fd, write_fd = os.pipe()
            try:
                child = self.start(read_fd)
            finally:
                os.close(read_fd)
            try:
                os.write(write_fd, offer(peer.getsockname()[1]))
            finally:
                os.close(write_fd)
            _, address = peer.recvfrom(1201)
            forged = bytearray(record(b'server to client', b'handoff confirmed'))
            forged[-1] ^= 1
            peer.sendto(forged, address)
            self.rejected(child)


if __name__ == '__main__':
    unittest.main()
