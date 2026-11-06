# SPDX-License-Identifier: GPL-3.0-or-later
import socket
import tempfile
import time
from pathlib import Path
import unittest

from loopback_pilot import Relay


class RelayTests(unittest.TestCase):
    def test_bidirectional_metadata_only(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(('127.0.0.1', 0))
            server.settimeout(2)
            client.bind(('127.0.0.1', 0))
            client.settimeout(2)
            target = Path(temp)/'port'
            target.write_text(str(server.getsockname()[1]))
            relay = Relay(target)
            try:
                relay.start = time.monotonic()
                client.sendto(b'abc', ('127.0.0.1', relay.port))
                payload, peer = server.recvfrom(100)
                self.assertEqual(payload, b'abc')
                server.sendto(b'defgh', peer)
                self.assertEqual(client.recvfrom(100)[0], b'defgh')
            finally:
                relay.close()
            self.assertEqual([p['udp_payload_bytes'] for p in relay.rows], [3, 5])
            self.assertEqual([p['direction'] for p in relay.rows], [1, -1])
            self.assertEqual(set(relay.rows[0]), {'time_ms', 'udp_payload_bytes', 'direction'})
            self.assertEqual(relay.received, relay.forwarded)
            self.assertEqual(relay.drops, 0)

    def test_extra_sender_rejected(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stranger:
            server.bind(('127.0.0.1', 0)); server.settimeout(2)
            target = Path(temp)/'port'; target.write_text(str(server.getsockname()[1]))
            relay = Relay(target)
            try:
                client.sendto(b'a', ('127.0.0.1', relay.port))
                server.recvfrom(100)
                stranger.sendto(b'b', ('127.0.0.1', relay.port))
                relay.thread.join(2)
                self.assertIn('unexpected relay sender', relay.error)
            finally:
                with self.assertRaises(RuntimeError):
                    relay.close()


if __name__ == '__main__':
    unittest.main()
