# Datagram channel for application event loops

`SessionChannel` connects the session-control state machine to an owned UDP
socket. Both the diagnostic probe and detached control server use this loop.
It is the datagram boundary for subsequent SSP integration, **not an SSP
implementation or a terminal client**. Records, key derivation and the session
control wire format are unchanged.

## Ownership and interface

The `client` and `server` factories consume a bootstrap secret and take exclusive
ownership of a `SessionSocket`. A channel cannot be copied or moved. It owns
its record counters, path validation state, lifetime timers and socket together.
It neither starts a thread nor registers process-wide callbacks.

An application calls `service(now_ms)` when the socket becomes readable or the
local timer returned by `wait_ms(now_ms)` expires. `fd()` is a borrowed readiness
handle for combining UDP with terminal, signal and application timers in an
outer poll loop. Do not read, close or alter it. Rebinding and closure invalidate
it, so fetch it again when constructing the next poll set.

All time inputs use one nondecreasing monotonic clock; the Linux owner supplies
`session_time_ms()`, which includes suspension. Time queries may look ahead but
do not advance state. A `service` call uses its supplied time for the bounded
batch. The caller must sample again after the call; it must not keep passing a
stale timestamp to avoid expiry. No worker can retire keys while the process is
suspended, and no session may survive a process restart by resetting counters.

## Data and fairness

`service` returns a move-only `ChannelBatch`. Its `data` entries are accepted
application datagrams, in arrival order. An empty DATA payload is an entry with
zero bytes; it is not confused with control traffic or an empty socket. The
batch erases its payload buffers when destroyed. An application that moves data
out owns the lifetime and erasure of those copies.

A call consumes at most 32 socket datagrams by default, configurable from 1 to
64. Oversized, truncated, malformed and unauthenticated packets all count toward
that budget. A consumed-but-discarded datagram is distinct from an empty socket.
The returned budget flag requests another prompt service opportunity, but the
outer loop should still process its other ready descriptors before returning.
This bounds per-call work and storage; it does not claim network flood immunity.

`send` accepts at most **1151 application bytes**: 1200 UDP payload bytes minus
32 record bytes and 17 session-control bytes. An SSP/timestamp adapter must
subtract its own framing from that budget. The channel does not fragment,
reassemble, compress or queue an oversized payload.

A successful send means only that the local kernel accepted the datagram. A
retryable socket error returns `false`; the record's packet number is already
consumed. There is no hidden output queue or automatic application retransmit.
The application must recompute/retransmit through `send`, producing a fresh
record. Reliability, state acknowledgement and remote-confirmed input latency
belong to SSP, not to socket success or path confirmation.

## Timers, route changes and shutdown

Only connection and close control messages are retried. The default interval is
200 ms; established-session route recovery backs off to a five-second maximum.
A late service call sends at most one retry, not a catch-up burst.
Incoming control replies reset that retry interval but cannot renew an absolute
connection deadline. Local key-retirement ticks produce no idle network traffic.
An eventual SSP sender must still schedule ACK-bearing application records;
this channel does not manufacture empty DATA as a fake application ACK.

Initial client connection attempts expire after 10 seconds by default. Once
established, route recovery has no deadline by default: losing a network must not
silently destroy a long-running session. A nonzero `revalidate_ms` can opt into
a bounded recovery episode; repeated rebinds within that episode do not renew it.
Crypto usage caps still apply, including during prolonged one-way failure.
An established client can replace its socket with `rebind`, retaining the **same**
crypto session and packet-number allocator. The new socket must use the same
address family. Application sends pause until the new return path is confirmed.
The old local socket closes at replacement; the server retains its old validated
route until confirmation. This is not a lossless dual-path migration promise.
A second local network change can replace an unconfirmed recovery route without
restarting cryptographic state. Cross-family migration and reliable application
recovery remain separate work.

`start_close` begins an authenticated close, with a three-second client deadline.
Calling it repeatedly does not extend the deadline. `ChannelEnd::peer_closed`
distinguishes an authenticated close acknowledgement from `close_timeout`.
The server uses its existing fixed drain period to recover a lost acknowledgement.
Server-local cancellation uses `stop`, not an invented server-initiated close
message. Closure clears key owners and releases the socket; `fd()` becomes -1.

The server's startup, idle and drain policies remain those of `RemoteSession`.
The standalone control server still discards application DATA. It does not echo
terminal content, acknowledge SSP state or launch a shell.

## Tests and integration boundary

Linux tests use real IPv4/IPv6 sockets and a test-only `sendto` interposer for
lost control replies, held datagrams and explicit transient/fatal send errors.
They cover bidirectional empty/maximal DATA, repeated key updates, replay,
reordering, receive-budget exhaustion, fixed deadlines, descriptor cleanup,
port migration and a logical 180-day pause. The process suite exercises the
actual detached server with a channel-based client, including expiry and signals.

`phantom-session-ssh` exercises the actual server and probe with an isolated
loopback sshd, disposable host/user keys, a non-DNS alias and a quoted remote
executable path. Missing tools are a visible local skip; with
`PHANTOM_REQUIRE_SSH_TESTS=ON`, missing tools fail. Test registration is not proof
that it ran: inspect the corresponding CTest results for the tested revision.

The next SSP change must define and test the timestamp/RTT interface, fragment
budget and connection abstraction, then exercise real terminal state convergence.
Do not replace those tests with a successful arbitrary-payload echo.
