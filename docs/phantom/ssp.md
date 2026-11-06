# SSP connection adapter

The opt-in Linux `SspTransport<MyState, RemoteState>` connects the inherited Mosh
State Synchronization Protocol to `SessionChannel`. It reuses Mosh's state-diff,
compression, fragmentation, acknowledgement, retransmission and shutdown engine.
It does not wrap legacy OCB packets or implement a second state protocol.

The existing Mosh executables still select the default `Network::Connection`
backend and v2 wire protocol. The control-only Phantom server/probe do not create
terminals or select the SSP application. The separate experimental
[terminal executables](terminal-integration.md) now connect this adapter to a PTY
and local frontend. Production integration and packaging remain incomplete.

## Ownership and scheduling

Construct a channel and its `SspTransport` with the same monotonic millisecond
clock. Call `service(now)` on socket readiness and timer wakeups. It pumps one
bounded channel batch, admits only complete timing envelopes with an SSP fragment
header, processes those fragments and runs the SSP sender. `wait_time()` combines
channel retry/key-retirement deadlines with SSP scheduling; `fds()` supplies
borrowed descriptors. No unbounded receive loop or additional retransmit queue is
introduced. The channel remains the sole owner of sockets and record counters.

The connection backend supplies SSP's clock as well as its payload budget. This
keeps all state timestamps in the same clock domain, including logical-time tests
and suspend-inclusive `session_time_ms()` in a future Linux frontend. Stock Mosh
continues to use its existing frozen timestamp source.

A retryable local send failure is recorded as loss, not delivery or an ACK. SSP
retains its own states and recomputes retransmissions with new record numbers.
Draining a receive batch is required before another pump; retained buffers are
bounded by the channel receive budget and cleansed when consumed or discarded.
SSP's own string/state copies retain their inherited lifetime behavior.

## Confidential timing envelope

Each encrypted session DATA payload has this layout:

```
application_version[1] | send_serial[8] | echoed_serial[8] | hold_ms[4] | SSP fragment
```

Version is 1; integers are unsigned big-endian. These fields are inside the
existing authenticated encryption, not public record headers. There is no clear
SSP marker. Both endpoints must explicitly select this application; the adapter
does not negotiate a downgrade or turn the diagnostic probe into an SSP peer.

A monotonically allocated serial identifies a local send timestamp in a bounded
128-entry table. Serials never repeat within an adapter, even on failed sends or
path changes. Several fragments sent during one millisecond still have different
identities. A peer echoes the newest serial and its local holding duration;
zero echo means no sample. RTT is local elapsed time minus that duration, without
requiring synchronized clocks or reconstructing truncated remote timestamps.

Only successful local sends enter the table. Unknown, evicted, duplicate,
expired and pre-migration echoes cannot become measurements. Holding time is
bounded to 1000 ms and samples to 10 seconds. Impossible negative samples are
ignored. The smoothed RTT and variance use 1/8 and 1/4 update weights, with Mosh's
50–1000 ms retransmission-timeout bounds. Migration or a long gap resets the path
estimate and pending measurements, but never resets serial allocation.

RTT measurements do not acknowledge SSP states, record epochs or terminal input.
Those remain separate authenticated protocol events. An authenticated malicious
peer can still misreport timing; this is scheduling telemetry, not proof of delay.

## Fragment accounting

The maximum encrypted UDP datagram remains 1200 bytes, excluding IP/UDP headers:

| Layer | Bytes |
| --- | ---: |
| Encrypted record overhead | 32 |
| Session DATA framing | 17 |
| SSP timing envelope | 21 |
| SSP fragment header | 10 |
| Maximum compressed fragment contents | 1120 |

SSP receives a 1130-byte fragment budget. The fragmenter deducts its own 10-byte
header exactly once. It rejects budgets that cannot contain fragment contents,
rather than underflowing or looping. The legacy connection computes its budget
using the unchanged v2 timestamp/nonce/tag constants.

No claim of path-MTU discovery, congestion-control modernization, timing
obfuscation or measured fingerprint resistance is added by this adapter.

## Build and test

Prepare the inherited libraries from the same source checkout, then enable the
adapter in the component build. Linux development prerequisites include OpenSSL,
protobuf/protoc, zlib, terminfo/ncurses, Autotools, CMake and a C++17 compiler.

```sh
./autogen.sh
./configure --with-crypto-library=openssl --without-utempter
make -j2
cmake -S src/phantom -B build/ssp \
  -DPHANTOM_BUILD_SSP=ON -DPHANTOM_MOSH_BUILD_DIR="$PWD"
cmake --build build/ssp --parallel 2
ctest --test-dir build/ssp --output-on-failure
```

Do not supply archives from another revision. When enabling sanitizers, rebuild
both the inherited libraries and the adapter with the same instrumentation. The
SSP CI workflow does this on standard `ubuntu-24.04` runners. The standalone
record/session build remains usable without the additional SSP dependencies.

The convergence test uses actual `Terminal::Complete` and `UserStream` models,
protobuf instructions, compression, fragmentation, encrypted records and real
IPv4/IPv6 UDP sockets. A deterministic socket interposer drops, duplicates and
reorders encrypted datagrams and injects retryable local send errors. It checks
screen contents, attributes, UTF-8, resize events, exactly-once input delivery,
state acknowledgements, recovery after a logical 180-day blackout, socket
migration and SSP shutdown before channel close. It also asserts datagram sizes
at the socket boundary, rather than checking only a constant in isolation.

This convergence test exercises terminal state rather than a launched shell.
The separate `phantom-terminal-ssh` test exercises the actual experimental
SSH-to-PTY client/server; see [terminal-integration.md](terminal-integration.md).
It does not establish native Windows support, packaging readiness, independent
cryptographic assurance or privacy against statistical classifiers.

## Silent NAT remapping

After a successful client send goes unanswered for five seconds, the SSP adapter
requests a new HELLO/challenge/CONFIRM proof on its existing socket. Only admitted,
authenticated SSP frames or successful path activation reset that timer. Idle
silence with no unanswered send does not start probes. This is a conservative
liveness heuristic, not a measured RTT guarantee: a one-way application workload
may also trigger a proof. The session keeps all record counters and replay state;
DATA from an unvalidated source still cannot move the server route. Once recovery
starts, existing retry backoff and any explicit recovery deadline remain in force.

The convergence test additionally runs through a user-space UDP NAT relay on
IPv4 and IPv6. Its outside socket gets a new real source port while the client's
socket and destination remain unchanged. Tests cover remapping amid loss,
duplication and reordering, delayed old-path traffic, a second remap during the
logical 180-day blackout, terminal/input convergence and orderly shutdown.
A source-port change is asserted, and the server's validated peer must remain the
new mapping after delayed old-path traffic. SSP connection tests check the exact
five-second boundary, idle silence, malformed authenticated frames and accepted
responses. Before the recovery change, the relay case failed to converge during
a 30-second logical recovery window; direct IPv4/IPv6 cases passed.

These tests use real loopback UDP and deterministic logical time. They do not
exercise kernel conntrack, a physical router, WAN timing, packet queue congestion,
path-MTU changes, cross-address-family migration or a launched PTY. A privileged
network-namespace/router experiment remains separate acceptance work; the relay
must not be described as empirical kernel-NAT validation.
