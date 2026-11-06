# Real-clock terminal recovery qualification

Ops: w18888. This lane combines terminal PR #7 at
`ebd798fd58cca6540a3c6da9869f7124e194ac7c` with PR #6's recovery fix at
`9e04f4bf6ae4dbad4c47251539b0849c7770281f`, without changing either branch.
It closes the gap between #6's logical-clock terminal-state test and #7's
actual SSH-launched PTY. It is not kernel-NAT or WAN qualification.

## Fixture and acceptance

`phantom-terminal-recovery` launches the actual terminal client/server through
isolated OpenSSH with disposable keys and pinned host trust. Its IPv4 loopback
relay has a stable client-facing socket and a replaceable server-facing socket.
Both replacements must allocate genuinely different UDP source ports; the
client's source endpoint and destination stay unchanged.

The test changes the relay source port during active input, then changes it again
during a real two-second bidirectional blackout. Both recovery phases include
deterministic packet loss, duplication and delayed forwarding. Retained encrypted
old-path datagrams are replayed after recovery, followed by fresh remote work.
Computed shell counters must be exactly 1, 2 and 3 in sequence; command echo
cannot satisfy those witnesses. It also checks remote UTF-8 output, a resize to
31 rows by 91 columns, orderly client/server shutdown, descendant cleanup and
restoration of local termios. Each computed recovery witness has a 25-second
wall-clock deadline. Missing OpenSSH is a skip, or a failure with `--required`.

Packet bytes and synthetic terminal output exist only transiently in memory.
The retained evidence includes timing, aggregate relay counters and boolean
acceptance results, not payloads, session keys, endpoints or terminal transcripts.
Queue-overflow observation must be zero. Deliberate relay drops are separate from
unplanned socket drops. These counters are fixture health, not passive wire data.

## Countercheck and local verification

The same test against a separate, pristine build of #7 at `ebd798f` fails at the
first computed recovery witness after the entire 25-second deadline. Adding
#6's recovery fix passes. Thus this test detects the actual launched-terminal
recovery failure rather than merely rerunning a successful loopback session.

All 21 component, SSP and integration CTests passed on the integrated build.
The inherited `make check` result was 5 passed, 27 skipped, 0 failed. Skips are
not passes. The build used GCC 14.2, protoc 3.21.12 and OpenSSL 3.5.7; inherited
libraries and SSP were built from the same checkout. Three additional runs and
binary/test hashes are in `evaluation/results/terminal-recovery-2026-11-06/`.
Hosted results must be checked for the exact published head; local release tests
do not establish sanitizer or hosted CI success.

Reproduce after the same-checkout build described in [ssp.md](ssp.md):

```sh
ctest --test-dir build/ssp -R phantom-terminal-recovery --output-on-failure -V
python3 tests/phantom/terminal_recovery_test.py \
  build/ssp/phantom-mosh-terminal-server build/ssp/phantom-mosh-terminal --required
```

## Limits and next network acceptance

This is a userspace IPv4 loopback relay with real monotonic time. It does not
exercise kernel conntrack, a physical router, a WAN, path-MTU change, realistic
background traffic or cross-address-family migration. #6 retains separate
logical-clock IPv4/IPv6 coverage, including its logical 180-day outage. The
real two-second blackout here is not evidence of a 180-day real outage.

This executor has zero permitted/effective capabilities, and no authorized
connected remote or owned WAN test endpoint was identified. No host firewall,
route, namespace or other security-sensitive network setting was changed. Real
kernel NAT/WAN work therefore remains unrun, not silently replaced by this relay.
A later owned-router experiment needs scoped endpoints and approved isolated
network administration, then source-port/conntrack evidence and the same computed
terminal witnesses under real link outages.

The terminal-only draft-02/exit-status work proceeds separately. This lane still
uses #7's draft-01 protocol. Any combined revision requires rebuilding and
rerunning this test and the matched traffic collector at that exact revision.
Nothing here establishes fingerprint resistance, privacy equivalence, independent
cryptographic assurance, production readiness, or permission to merge/deploy.
