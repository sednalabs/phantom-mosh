# Integration status and roadmap

[Documentation index](README.md) · [Architecture](architecture.md)

Documentation baseline: 20 November 2026. The implementation reviewed for this
refresh is [`c79f486`](https://github.com/sednalabs/phantom-mosh/commit/c79f486dc5ebe703860b3ba4825e0be7fd929fbd),
the default `master` branch after [PR #9](https://github.com/sednalabs/phantom-mosh/pull/9)
and the [PR #10 documentation update](https://github.com/sednalabs/phantom-mosh/pull/10).
The remaining work below is a roadmap, not a claim that those additions have landed.

The default branch includes the record layer, SSH startup, session channel, SSP
adapter, experimental Linux terminal, recovery tests and pinned loopback evidence.
The inherited Mosh executables continue to use v2. The terminal is a separate,
explicit build/install opt-in and remains experimental.

## Implemented

| Capability | Current behaviour | Reference |
| --- | --- | --- |
| Authenticated bootstrap | Existing SSH host trust, exact profile selection, bounded output, EOF and successful SSH exit; address-bound offers | [SSH supervisor](ssh-startup.md) |
| Record protection | Directional HKDF-SHA-256 keys, ChaCha20-Poly1305, protected packet numbers, encrypted epoch acknowledgements, gated key updates and replay protection | [Record draft](protocol-draft-01.md) |
| Remote ownership | Server detaches before key generation; unconfirmed startup expires; terminal owns its PTY and ordinary descendants | [Remote session](remote-session.md), [terminal](terminal-integration.md) |
| Channel and recovery | One socket/crypto owner, bounded receive work, control retry timers and authenticated path revalidation with crypto state retained | [Session channel](session-channel.md) |
| State synchronisation | Inherited SSP engine, explicit timing, full accounting of the 1200-byte UDP record budget | [SSP adapter](ssp.md) |
| Linux terminal | SSH-to-PTY operation, input/display/resize, authenticated remote exit status, local terminal restoration and separate installation | [Terminal setup](terminal-integration.md) |
| Qualification fixtures | Component/reference tests, OpenSSH/PTY tests, logical-time outage tests and real-clock loopback remapping | [Recovery qualification](terminal-recovery.md) |
| Retained measurements | Matched metadata-only pilots with source/binary pins, ledgers and session-health evidence | [Integrated pilot](integrated-loopback-pilot.md) |

Implementation does not imply completion of independent review, distribution
packaging or real-network qualification. Tests available in the source tree
must be distinguished from results actually observed for a particular commit.

## Remaining work

### Security and secret lifetime

The custom cryptographic composition needs independent review. The dated
[record review](protocol-review-2026-11-05.md) and subsequent internal review
work are bounded evidence, not an external audit or deployment approval.
Review must cover the complete terminal/session path as well as the record
layer, including inherited state processing and process/secret lifetime.

Provider and allocation failure coverage needs reproducible evidence tied to
the reviewed revision. Wider process-memory and secret-erasure assurance remains
open. Symmetric key updates do not provide post-compromise recovery. Restart,
cloning and rollback must not reuse live session state or a bootstrap with reset
counters. Fresh authenticated startup is the supported process-restart rule;
network recovery preserves the existing live session instead.

Completion requires a defined review scope, identified reviewer and revisions,
documented resolutions, retained validation evidence and explicit remaining
limits. Passing a test matrix alone does not close this work. See the
[security notes](security.md) and [private reporting guidance](../../SECURITY.md).

### Terminal usability and platforms

Account/login-shell and locale selection, local prediction, escape controls and
distribution packaging remain incomplete. Linux process APIs and `C.UTF-8` are
required by the experimental terminal. There is no persistent reattachment or
restart-resume feature. A native Windows client needs terminal, process,
networking and secret-handling work beyond compiling the record layer.

Future usability work should make connection, outage and shutdown state clear,
provide deliberate cancellation and retain correct exit status and terminal
restoration. Packaging must install the Phantom pair explicitly without silently
replacing the inherited Mosh executables. Acceptance should exercise the installed
binaries and ordinary user workflows, not just library tests.

### Network acceptance

The existing recovery tests use userspace loopback relays. WAN conditions, kernel
NAT, actual Wi-Fi/mobile link changes, path-MTU behaviour and congestion need
separate qualification. The client's server endpoint is fixed; server-address
and cross-address-family migration are not implemented. An established live
session can wait through an outage, but that does not restore a terminated
process or a closed transport connection.

Preserve computed remote output, exact input delivery, final exit status and
cleanup checks when adding network fixtures. Record actual outage duration,
network conditions, build identity, failures and recovery latency. A logical
180-day clock advance is not a 180-day network experiment, and a loopback port
remap is not a physical link handover.

### Transport comparison

The direction is to retain the terminal, SSP integration and lifecycle work as
reusable foundations while comparing the current custom transport with a QUIC
DATAGRAM alternative. **No QUIC backend, transport-selection flag or completed
transport-independent public API exists in the current checkout.** The custom
protocol remains the implemented research baseline.

The [architecture guide](architecture.md#transport-comparison-direction) describes
the proposed boundary. A useful comparison needs an explicit application
contract for identity binding, payload budgets, timers, backpressure, path
changes, connection loss and shutdown, followed by the same terminal acceptance
fixtures on both implementations. Long outages and connection expiry need
deliberate treatment rather than an assumption of equivalent recovery.

Compare latency, loss recovery, idle traffic, CPU/memory, deployment requirements
and maintenance burden on matched workloads. Record protocol-level differences
separately from terminal behaviour. A standards-based backend is an engineering
candidate; it is not an automatic security or fingerprint-resistance result.

### Traffic analysis and release claims

The retained pilots are small, pinned experiments. Their visible differences
in size, count and rate remain part of the evidence. The
[evaluation contract](../../evaluation/contract.json) is still `not_measured`.
No detector acceptance, realistic-background result or independent replication
has been established by those pilots.

The [matched measurement method](matched-measurement.md) and separate
[held-out evaluation](evaluation.md) define what is needed before a statistical
claim. Freeze builds, observers, thresholds and whole-session holdouts before
scoring, and retain failed captures, exclusions and negative results. Equal
packet counts do not establish equivalent traffic distributions. Protecting
selected protocol fields does not remove timing, size or endpoint metadata.

Independent security review, broader terminal/network acceptance and
reproducible measurements are separate milestones. Check CI for the exact commit
under consideration; historical results do not certify a later checkout.
