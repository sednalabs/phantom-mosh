# Security considerations

The record protocol is experimental and has not received independent
cryptographic review. The inherited Mosh executables still use upstream v2;
only the separate opt-in Phantom executables use the new protocol. Do not treat
this experimental fork as a production-security replacement for upstream Mosh.
The [architecture guide](architecture.md) describes the components and their
separate responsibilities.

## Trust and assurance boundaries

| Boundary | What it provides | What remains outside that claim |
| --- | --- | --- |
| SSH startup | Existing host trust and authenticated selection of the exact application profile and fresh bootstrap | A trusted local machine, remote account, SSH configuration and server binary |
| Record layer | Confidentiality and authentication using the specified custom composition; replay and key-lifetime controls | Independent proof of that composition, traffic anonymity or recovery from a compromised endpoint |
| Session channel | Bounded control handling, UDP return-path validation and recovery while the owner remains alive | Flood immunity, durable process restoration or a guarantee that an unreachable remote shell has exited |
| SSP and terminal | State synchronisation, PTY integration and the specific regression coverage described in their guides | A complete security audit of inherited parsers, compression, terminal handling and process management |

Reviewing one row does not establish the security of the others. In particular,
record-layer test results do not certify the entire remote terminal.

## Implemented protections

The record layer encrypts epoch and acknowledgement fields, protects packet
numbers with a separate header-protection key, and derives independent traffic
keys for each direction. It authenticates and validates records before advancing
replay, acknowledgement or receive-epoch state.

Key updates require an authenticated acknowledgement of the current epoch.
Receiver work is bounded to three key candidates per datagram, with a replay
window, per-key usage limits and previous-key retirement. Accepting a reordered
record does not authorize changing the peer address.

The [protocol specification](protocol-draft-01.md) defines these mechanisms and
the caller's responsibilities. Tests exercise the implementation; they do not
constitute a proof of the protocol's security.

The integrated SSH supervisor requires existing host trust, exact profile
selection, bounded output, EOF and a successful SSH exit before accepting
bootstrap material. The session channel separately validates UDP return paths
before activation or migration, limits control replies to the size of their
authenticated requests, and expires unconfirmed startup owners. See
[SSH startup](ssh-startup.md) and [session control](remote-session.md).

## Limitations

**No post-compromise recovery.** A compromised traffic secret or precomputed
successor can reveal future symmetric-ratchet states. There is no fresh
Diffie-Hellman or post-quantum exchange. Protection of earlier epochs depends on
erasing the bootstrap, master, previous keys and their copies at both endpoints.
Logs, environment variables, crash dumps, swap and snapshots can retain secrets;
explicit memory cleansing does not prove that every system-level copy is gone.

**No session restoration or clone protection.** Recovery from packet loss,
network changes and suspension assumes that the existing owner and its complete
state survive. A process restart requires a fresh authenticated bootstrap. Never
continue a live session from duplicated process memory, a cloned VM or a restored
checkpoint, even if its counters appear intact. Noncopyable C++ ownership does
not prevent operating-system process copies or VM snapshots; clone detection and
checkpoint restoration are not implemented. The server detaches before creating
its session material, but that does not make later cloning safe. A production
integration would also need a reviewed secret-handling and crash-dump policy.

**No established fingerprint resistance.** Small, pinned
[loopback traffic measurements](integrated-loopback-pilot.md) show visible
packet-size/count/rate differences; they are not classifier or privacy results.
Packet direction, lengths, timing,
bootstrap correlation and migration continuity remain observable. Removing
explicit fields does not make traffic indistinguishable from other UDP protocols.
There is no cover traffic, timing jitter or protocol impersonation.

**No flood immunity or endpoint authenticity from UDP alone.** The integrated
return-path proof establishes reachability, not protection against an on-path
relay or a compromised endpoint. Bounded decryption, candidate-path and reply
work do not solve flooding. Verification-budget exhaustion closes the session;
an attacker can cause that loss of availability. The record library alone does
not validate routes. Do not reflect local exception details to unauthenticated
senders.

**No hostile-process containment.** The terminal server owns its PTY and ordinary
descendants using Linux subreaper/pidfd support, but is not a sandbox or cgroup
boundary. Userspace deadlines cannot force a kernel-uninterruptible process to
finish. The authenticated server, shell, SSH configuration and local environment
remain trusted. Run experiments in accounts and networks you control. Confirmed
terminals have no idle expiry by default; a broken client or unavailable server
can require manual cleanup. Closing the local client while the network is down
is not proof that the remote process exited.

## Review priorities

The eight-byte header-protection mask, sample selection, cross-epoch acceptance
rules and usage limits need independent protocol review. RFC vectors check
primitive conformance, not the security of this custom composition. A maintained
OpenSSL implementation is a dependency, including its timing behavior.

Acceptance work still includes independent composition review, reproducible
provider/allocation-failure coverage, state-machine analysis, process and secret
lifetime review, and broader end-to-end failure and real-network testing. The
[source review dated 5 November 2026](protocol-review-2026-11-05.md) is AI-assisted
and revision-bound. Additional local review or successful experiments do not
become maintained repository coverage without an inspectable implementation and
validation receipt. None substitutes for independent cryptographic review.

Real SSH/PTY and loopback recovery tests exist, but do not establish kernel-NAT,
WAN or physical-link acceptance. A simulated long outage is not a long-running
deployment. The proposed transport-independent architecture and QUIC DATAGRAM
comparison in the [roadmap](integration.md) are research directions, not an
implemented replacement or a transfer of QUIC's security analysis to this protocol.

Do not attach live keys, terminal contents or private captures to public reports.
Follow [SECURITY.md](../../SECURITY.md) for reporting guidance.
