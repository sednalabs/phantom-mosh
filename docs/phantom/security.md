# Security considerations

The record protocol is experimental and has not received independent
cryptographic review. The inherited Mosh executables still use upstream v2;
only the separate opt-in Phantom executables use the new protocol. Do not treat
this experimental fork as a production-security replacement for upstream Mosh.

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

**No session restoration.** The process must retain its state across network
outages. Restart, process cloning and VM rollback must not reuse a bootstrap with
reset counters. Clone detection and checkpoint restoration are not implemented.
A production integration needs fresh authenticated setup on restart and a
reviewed secret-handling and crash-dump policy.

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

Further work includes provider/allocation failure injection, state-machine
verification, process/secret-lifetime review and broader end-to-end failure and
real-network testing. The source review in [the dated review report](protocol-review-2026-11-05.md)
is AI-assisted, not independent cryptographic certification. Real SSH/PTY and
loopback recovery tests now exist, but do not establish kernel-NAT, WAN or
physical-link acceptance. A simulated long outage is not a long-running deployment.

Do not attach live keys, terminal contents or private captures to public reports.
Follow [SECURITY.md](../../SECURITY.md) for reporting guidance.
