# Security considerations

The record protocol is experimental and has not received independent
cryptographic review. The existing Mosh executables do not use it yet.

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

**No measured fingerprint resistance.** Packet direction, lengths, timing,
bootstrap correlation and migration continuity remain observable. Removing
explicit fields does not make traffic indistinguishable from other UDP protocols.
There is no cover traffic, timing jitter or protocol impersonation.

**No flood or path-validation guarantee.** Bounded decryption work does not solve
flooding. Address validation, anti-amplification, admission limits and scheduling
belong to the transport integration. Verification-budget exhaustion closes the
session; an attacker can cause that loss of availability. Do not reflect local
exception details back to unauthenticated senders.

## Review priorities

The eight-byte header-protection mask, sample selection, cross-epoch acceptance
rules and usage limits need independent protocol review. RFC vectors check
primitive conformance, not the security of this custom composition. A maintained
OpenSSL implementation is a dependency, including its timing behavior.

Further work includes provider/allocation failure injection, state-machine
verification, secret-lifetime review and end-to-end SSH/terminal testing. The
loopback UDP test checks admission and rebinding rules, not complete terminal
integration. A simulated long outage is not a long-running deployment.

Do not attach live keys, terminal contents or private captures to public reports.
Check the repository's Security page for available reporting options.
