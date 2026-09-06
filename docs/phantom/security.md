# Security review notes and claim boundaries

This draft is experimental and has not received independent cryptographic review.
It implements protocol mechanisms; it does not certify a production terminal.

## Threats addressed by the component

A passive observer should no longer receive the old explicit direction/sequence
nonce or the prototype's clear version/flags/epoch/ACK header. An unauthenticated
sender cannot legitimately advance epoch, ACK or replay state without a valid
AEAD record. A receiver does at most three key trials per bounded datagram.
Single-owner numbering, per-key usage limits, replay rejection and authenticated
ACK-gated updates address nonce reuse, duplication and outage desynchronization.

These statements concern the source contract and its tests, not a proof of the
custom header-protection composition or immunity to implementation defects.

## Threats NOT solved

A compromised current/successor traffic secret predicts future symmetric ratchet
states. No post-compromise healing, fresh Diffie-Hellman, PQ exchange or new SSH
identity scheme is present. Historical-epoch secrecy depends on genuinely erasing
the bootstrap, master and prior keys across all endpoints and their copies.
Keeping a bootstrap string in a launcher, log, environment, crash dump, swap,
checkpoint or VM snapshot defeats that property. OPENSSL_cleanse does not prove
that registers, compiler/runtime copies, the OS or a hypervisor retain no secrets.

The process must remain alive and retain valid state across a network outage.
Reboot, fork/clone reuse, checkpoint rollback and session restoration are not
supported. Reusing a bootstrap with reset counters is forbidden. Clone detection
is not implemented. A production integration needs a documented custody/lifetime
review, a dump policy, and fresh authenticated setup on restart.

Wire direction is still visible from IP/UDP endpoints. Lengths, timing, periodic
ACKs, bootstrap correlation, duration and migration continuity are not concealed.
Removing fields is not indistinguishability from random bytes, benign UDP or QUIC.
There is no constant-rate cover, artificial jitter or protocol impersonation.

Bounded work is not network-flood defense. Routing, anti-amplification, peer-address
validation, per-source admission and scheduler fairness belong to the transport.
No generic exception text should be reflected back to unauthenticated traffic.
Cryptographic failure-budget exhaustion intentionally sacrifices availability to
avoid exceeding the local exposure bound. An attacker may cause that closure.

## Review decisions and open questions

Retain the directional acknowledgement-gated ratchet. Reject clear lifecycle
metadata. Protect the complete packet number instead of guessing last+1 under
loss. Try only adjacent precomputed receive epochs; never keep a session master
for arbitrary recovery. Keep a bounded previous-key grace slot. Make successful
out-of-order delivery distinct from permission to rebind a peer address.

The full eight-byte HP mask, sample selection, cross-epoch acceptance rules and
usage caps need independent cryptographic/protocol review. RFC vectors establish
primitive/API conformance, not a composition proof. Constant-time properties of
the chosen maintained OpenSSL build remain a dependency. Allocation/provider
fault injection and exhaustive formal state-machine verification remain follow-up
work; exceptional-path ownership is reviewed but not universally proved.

Tests cover each-byte/bit tampering, wrong roles/keys, authenticated invalid fields,
replay, ordering, simultaneous updates, old-key retirement, hard limits and a
seeded lossy model. The real UDP test validates the exposed rebind rule only.
A new terminal frontend must pass an independent end-to-end review and tests
before any release claim. Existing upstream Mosh tests must continue to pass.

Security reports belong in this fork's GitHub security reporting facilities when
available. Do not attach live session keys, terminal contents or private captures
to public issues. This PR does not create a private reporting service.
