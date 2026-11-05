# Record protocol review, 2026-11-05

## Scope and disposition

This is an AI-assisted source and regression-test review, not an independent
external cryptographic audit, a proof, or production approval. The reviewed
revision is `4fb6005f9d8db8228024fd12560341e0d501ea1a` (SSP adapter draft).
`record.cc`, `record.h`, `crypto_internal.h`, the record tests and the protocol
and security documents define this review's boundary. Socket admission, SSH,
PTY handling and SSP correctness need their own reviews.

No new record-layer implementation defect was established. No wire semantics,
profile identifier or production cryptographic code is changed by this review.
Three deterministic regression groups close concrete coverage gaps. Passing
these tests does not remove the production blockers below.

## Results and remaining gates

### Header protection: custom construction remains unproven

`detail::mask` uses a separate direction/epoch key and the first sixteen bytes
of ciphertext plus tag. Even the minimum record supplies a full sample. Its
single eight-byte output stays within the first ChaCha block, avoiding the
OpenSSL raw-ChaCha counter-layout carry distinction. The recovered full packet
number is authenticated as AEAD associated data.

The RFC primitive vectors and independent Python whole-record oracle pass,
including empty and maximum-sized payloads. This checks implementation agreement,
not a security reduction for the eight-byte extension or the sample construction.
An external cryptographer must review composition, chosen-ciphertext behavior,
multi-user bounds and the stated usage/verification limits before production.
Do not infer traffic indistinguishability from this result.

### Nonce ownership: sound under the stated process-state assumption

`Session::seal` consumes `tx_pn` and `tx_count` before allocations/encryption of
the record (record.cc lines 410-421 at the reviewed revision). Packet numbers
never reset during epoch changes. Directional derivation separates client and
server keys; noncopyable Session ownership prevents ordinary C++ object copying.

Bootstrap reuse after restart, fork, snapshot restore or rollback remains unsafe.
The API cannot enforce cross-process freshness. A production owner must ensure a
fresh authenticated bootstrap after loss of state. Provider/allocation failure
injection and process/secret-lifetime auditing remain open; this review did not
simulate allocator or OpenSSL failure.

### Epoch/replay/ACK validation: targeted boundaries now covered

Authentication precedes protocol state commit. `Session::open` rejects future
ACKs, invalid epoch labels, globally replayed numbers, a next-epoch record below
the receive high-water mark, and a retained previous-key record at or beyond the
first accepted current-epoch number (record.cc lines 454-477). Successor derivation
and output allocation precede the receive-state mutation.

Added tests explicitly show:

- Authenticated next-epoch rollback and an epoch-two skip are rejected without
  advancing protocol state.
- A previous-key record cannot authorize a newer path/high-water mark. Legitimate
  delayed old and current records remain accepted without `newest` authority.
- Replay protection spans epochs rather than resetting at an update.
- A replayed packet with a changed, valid-AEAD ACK cannot unlock another send
  epoch. A fresh authenticated ACK can.
- The 4096-packet replay edge and exact 30,000 ms previous-key expiry reject the
  boundary packet while adjacent valid packets continue to work.

The synthetic records deliberately use public fixture keys to isolate validation
from authentication. They do not demonstrate an unauthenticated forgery.

### Key compromise and availability: limitations, not repaired findings

The precomputed successor secret permits derivation of later epochs. Erasing
active roots is not post-compromise recovery; fresh asymmetric key agreement is
absent. Retained previous keys intentionally permit unseen in-window old records
until retirement. Tests do not establish system-wide erasure from dumps or swap.

A session has at most three candidate authentications per datagram, but its
cumulative failed-verification budget can be exhausted by hostile traffic. This
is documented loss of availability, not flood protection. Earlier candidates
also consume budget during legitimate next/previous-key authentication. Network
admission, anti-amplification and fair scheduling remain separate obligations.

## Validation receipt

- Linux, GCC 14.2.0, OpenSSL 3.5.7.
- Release CMake record target: thirteen record-test groups passed.
- Independent integer ChaCha/Poly1305 and full-record oracle passed.
- Direct GCC AddressSanitizer/UndefinedBehaviorSanitizer build of the exact
  reviewed record source and revised record tests: all groups and oracle passed
  with `ASAN_OPTIONS=detect_leaks=0`.
- LeakSanitizer could not run because the execution environment uses ptrace;
  leak checking is **not** claimed.
- clang-format 14 and `git diff --check` passed.
- This receipt is focused record validation, not a full SSP, network, SSH,
  terminal, inherited-Mosh or hosted-CI pass.

The local review copy's record source/header and original record test blob hashes
were matched against the remote revision before changes. No secret or live
traffic capture is included.
