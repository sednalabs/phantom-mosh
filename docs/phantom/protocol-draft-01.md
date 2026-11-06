# Phantom record protocol: draft-01

Status: implemented experimental record contract, not a frozen interoperability
standard. Changes to this draft's byte semantics require a new authenticated
profile identifier. There is no official Mosh-v3 allocation or QUIC compatibility.

## Boundary and authenticated setup

This component accepts a role, a fresh 32-byte random bootstrap secret, a trusted
monotonic millisecond clock and bounded local resource policy. The caller MUST
already have authenticated the exact `phantom-mosh/v3/draft-01` selection and
both endpoint roles through an authenticated channel. SSH remains the intended
identity/bootstrap authority, but that integration is not implemented here.

The text form is exactly 43 canonical unpadded standard-base64 characters.
Whitespace, `=`, URL-safe substitutions and nonzero unused bits are rejected.
The constructor consumes and clears its bootstrap argument, including on failure.
Callers MUST clear their own encoded/input copies and MUST NOT log secrets.
Every new session requires fresh entropy. No process restart, cloned process or
VM rollback may reuse the bootstrap and reset packet numbering.

No UDP cipher negotiation or downgrade fallback exists. A future launcher must
fail closed when an explicitly selected profile is unavailable or mismatched.
Choosing upstream v2 compatibility must be an explicit separate decision.

## Fixed suite and key schedule

All strings below are exact ASCII bytes without trailing NUL. HKDF is RFC 5869
with SHA-256. AEAD is RFC 8439 ChaCha20-Poly1305, with a 32-byte key, a 12-byte
nonce and the complete 16-byte tag. There is no additional HMAC.

```
master = HKDF-Extract(salt="phantom-mosh/v3/draft-01", IKM=bootstrap)
c2s[0] = HKDF-Expand(master, "client to server", 32)
s2c[0] = HKDF-Expand(master, "server to client", 32)
key[e] = HKDF-Expand(traffic_secret[e], "traffic key", 32)
iv[e]  = HKDF-Expand(traffic_secret[e], "traffic iv", 12)
hp[e]  = HKDF-Expand(traffic_secret[e], "header protection", 32)
traffic_secret[e+1] = HKDF-Expand(traffic_secret[e], "traffic update", 32)
```

Each direction advances independently. The active epoch's successor is
precomputed; the active root secret is then erased. Previous receive epochs
retain only derived keys, never an all-epochs master. Holding a successor secret
still permits derivation of future epochs: this is NOT post-compromise recovery.

## Datagram layout

```
protected_packet_number[8] | encrypted(epoch[4] | ack_epoch[4] | payload) | tag[16]
```

All integers are unsigned big-endian. `packet_number` is a session-wide,
per-direction counter starting at zero. It does not reset on a key update.
The maximum is `2^63-1`, preserving a future adapter's internal Mosh packet range.
`epoch` and `ack_epoch` are 32-bit. `ack_epoch` means the highest peer epoch this
receiver has successfully authenticated and accepted, not application delivery.

The AEAD nonce is `iv[e] XOR (zero[4] || packet_number[8])`. AEAD associated data
is the full UNMASKED eight-byte packet number. The inner epoch and ACK are
confidential and authenticated as plaintext. Version, flags, endpoint direction
and connection identity are not carried in clear UDP fields.

Header protection uses a SEPARATE epoch/direction HP key and the first 16 bytes
of ciphertext-plus-tag as a ChaCha sample. Initialize the RFC 9001 section 5.4.4
ChaCha state with that sample and take the first EIGHT keystream bytes; XOR those
with the encoded packet number. This extends the cited construction's five-byte
mask to eight bytes. It is a custom composition requiring independent review,
not a claim that the full QUIC security analysis transfers unchanged.

OpenSSL's raw ChaCha IV has a 64/64 counter/nonce API split. For this single-block
operation its state words match the RFC's 32/96 interpretation of the same
16 bytes. The implementation requests only eight bytes; no counter carry into a
second block is used. RFC and independent full-record vectors check this boundary.

Even an empty payload yields eight encrypted epoch/ACK bytes plus a 16-byte tag,
so a 16-byte sample is always available. Total overhead is 32 bytes. Datagrams
are bounded to 1200 bytes and payloads to 1168 bytes. This budget includes record
overhead, but not IP/UDP headers. Future timestamp/SSP adapters must deduct THEIR
own overhead; they cannot reuse upstream's overhead constants unmodified.
Fixed sizes and overhead remain observable. No padding or shaping is implied.

## Sending and key updates

A single noncopyable/nonmovable Session owns packet numbering. It consumes a
number and packet budget BEFORE encryption, including failed attempts. A failed
`sendto` never permits nonce reuse: send a newly sealed record with a new number,
or retransmit the same immutable bytes if the higher layer explicitly supports
that. Never modify plaintext while reusing a sealed record's number.

Default update triggers are `2^20` attempted records or one hour in an epoch.
A due sender can advance from e to e+1 only after receiving an authenticated ACK
for e. Epoch zero starts with an implicit acknowledgement because setup supplied
both sides with its key material. The receiver can therefore be at most one
unacknowledged epoch behind. Elapsed time alone does not cause multiple updates.
A logical 180-day blackhole test exercises this invariant; it is not a real
six-month deployment or proof of process survival across reboot.

The per-epoch hard bound is `2^24` attempted encryptions. If an ACK cannot arrive
before that budget is exhausted, the session closes and wipes its key material.
It does not exceed the budget to preserve apparent liveness. Exhaustion of the
packet-number or epoch space likewise requires a fresh authenticated bootstrap.
Local policy may reduce limits, not raise the fixed hard cap.

There is no autonomous timer thread or automatic ACK packet generation in this
library. The owner schedules sends and calls `tick`, and must arrange timely
ACK-carrying traffic through the transport. A future SSP adapter owns that work.

## Receiving, replay and bounded work

Reject datagrams shorter than 32 or longer than 1200 bytes. At most THREE
precomputed key candidates are tried: current, next and retained previous.
For each, unmask the packet number, construct the nonce and authenticate the
record. Untrusted epoch bytes never drive a key-derivation loop.

After authentication, require the encrypted epoch to match the candidate, the
ACK not to exceed the local send epoch, and the packet number to be in range and
fresh in the global 4096-packet replay window. The first accepted next-epoch
record must be newer than the receive high-water mark. Previous-epoch records
must precede the first accepted current-epoch record. Legitimate delayed current
records can arrive below that first-seen number and still pass the replay window.

Prepare plaintext output and a possible successor key BEFORE committing replay,
ACK and receive-epoch state. Invalid or duplicate packets cannot advance those
states. API attempts/failure diagnostics and time-based retirement can change
on rejection; they are not packet-authorized protocol progress.

Only an accepted record with `Received.newest == true` may authorize a new peer
address. Accepted reordered records deliver payload without moving the address
backward. The real loopback UDP test demonstrates this adapter rule. The record
library does not itself own sockets, route validation or anti-amplification.

Failed candidate authentications are capped at `2^32` for the entire session,
not reset per epoch. Wrong-candidate trials during valid updates also consume
that conservative budget. Exhaustion closes the session. This bounds verification
exposure and per-packet work; it does not establish flood resistance.

## Retirement, time and failure behavior

Retain at most one previous receive key for 30 seconds after an authenticated
transition, with a configurable maximum of 120 seconds. A further transition
retires that slot earlier. `tick` also retires it while otherwise idle. The owner
MUST schedule ticks; memory cannot be wiped while the process is suspended.
The supplied clock must never go backward and should include suspension when
wall-duration retirement is required. Resume must tick before receiving data.

Keys and temporary secret/plaintext buffers use explicit OpenSSL cleansing and
RAII. The API intentionally has no checkpoint, restore or session-cloning
operation. A fatal limit requires new authentication. Provider/allocation failures
are exceptions; authentication, replay and framing failures return `nullopt`
without exposing a detailed network oracle. The caller must handle local
exceptions without logging key material or retrying old state. These ownership
measures are not a proof that all OS/runtime/allocator copies are erased.

## Normative implementation and tests

`src/phantom/record.{h,cc}` defines this draft. `crypto_internal.h` is not a public
protocol API. RFC 5869 A.1, RFC 8439 2.8.2 and RFC 9001 A.5 vectors anchor its
primitives. `tests/phantom/reference.py` is an independent TEST-ONLY arithmetic
oracle, never a production crypto provider. State-machine, fault, replay,
logical-time and UDP-path tests are separate from statistical privacy evaluation.

References: https://www.rfc-editor.org/rfc/rfc5869.html ;
https://www.rfc-editor.org/rfc/rfc8439.html ;
https://www.rfc-editor.org/rfc/rfc9001.html .
