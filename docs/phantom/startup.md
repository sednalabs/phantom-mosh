# Startup and secret handoff

The startup component provides a message codec and a POSIX descriptor reader for
connecting the record layer to a launcher. It does not run SSH, authenticate a
host or start a terminal. Existing Mosh executables are unchanged.

## Message format

A server-to-client offer is exactly one ASCII line followed by end-of-stream:

```text
PHANTOM CONNECT phantom-mosh/v3/draft-01 server client <port> <secret>\n
```

`\n` denotes one LF byte, not two literal characters. The profile and role labels
are exact and case-sensitive. `port` is canonical decimal in 1..65535, without
leading zeros. `secret` is the existing 43-character canonical, unpadded standard
base64 encoding of a fresh 32-byte bootstrap. The entire message is at most 105
bytes, including LF. No host address or remote command can be supplied by it.

The decoder rejects unknown profiles, reversed roles, legacy `MOSH CONNECT`
messages, banners, CRLF, control characters, extra spaces, duplicate messages,
trailing output, missing LF and truncated input. It never searches through output
for a promising line or falls back to another protocol. A parse failure closes
the decoder permanently, and error messages do not include input fragments.

`PROFILE_ID` is shared with the record key schedule. This is the first startup
format for the existing record draft; its UDP bytes and independent test vectors
are unchanged. Future incompatible setup formats need distinct profile selection.

## Codec and ownership

`make_startup_offer(port, secret)` returns a move-only `StartupFrame`. It borrows
the server bootstrap, which the server still needs to construct its own
`Session`. The frame owns a fixed-size sensitive buffer; destruction, explicit
`clear()` and moving from it erase that buffer. Its `view()` is borrowed and must
not outlive those operations or be copied into logs or ordinary strings.

`StartupDecoder::feed()` accepts arbitrary read boundaries, including one-byte
fragments, without allocating an unbounded input buffer. Call `finish()` only at
EOF. It returns a move-only `StartupOffer` containing the port and bootstrap,
and clears its input storage on success or failure. Construct the client
`Session` by moving `offer.secret`; session construction consumes that secret.
Callers remain responsible for erasing their own input and output copies.

## POSIX descriptor handoff

`read_startup_offer_fd(fd, timeout)` takes exclusive ownership of a dedicated
pipe or connected stream-socket read end, including on failure. It sets
nonblocking and close-on-exec flags, reads one message through EOF, and closes
the descriptor when it returns or throws. Other descriptor types are rejected.
The descriptor must not have competing readers or aliases that rely on its
previous open-file-description flags.

The default timeout is ten seconds; callers may select 1..120000 milliseconds.
It is a single steady-clock deadline, not a new timeout for each read or signal.
The reader handles partial reads, interrupted waits and hangup with buffered
data. A complete line without EOF still times out. Scheduling or suspension can
delay when a process runs; this is not a real-time scheduling guarantee.

Only the descriptor number needs to appear in the child's arguments. The secret
does not need an environment variable, command argument or temporary file.
The launcher must create pipes with suitable inheritance controls, pass only the
intended read end, and close every unused write end so EOF is observable.
Setting close-on-exec inside the reader cannot undo an earlier inheritance leak.

## Authentication remains the launcher's responsibility

This plaintext message is for an authenticated, confidential control channel,
not a public UDP socket. A correct prefix and successful parsing are not proof
of identity. The future launcher must retain SSH host-key authentication, request
the exact profile, check successful SSH/remote startup completion, and use only
that authenticated server's address with the returned port.

Use a dedicated control stream without a pseudo-terminal. Keep banners and
diagnostics out of it; do not merge stderr into stdout or log malformed stdout.
Apply an overall startup deadline and bound/drain diagnostics independently.
Close/cancel the child and reject the offer when SSH fails, even when its stdout
contained a syntactically valid message. Do not reuse the bootstrap after a
failed or restarted session. These launcher responsibilities are not implemented
by the codec or the descriptor reader.

## Tests

The startup unit suite covers canonical encoding, all two-chunk splits, bytewise
input, truncated and malformed messages, one-shot state, moved secrets, record
interoperability and 10,000 deterministic input mutations.

The POSIX process suite passes a public fixture through inherited pipes and a
stream socket to a C++ child. The child exchanges actual encrypted UDP records
with the independent Python wire oracle. Negative cases exercise invalid and
duplicate offers, missing EOF, stalled/trickling writers, repeated signal
interruptions, descriptor cleanup and unauthenticated UDP replies. No secret is
passed through the child's arguments or environment.

These are local process and protocol tests, not SSH authentication, terminal
convergence or traffic-analysis measurements. See the [integration roadmap](integration.md).
