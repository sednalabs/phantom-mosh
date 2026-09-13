# Experimental remote-session control

The Linux `phantom-mosh-server` executable owns an encrypted UDP session after
SSH exits. `phantom-mosh-probe` authenticates startup through OpenSSH, confirms
UDP reachability and closes the session. Neither executable starts a shell or
PTY, and neither is a replacement for the existing Mosh client. SSP remains
unintegrated. Application data is exposed by the library API but is discarded
by the control-only server executable, not acknowledged as terminal delivery.

The server and diagnostic probe share the [bounded datagram channel](session-channel.md).
It owns socket readiness, control retry deadlines and application-data batches,
so subsequent SSP integration need not duplicate those event loops.

## Build and diagnostic use

The existing CMake build produces both executables when
`PHANTOM_BUILD_SSH_STARTUP=ON` on Linux. The supervisor requires glibc 2.34+ and
the server requires kernel `close_range` support (Linux 5.9+). Unsupported process
isolation fails before the daemon generates any session key. No binaries are
installed over upstream Mosh.

Place the built `phantom-mosh-server` at a chosen path on the remote host, then:

```sh
build/phantom/phantom-mosh-probe \
  --server /absolute/path/to/phantom-mosh-server \
  --ssh-config /path/to/trusted/ssh_config host-alias
```

Use an existing trusted host key and key-based authentication. The probe does
not automatically enroll unknown keys or run interactive password prompts.
It prints only its final status, not a bootstrap key. It deliberately closes
the session after confirmation instead of leaving an unattended daemon running.
The inherited `mosh`, `mosh-client` and `mosh-server` remain unchanged.

## Address-bound startup

The new SSH-selected application profile is `phantom-mosh/session/draft-01`.
It uses the existing `phantom-mosh/v3/draft-01` record cipher/key schedule, but
its startup message is distinct from the older, port-only startup component:

```
PHANTOM SESSION phantom-mosh/session/draft-01 server client <host> <port> <key>\n
```

This is plaintext only within the confidential, authenticated SSH output stream.
The decoder requires one canonical numeric unicast host, nonzero decimal port,
canonical 43-character bootstrap and EOF, within 160 bytes. It rejects banners,
extra lines, trailing data, DNS names, scoped/mapped IPv6 and profile mismatches.
`start_session_over_ssh` requires a valid offer, EOF AND successful SSH exit;
parsing alone never authenticates a session. The old `start_over_ssh` entry point
retains its original profile and decoder, without automatic fallback.

The server binds to the server-local address in `SSH_CONNECTION`. SSH aliases
and ProxyJump destinations therefore cannot accidentally become guessed UDP
hostnames. An SSH proxy does not carry UDP: the advertised local address may be
unreachable behind NAT, a jump host or a firewall. The probe accepts deliberate
`--udp-host NUMERIC_IP` and `--udp-port PORT` overrides from trusted local input;
there is no automatic NAT discovery, port mapping or UDP tunnelling. A routing
override still requires the authenticated session keys and return-path proof.
The local socket uses the OS route to that numeric destination. Servers do not
accept peer-host redirection from UDP payloads.

## Process and key lifetime

The server completes both forks and detachment before generating entropy,
deriving keys or allocating packet numbers. Only the private startup pipe is
preserved; all unrelated descriptors are closed and standard I/O is redirected
to `/dev/null`. Key generation never precedes a fork of a live session.
The bounded offer passes back to the SSH-facing parent, which validates and
forwards it and clears its secret-bearing representations before exiting.

An unconfirmed owner expires ten seconds after creation. New packets, repeated
HELLO messages and candidate replacement do not extend this absolute deadline.
The standalone control-only executable defaults to a 60-second authenticated
idle budget after confirmation, so an interrupted probe cannot leak a daemon
indefinitely. The reusable `RemoteSession` API defaults to no idle expiry for
future long-lived terminal sessions. `--startup-ms`, `--path-ms`, `--drain-ms`
and `--idle-ms` are explicit server lifetime overrides; `--idle-ms 0` disables
idle expiry and requires an owner to close the confirmed session later.

Termination signals stop the owner and release its socket and keys. A failed
SSH client cannot reliably kill a detached remote process, so the remote lease
is necessary even with correct local child cleanup. Full terminal/process-tree
ownership, user quotas and a durable service manager are not implemented here.

## Encrypted control protocol

Each record payload contains `kind[1] | path_token[16] | optional_data`.
Kinds are HELLO=1, CHALLENGE=2, CONFIRM=3, READY=4, DATA=5, CLOSE=6 and CLOSED=7.
Only DATA permits additional bytes. The entire payload is encrypted by the
unchanged record layer. Total record-plus-session overhead is 49 bytes; at a
1200-byte UDP payload budget, application data is limited to 1151 bytes. A
future SSP/timestamp adapter must deduct its own overhead again.

A fresh client sends HELLO with a random request token. The owner creates one
bounded candidate path and a random 128-bit challenge for that source address.
Only a matching CONFIRM from that address, under a newer authenticated record,
activates the session. READY confirms this to the client. Lost control messages
are retried with fresh packet numbers. Periodic HELLO retries recover from an
expired challenge; replaying an old datagram is not a retry. No application data
or bulk server output is admitted before confirmation. Each control reply is
no larger than its authenticated request.

Migration uses the same challenge/confirm exchange on a new source address.
The previous active route remains available while the candidate is unconfirmed.
Committing the candidate replaces its path token and route. Delayed packets from
the retired route cannot move the address backwards. Replay and crypto epoch
state belong to the record layer; a valid record may consume replay state even
when its session control or source path is rejected. Session activation and
route selection have separate, stricter admission checks.

At most one candidate exists, with a default three-second lifetime. Repeated
HELLO for that candidate resends its challenge without extending its lifetime.
Candidate timeout does not destroy an already active old route. Packet loss or
an absent network does not advance the key schedule arbitrarily. The client and
server adapters retain the underlying ACK-gated updates.

A newest CLOSE from the active source and token enters a fixed one-second drain
period. CLOSED may be resent for fresh CLOSE retries, but retries never extend
the drain period and DATA is no longer delivered. Expiry erases keys and ends the
owner. There is no reliable terminal-exit protocol or restoration after reboot.

## Scheduling, tests and limits

The Linux event loop uses CLOCK_BOOTTIME, including suspension, and checks time
before admission. It processes at most 64 datagrams between timer checks. Both
library adapters expose `tick` for idle key retirement and explicit shutdown.
The public endpoint is fixed on the client side; server-address migration is
not implemented. Route proof establishes round-trip reachability, not immunity
to an on-path relay or compromised endpoints. A bounded reply/key-trial budget
is not a complete flood-resistance mechanism.

State-machine tests cover absolute leases, packet loss, expired-challenge
recovery, source confusion, duplicate/reordered traffic, migration, closure and
logical long sleep. Linux subreaper tests exercise actual detached processes,
IPv4/IPv6 sockets, descriptor isolation, idle/signal expiry and abandoned output.
The simulated SSH supervisor test validates process/decoder composition, not
SSH cryptographic authentication. Existing isolated OpenSSH tests remain
required in CI, but do not by themselves establish terminal acceptance.

The challenge protocol adds startup/migration round trips and observable traffic
patterns. It is not fingerprint-resistance evidence. Independent protocol review,
full OpenSSH-to-terminal acceptance and statistical traffic evaluation remain
necessary before corresponding production or privacy claims.
