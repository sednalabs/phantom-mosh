# Experimental SSH-to-PTY terminal

Ops work item: w18886. Branch: `feat/phantom-terminal-pty`, stacked on PR #3.

The Linux SSP opt-in now builds `phantom-mosh-terminal` and
`phantom-mosh-terminal-server`. This is an experimental usable terminal slice,
not a production release, an upstream Mosh replacement, or a fingerprint claim.
The original Mosh binaries still use v2 and the Phantom probe/server remain
control-only. No installed binary or packaging behavior changes.

## Build and run

Build the inherited libraries and enable SSP using the exact same checkout,
as described in [ssp.md](ssp.md). The resulting binaries are in your CMake build
directory. Place the terminal server binary on a Linux host you administer, then
run (substitute your actual absolute remote binary path and SSH destination):

```sh
build/terminal/phantom-mosh-terminal \
  --server /absolute/path/phantom-mosh-terminal-server user@host
```

An optional `--ssh-config FILE` uses a trusted OpenSSH config. An explicit
`--udp-host IP` and/or `--udp-port PORT` override the advertised endpoint behind
NAT or for an explicit controlled test relay; they do not
carry UDP through an SSH proxy. Existing SSH host trust and noninteractive
credentials are required; the client never enrolls unknown or changed host keys.
No bootstrap secrets appear in arguments or environment variables.

The separate `phantom-mosh/terminal/draft-01` application profile is selected
inside authenticated SSH startup and strictly checked in the address-bound
offer. Control-only probes cannot select it, and terminal clients cannot accept
control-only offers. The existing record cipher/key schedule is unchanged.

The remote shell is explicitly `/bin/sh -i`, TERM is `xterm-256color`, and both
endpoints require `C.UTF-8`. This is not yet a configurable login shell. The client
has no local prediction or Mosh escape-key menu. Exit the shell to disconnect;
a local SIGTERM/INT/HUP requests bounded shutdown and restores terminal modes.
Pipe stdin EOF sends one terminal EOT, then waits for the remote shell to finish.
Client exit status reports transport completion, **not the shell's exit status**.

## Ownership and bounds

All daemon and PTY forks finish before session secrets are generated. The SSH-
launched shell is owned while UDP confirmation is pending; unconfirmed startup
expiry tears it down. A single SessionChannel owns crypto, packet counters,
control/recovery timers and sockets. SspTransport handles reliable terminal state
and input; no parallel reliable byte protocol is introduced. Terminal echo ACKs
are registered only for nonempty UserStream changes, not for empty SSP ACK
frames; otherwise those acknowledgements can generate an idle feedback loop.

The PTY master is nonblocking and close-on-exec. Exec takes an absolute executable
and argv, with no ENOEXEC shell fallback. The child resets inherited signal masks
and dispositions, establishes a controlling terminal and closes unrelated file
descriptors. The caller exclusively owns SIGCHLD/reaping. Environment is inherited;
descriptor isolation is not environment isolation.

The server caps queued PTY writes at 64 KiB and reads at most 4096 output bytes
per service iteration. Dimensions are limited to 512x256 server-side and 300x100
in this client. Client input is capped at 32 Ki events and pending rendered output
at 4 MiB, coalescing later frames while stdout is blocked. Local raw mode, fd flags
and signal handlers are restored on clean exit and exceptions. Final terminal
state must be acknowledged through SSP before client-initiated encrypted close.

The dedicated server is a Linux child subreaper. After the shell exits, or session
cleanup begins, it reaps adopted children and signals only pidfd-pinned processes
whose parentage is rechecked against the daemon. This covers ordinary foreground
and background shell job groups in the integration fixture, with a bounded drain.
It is **not a hostile-process sandbox** or a cgroup containment guarantee. The PTY
primitive alone only owns its original leader/group. Linux pidfd, close_range,
subreaper and readable procfs support are required. The adopted-descendant scan has a bounded drain and reports failure when that
drain expires. Reaping the directly owned PTY leader can remain blocked in an
uninterruptible kernel state; this is not a bounded whole-lifecycle guarantee.

## Verification and remaining work

`phantom-terminal-ssh` uses isolated loopback OpenSSH and disposable keys, observes
the actual detached server, and checks a computed shell result (not just command
echo), pipe EOF, bidirectional terminal traffic, resize, raw-mode restoration,
client SIGTERM, SSH-startup signal cancellation, abandoned-startup expiry,
ordinary foreground/background job cleanup, idle echo-ACK stability, and acknowledged
shutdown. Unknown-host trust and both terminal/control profile mismatches fail.
No real terminal contents or session keys are captured or logged.

The component suite also covers explicit exec rejection, closed-stdio permutations,
SIGCHLD ownership rejection, UTF-8/PTy I/O and strict offer parsing. These tests are
not an independent cryptographic review, a native Windows client, release packaging,
or real-network statistical validation. The current terminal integration test is
loopback; #6's NAT-rebinding/recovery lane is separate and not silently incorporated.

Remaining work includes remote shell exit-status propagation, configurable login
shell/TERM/locale, prediction and local escape controls, bounded constructor startup
cancellation, packaging, broader interrupted/failed-session coverage, and real
network validation. Established session state intentionally survives a network
outage; a crashed server can look like an outage until the user cancels locally.

The measurement lane (w18887, PR #4) can now drive the fixed synthetic terminal
workload through this invocation, but must still collect real paired captures.
Export observer-only `time_ms`, `udp_payload_bytes`, `direction` with matched fixed
window/workload/network profile and capture-health metadata. Never publish real
terminal contents, keys or endpoint identity. Fixtures are not measured resistance.
