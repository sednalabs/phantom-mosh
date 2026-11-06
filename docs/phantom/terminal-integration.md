# Experimental SSH-to-PTY terminal

Ops work item: w18886. Branch: `feat/phantom-terminal-pty`, stacked on PR #3.

The Linux SSP opt-in now builds `phantom-mosh-terminal` and
`phantom-mosh-terminal-server`. This is an experimental usable terminal slice,
not a production release, an upstream Mosh replacement, or a fingerprint claim.
The original Mosh binaries still use v2 and the Phantom probe/server remain
control-only. Installation remains off by default; an explicit CMake option installs only the two experimental binaries.

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

The separate `phantom-mosh/terminal/draft-02` application profile is selected
inside authenticated SSH startup and strictly checked in the address-bound
offer. Control-only probes cannot select it, and terminal clients cannot accept
control-only offers. The existing record cipher/key schedule is unchanged.

The default shell is `/bin/sh -i` and TERM is `xterm-256color`. Select another
absolute remote executable with `--shell /bin/bash` and a terminal type with
`--term vt100`. Shell paths are single quoted SSH arguments, never command
fragments or an ENOEXEC fallback. Every selected shell receives `-i`; this is
not a login-shell/account lookup or arbitrary command interface. Both endpoints
require `C.UTF-8`; locale selection is not configurable. The client
has no local prediction or Mosh escape-key menu. Exit the shell to disconnect;
a local SIGTERM/INT/HUP requests bounded shutdown and restores terminal modes.
Pipe stdin EOF sends one terminal EOT, then waits for the remote shell to finish.
After final screen acknowledgement and channel close, the client returns the
remote shell's exit code (0–255), or `min(255, 128 + signal)` for a signalled
shell. Local cancellation returns `128 + signal`. Missing remote status, failed
startup, or failed transport completion returns a nonzero error, never an implied
remote success. Exit 1 can therefore mean either a remote command failure or a
local transport error, like other terminal tools.

## Exit-status state and compatibility

Both binaries must use terminal profile draft-02. A draft-01 client or server is
rejected during authenticated SSH selection, with no downgrade. Record, channel,
SSP timing, and upstream Mosh wire formats remain unchanged.

Each nonempty server-to-client state diff now begins with six bytes:
`50 54 53 02 | kind | value`, followed by the inherited Complete terminal diff.
Kind 0 means running (value must be 0), 1 means normal exit (value 0–255), and 2
means signal (value is a valid nonzero Linux signal number). The prefix is inside
encrypted SSP state, not a public record header. Empty diffs remain empty. A final
status is immutable in a given state and participates in SSP equality, snapshots,
ACKs and recovery. The server publishes it only after observing shell exit,
ordinary descendant cleanup and PTY output EOF, then initiates SSP shutdown.
Terminal text cannot spoof the status. The client does not infer status from EOF.

Independent status-only vectors are `505453020100` (exit 0), `505453020107`
(exit 7), `5054530201ff` (exit 255), and `505453020209` (SIGKILL, client 137).
These describe metadata encoding, not a new cryptographic assurance claim.

## Optional installation

The default CMake build installs nothing. To opt in after building SSP:

```sh
cmake -S src/phantom -B build/terminal -DPHANTOM_BUILD_SSP=ON \
  -DPHANTOM_MOSH_BUILD_DIR="$PWD" -DPHANTOM_INSTALL_TERMINAL=ON
cmake --build build/terminal --parallel 2
DESTDIR="$PWD/stage" cmake --install build/terminal --prefix /usr \
  --component phantom-terminal
```

This stages exactly `usr/bin/phantom-mosh-terminal` and
`usr/bin/phantom-mosh-terminal-server`, with no test binaries, inherited Mosh
replacement, service activation or package-manager changes. Install the matching
server on the remote host separately. This is not distribution release packaging.

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
subreaper and readable procfs support are required. The adopted-descendant scan has a five-second drain and reports failure when
that drain expires. PTY exec acknowledgement is polled for at most five seconds
and observes startup cancellation. Explicit PTY termination signals the owned
group/leader and uses nonblocking reap for at most one second; timeout returns
failure and relinquishes reaping to the daemon subreaper, without a destructor
retry. A kernel-uninterruptible task can outlive these deadlines. These are
bounded userspace waits, not a guarantee that every system call or process can
be forcibly completed.

## Verification and remaining work

`phantom-terminal-ssh` uses isolated loopback OpenSSH and disposable keys, observes
the actual detached server, and checks a computed shell result (not just command
echo), pipe EOF, bidirectional terminal traffic, resize, raw-mode restoration,
client SIGTERM, SSH-startup signal cancellation, abandoned-startup expiry,
ordinary foreground/background job cleanup, idle echo-ACK stability, acknowledged
shutdown, remote exits 7/255 and SIGKILL=137, final output preservation, safely quoted
shell selection, TERM selection and old-profile rejection. Component fault injection
exercises a stalled pre-exec child, signal cancellation, and unavailable nonblocking
reap. The latter is a deterministic syscall fixture, not a real uninterruptible task. Unknown-host trust and both terminal/control profile mismatches fail.
No real terminal contents or session keys are captured or logged.

The component suite also covers explicit exec rejection, closed-stdio permutations,
SIGCHLD ownership rejection, UTF-8/PTy I/O and strict offer parsing. These tests are
not an independent cryptographic review, a native Windows client, release packaging,
or real-network statistical validation. The current terminal integration test is
loopback; #6's NAT-rebinding/recovery lane is separate and not silently incorporated.

Remaining work includes account/login-shell and locale selection, prediction and
local escape controls, distribution packaging, broader interrupted/failed-session
coverage, and real
network validation. Established session state intentionally survives a network
outage; a crashed server can look like an outage until the user cancels locally.

The measurement lane (w18887, PR #4) already preserved the draft-01 ACK-loop
before/after pilot. Its observations do not measure this draft-02 status envelope.
A new matched collection must use the current exact client/server revision.
Export observer-only `time_ms`, `udp_payload_bytes`, `direction` with matched fixed
window/workload/network profile and capture-health metadata. Never publish real
terminal contents, keys or endpoint identity. Fixtures are not measured resistance.
