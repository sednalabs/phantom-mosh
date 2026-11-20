# Experimental SSH-to-PTY terminal

[Documentation index](README.md) · [Build guide](ssp.md#build-and-test) ·
[Architecture](architecture.md)

The terminal, recovery tests and matched traffic measurements are integrated
on the default branch. Historical measurement reports pin their tested revisions;
they are not measurements of every later checkout.

The Linux SSP opt-in now builds `phantom-mosh-terminal` and
`phantom-mosh-terminal-server`. This is an experimental usable terminal slice,
not a production release, an upstream Mosh replacement, or a fingerprint claim.
The original Mosh binaries still use v2 and the Phantom probe/server remain
control-only. Installation remains off by default; an explicit CMake option installs only the two experimental binaries.

This guide describes the current Linux frontend in
[`terminal_client.cc`](../../src/phantom/terminal_client.cc) and
[`terminal_server.cc`](../../src/phantom/terminal_server.cc). The inherited
`man/mosh*.1` pages document Mosh v2; they are not a CLI reference for these
executables.

## Build and run

Build the inherited libraries and enable SSP using the exact same checkout,
as described in [ssp.md](ssp.md). The resulting binaries are in your CMake build
directory. Build or place the matching terminal server binary on a Linux host you
administer. It must match that host's architecture and shared-library versions.
Run as your ordinary SSH account, not as a privileged service (substitute your
actual absolute remote binary path and SSH destination):

```sh
build/ssp/phantom-mosh-terminal \
  --server /absolute/path/phantom-mosh-terminal-server user@host
```

An optional `--ssh-config FILE` uses a trusted OpenSSH config. An explicit
`--udp-host IP` and/or `--udp-port PORT` override the advertised endpoint behind
NAT or for an explicit controlled test relay; they do not
carry UDP through an SSH proxy. Existing SSH host trust and noninteractive
credentials are required; the client never enrolls unknown or changed host keys.
No bootstrap secrets appear in arguments or environment variables.

The server binds an OS-selected UDP port on its SSH server-local address. The
client has no server port-range selection option; `--udp-port` changes only the
client destination, not the server bind. Use a controlled network with reachable
UDP or an explicitly arranged mapping. Opening the SSH TCP port alone is not
enough, and upstream Mosh's usual UDP port range is not a Phantom guarantee.

If startup fails, first verify ordinary SSH to the same destination with the
same trusted config and noninteractive credentials. Do not weaken host-key
checking. If SSH works but UDP confirmation times out, check the advertised
address, routing and firewall policy. A profile mismatch requires matching
terminal builds, not a downgrade. Missing `C.UTF-8`, unsupported process APIs
or incompatible shared libraries require fixing the host prerequisites.

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

### Client options

Options take a separate value. Exactly one SSH destination is required.

| Argument | Meaning and default |
| --- | --- |
| `HOST` | Trusted SSH destination, including `user@host` or a configured alias. |
| `--server PATH` | Remote terminal server executable; defaults to `phantom-mosh-terminal-server`. Use an absolute path to select a known build. |
| `--ssh-config FILE` | Trusted OpenSSH configuration; omitted means normal SSH configuration. |
| `--udp-host IP` | Explicit numeric UDP destination override; otherwise use the authenticated advertised address. |
| `--udp-port PORT` | UDP destination port override, 1–65535; does not change the server's bind port. |
| `--shell /PATH` | Absolute remote shell executable, always invoked with `-i`; defaults to `/bin/sh`. |
| `--term TERM` | Remote terminal type; defaults to `xterm-256color`. |

The client does not expose arbitrary SSH arguments, a server bind-port option,
a remote command after `HOST`, `--help`, `--version`, or `--protocol=v3`.
Configure SSH port, identity and aliases in the trusted SSH configuration.
The terminal server is normally started by this client; invoking it directly
requires the authenticated startup environment and is not a replacement for
the client command above.

## Session lifetime and recovery

Once connected, network loss leaves the live session in memory. The channel
retains its keys, packet counters and replay state while SSP retains terminal
state and pending input. When the existing client can reach the same server
endpoint again, it validates the path and resumes state synchronisation.
Source-port recovery is implemented, including silent NAT remapping; changing
the server's address or moving between IPv4 and IPv6 is not supported.

There is no default established-terminal idle expiry. A client whose server
has crashed can therefore continue waiting as though the network were down.
There is also no detach/reattach command, reconnect token, saved-session file
or restore-after-reboot feature. Starting the client again creates a new SSH
bootstrap and a new shell. Do not copy or restore live session state to resume
an old connection; see [session ownership](security.md).

Exit the remote shell normally when the network is available. If the connection
cannot recover, send SIGTERM to the local client from another local terminal to
start its bounded shutdown attempt. This attempts to restore local terminal modes but
cannot prove remote cleanup across a broken path. Manage any remaining process
through a separate authenticated connection to the host. The server's cleanup of its ordinary shell descendants
is described below; it is not a general service manager.

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
cmake -S src/phantom -B build/ssp -DPHANTOM_BUILD_SSP=ON \
  -DPHANTOM_MOSH_BUILD_DIR="$PWD" -DPHANTOM_INSTALL_TERMINAL=ON
cmake --build build/ssp --parallel 2
DESTDIR="$PWD/stage" cmake --install build/ssp --prefix /usr \
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
or real-network statistical validation. Transparent source-port revalidation from
PR #6 is included in the integrated terminal. The separate
[`phantom-terminal-recovery` test](terminal-recovery.md) checks launched terminals
through real-clock loopback remapping, impairment and a two-second blackout.
This remains userspace loopback coverage, not kernel NAT or WAN acceptance.

Remaining work includes account/login-shell and locale selection, prediction and
local escape controls, distribution packaging, broader interrupted/failed-session
coverage, and real-network validation. Established session state intentionally
survives a network outage; a crashed server can look like an outage until the user cancels locally.

The measurement reports preserve the draft-01 ACK-loop before/after
pilot and a [separate integrated draft-02 collection](integrated-loopback-pilot.md).
That collection pins the exact terminal/recovery revision and binary hashes;
it is not a measurement of every later checkout. Visible traffic differences
remain, and fingerprint resistance has not been established.
Export observer-only `time_ms`, `udp_payload_bytes`, `direction` with matched fixed
window/workload/network profile and capture-health metadata. Never publish real
terminal contents, keys or endpoint identity. Fixtures are not measured resistance.
