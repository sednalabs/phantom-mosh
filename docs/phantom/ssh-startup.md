# SSH startup supervisor

The Linux supervisor executes OpenSSH and returns a validated, move-only offer.
It supplies three explicit entry points:

- `start_over_ssh`: original record profile and port-only `StartupOffer`.
- `start_session_over_ssh`: control-session profile and address-bound `SessionOffer`.
- `start_terminal_over_ssh`: terminal draft-02 profile and address-bound offer,
  with safely quoted shell/TERM options.

The [control probe](remote-session.md) and [terminal client](terminal-integration.md)
use the latter two entry points. The supervisor does not itself own the remote
PTY; the terminal server does. Inherited Mosh executables remain unchanged.

## Authentication and command construction

The caller supplies a trusted destination, an absolute local SSH executable and
a remote server executable. The default local executable is `/usr/bin/ssh`; it
is not found through `PATH`. An optional `config_path` selects a trusted OpenSSH
configuration file. Local executable/configuration files, including configured
proxy commands and host-key providers, are part of the trusted environment.

The supervisor invokes OpenSSH without a local shell. For the original
`start_over_ssh` entry point, the remote command is:

```text
exec '<server_path>' '--startup-profile' 'phantom-mosh/v3/draft-01'
```

The control-session entry point selects `--session-profile` with
`phantom-mosh/session/draft-01`; the terminal entry point selects
`--terminal-profile phantom-mosh/terminal/draft-02` plus explicit `--shell` and
`--term` values. Both use the bounded `PHANTOM SESSION` address-bound codec.
Application profile versions do not change the record cipher/key schedule.

Each remote argument is independently shell-quoted, including embedded single
quotes. Destinations are restricted to hostname, address and `user@host`/alias
characters; option-like, whitespace and shell-operator input is rejected. The
command does not contain the bootstrap secret. The existing startup decoder
requires the exact profile and role binding in the server's response.

Host verification uses `StrictHostKeyChecking=yes`. Unknown or changed host keys
fail; enrolling a host remains a separate user action. Batch mode disables
interactive password/passphrase prompts; use an existing key or local SSH agent.
There is no automatic downgrade or alternate authentication path.

Command-line settings disable PTY allocation, agent/X11/port forwarding, local
commands, connection multiplexing and backgrounding. This keeps the SSH child
under the supervisor's ownership. Normal SSH configuration may still resolve
aliases, select a user/port/key and configure a trusted proxy. The original
record offer contains only a port, so its caller must supply the authenticated
server address. Current session and terminal offers include the numeric
server-local address obtained from `SSH_CONNECTION`. A trusted local UDP endpoint
override may be needed behind NAT. Do not resolve a configuration alias as DNS
or assume an SSH proxy carries UDP; see [address binding](remote-session.md#address-bound-startup).

## Admission and lifetime

Success requires all three conditions: exactly one valid bounded startup frame,
EOF on stdout, and successful exit of the SSH child. A valid-looking frame
followed by a failed or stalled SSH process is not admitted. Stderr is discarded
so a remote program cannot expose a secret by echoing it in a diagnostic. Errors
contain fixed descriptions, not input fragments. Diagnose authentication issues
with a separate ordinary SSH invocation, without supplying a session secret.

One monotonic deadline, between 1 and 120,000 ms, covers spawning, reading and
successful-exit observation. Fragmentation and interrupted system calls do not
restart it. An optional borrowed `cancel_fd` cancels on readability or hangup;
the supervisor neither consumes its bytes nor closes it. Keep that descriptor
open for the call. A pre-signalled cancellation does not launch a process.

The child receives only standard descriptors, with null stdin/stderr and a
private stdout pipe. Unrelated inherited descriptors are closed atomically by
the spawn actions. Pipe creation uses close-on-exec from the outset. Each SSH
attempt gets its own process group. Success, rejection, timeout, cancellation
and exceptions all clean up remaining local group members and reap the leader.
The leader is observed with `waitid(..., WNOWAIT)` and not reaped until after
group signalling, avoiding signalling an ID that has already been recycled.

The caller must not install an auto-reaping SIGCHLD disposition or run a competing
child reaper. Detected incompatible dispositions are rejected. Killing a local
process group is not a sandbox for descendants that deliberately detach, and is
not a remote-process cancellation guarantee. OS-level uninterruptible operations
can delay cleanup despite the protocol deadline.

Remote owners must independently expire startups that never receive an
authenticated UDP confirmation. The [control server](remote-session.md) and
[terminal server](terminal-integration.md) implement that separate lease; local
SSH cleanup alone cannot guarantee remote cleanup. The original record test
responder has a three-second lease and remains a test fixture.

## Building and testing

The supervisor currently requires Linux with glibc 2.34 or later, including
`posix_spawn_file_actions_addclosefrom_np`, and a modern OpenSSH client supporting
`SessionType` and `ForkAfterAuthentication` (OpenSSH 8.7 or later). CMake checks
spawn capability instead of silently allowing descriptor inheritance. Set
`PHANTOM_BUILD_SSH_STARTUP=OFF` to build the existing record/startup components
without this Linux-specific addition. No Windows or macOS supervisor is supplied.

The process tests inject unsuccessful exits, signals, output floods, malformed
frames, late trailers, missing EOF, stalled children and inherited output pipes.
They exercise cancellation, interruptions, quoting, descriptor isolation and
cleanup. The fake SSH executable is only a test fixture.

The real integration test creates a temporary loopback-only `sshd`, fresh host
and client keys, and an isolated known-hosts file. It tests correct, unknown and
changed host keys, a rejected client identity, a valid offer with a failing
remote exit status, and a successful SSH-to-encrypted-UDP exchange. The UDP peer
uses the independent test implementation. It never modifies the user's SSH
configuration or trust files. A temporary executable name containing spaces,
quotes and shell punctuation tests actual remote-shell argument handling.

Install `openssh-client` and `openssh-server` and set
`PHANTOM_REQUIRE_SSH_TESTS=ON` to make missing integration prerequisites fatal.
CI uses this setting. Developer builds without those tools report an explicit
skip, not a passing SSH test. The separate `phantom-session-ssh`,
`phantom-terminal-ssh` and `phantom-terminal-recovery` tests exercise the
integrated owners and terminal. Their results do not replace independent
cryptographic review or statistical traffic evaluation.

References: [OpenSSH client](https://man.openbsd.org/ssh) and
[OpenSSH configuration](https://man.openbsd.org/ssh_config).
