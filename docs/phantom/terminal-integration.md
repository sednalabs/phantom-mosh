# Terminal lane: acceptance contract

Ops work item: w18886. Branch: `feat/phantom-terminal-pty`, stacked on PR #3.

## Delivered increment

`TerminalPty` is a Linux process/PTY ownership primitive. It starts an explicit
absolute executable with an argument vector, establishes a controlling terminal,
sets the initial window size, and exposes a borrowed nonblocking, close-on-exec
master descriptor. It preserves child exit status, supports resize, rejects exec
failures, and closes unrelated descriptors before exec. ENOEXEC does not fall back
to a shell. A shell is launched only when explicitly selected as the executable.

The constructor must run **before session secrets are generated**, because fork
copies memory. The caller must retain exclusive child reaping, SIGCHLD default
handling, and no SA_NOCLDWAIT for its lifetime. It must not concurrently alter
those conditions. Destructor cleanup kills and reaps the leader and its initial
process group; it is **not** whole-session containment. Interactive shell job
control can create other groups even without setsid. A terminal frontend must
resolve that cleanup boundary before claiming complete session cleanup.

Environment is inherited: the caller must explicitly manage TERM, locale and
secret-bearing variables. Descriptor isolation is not environment isolation.

The caller owns bounded I/O: partial writes, EAGAIN, EINTR, Linux master EIO after
slave close, output caps/backpressure, and terminal emulation. Constructor exec
handoff is synchronous; cancellation/deadline integration remains frontend work.

No current executable uses this primitive. The inherited Mosh binaries remain v2;
Phantom's server/probe remain control-only. This increment is not a usable remote
terminal and does not establish an SSH-to-PTY terminal success.

## Remaining vertical slice

1. Choose an explicit authenticated terminal application profile and launcher
   contract. Never silently interpret the diagnostic probe as a terminal client.
2. Arrange PTY creation before entropy/key generation, while retaining bounded
   unconfirmed-startup expiry and cleanup on failed SSH handoff. Do not fork a
   shell from a process holding live session secrets.
3. Connect UserStream input and Terminal::Complete output through the existing
   SspTransport, not a new ad-hoc reliable byte protocol. Bound read/write work,
   preserve exactly-once input, resize ordering and terminal state convergence.
4. Add client raw-mode restoration on exit, signals, startup failure and network
   failure. Close SSP cleanly before closing the encrypted session channel.
5. Demonstrate isolated real OpenSSH bootstrap into the actual terminal server,
   with UTF-8/attributes, input echo, resize, shell exit status, disconnect,
   abandoned startup, and cleanup of foreground/background shell jobs. Include
   initial authentication and changed/unknown-host-key failures.
6. Run the same fixed synthetic terminal workload under loss/reordering and
   NAT rebinding. Require remote completion plus terminal convergence, not just
   transport connectivity. Record exact tested commit and environment.

Only after these gates pass may the lane advertise a usable invocation. The
measurement lane (w18887, PR #4) requires paired real-session evidence. Export
observer-only `time_ms`, `udp_payload_bytes`, `direction` rows with matched fixed
windows/workload/network profile and capture-health metadata. Do not capture or
publish real terminal contents, keys, or endpoint identity. Synthetic comparator
fixtures and this PTY unit test are not a traffic-fingerprint experiment.

## Local verification

The standalone component CMake build includes `phantom-terminal-pty`. It covers
PTY input/output, UTF-8, dimensions/resize, nonblocking/CLOEXEC, inherited descriptor
isolation, exec rejection, no-shell fallback, all closed-stdio permutations,
SIGCHLD ownership rejection, child exit status, and deterministic leader reaping.
The complete component suite also exercises the existing real OpenSSH fixtures;
those fixtures remain control/startup tests, not terminal integration tests.
