# Integration boundary and next delivery slices

This PR is a record-layer foundation, not a completed Mosh-v3 terminal.
The upstream Autotools build, SSH wrapper, crypto, network and SSP paths are
unchanged. The following are explicit unimplemented integration requirements,
not flags or features users can already run.

## 1. Authenticated bootstrap and compatibility

Add a distinctly named Phantom launcher/client/server profile. Keep upstream v2
compatibility explicit and test both directions against a pinned upstream build.
Authenticate draft identity, roles and the random 256-bit bootstrap through SSH.
Use an unambiguous new startup grammar; the old 22-character-key parser cannot
silently accept the new 43-character secret. Reject profile mismatch without
fallback, bound and redact malformed secret-bearing startup lines, and erase
launcher, environment and parser copies. Do not invent a new host-key system.

## 2. SSP adapter and socket lifecycle

Use one Session per direction pair, retain Mosh state synchronization/prediction
and preserve single ownership. Convert timestamps/payload explicitly without
routing new records through the old OCB framing. Deduct the full 32-byte record
overhead plus timestamp/SSP overhead from the selected MTU. Tick idle sessions
for key retirement. Ensure ACK-carrying traffic allows progress without unbounded
control loops. Handle hard-limit closure as a fresh-authentication requirement.
Never reset a packet counter after EAGAIN, EMSGSIZE, port hopping or disconnection.

Only a newest authenticated record may update the remote address; out-of-order
payload acceptance must not roll the route backward. Add path validation and
anti-amplification appropriate to the server's threat model. Preserve terminal
state convergence independently of packet delivery order.

## 3. End-to-end and platform acceptance

Use real local SSH/PTY sessions and a controllable UDP relay for duplication,
loss, delay, reordering, port/address migration and blackout/resume. Assert remote
terminal convergence and remote-confirmed keystroke latency, not only local
prediction. Exercise simultaneous rekey, lost ACK, active output across a key
limit, rebind races, malformed bootstrap and explicit v2/v3 mismatch. A logical
clock test is not evidence of a real six-month session.

Native Windows support requires terminal, process, signal/event, networking and
secure-secret-custody work. A C++17 core compiling on Windows is not a native
Windows Mosh client. Packages must avoid replacing stock executables implicitly.

## 4. Privacy evaluation and promotion

Freeze the integrated build, observer model, corpus lineage, detector, thresholds
and whole-session/domain holdouts before scoring. Compare stock Mosh, the retained
clear-header prototype and this successor using actual candidate traffic. Never
call a trace with fields manually removed an implemented candidate capture.
Test bounded padding or idle scheduling only when attribution studies justify
it. Independent review and challenge/replication are prerequisites for strong,
bounded release claims. No PR here authorizes deployment or universal assurance.
