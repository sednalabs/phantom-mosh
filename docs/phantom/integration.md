# Integration roadmap

The record layer is implemented separately from the inherited Mosh runtime.
The following work is needed for a usable Phantom Mosh terminal.

## Authenticated bootstrap

The [startup codec and POSIX handoff reader](startup.md) now implement bounded
framing, exact profile/role selection, secret-buffer cleanup and a total read
deadline. Process tests hand a bootstrap through a pipe or stream socket and
exchange encrypted UDP records with an independent test peer.

Add distinctly named launcher, client and server entry points. Authenticate the
profile identifier, endpoint roles and fresh 256-bit bootstrap secret through
SSH, retaining its host-key authentication. Use the startup codec on a dedicated
control stream and check successful SSH completion before admitting the session.
Reject profile mismatches without silent fallback; keep v2 compatibility an
explicit choice and test it against a pinned upstream build.

Keep the secret out of command arguments, environment variables and logs. Pass
only the dedicated descriptor to the child, close unused pipe ends, and erase
launcher-owned copies. The handoff reader does not replace those responsibilities.

## SSP and socket integration

Connect one `Session` to each client/server pair while preserving Mosh's state
synchronization and prediction. Keep the new records separate from the legacy
OCB framing, and deduct the 32-byte record overhead plus timestamp and SSP
overhead from the selected datagram budget.

Schedule idle `tick` calls for key retirement and timely acknowledgement-carrying
traffic. Treat hard-limit closure as requiring fresh authentication. Never reset
packet numbers after failed sends, port changes or disconnection.

Only an authenticated newest record may update the peer address. Reordered
payloads must not move it back to an old path. Add path validation,
anti-amplification and admission limits without breaking state convergence.

## End-to-end tests and platforms

Test real SSH/PTY sessions through a controllable UDP relay with loss, duplication,
delay, reordering, migration and blackout/resume. Check remote terminal
convergence and remote-confirmed keystroke latency, not only local prediction.
Include simultaneous updates, lost acknowledgements, output across key limits,
rebinding races, malformed bootstrap and explicit protocol mismatches.

Native Windows support requires terminal, process, event, networking and secret
handling work beyond compiling the record layer. Packaging must not silently
replace upstream executables.

## Evaluation and release readiness

Collect actual integrated traffic for the comparisons in the
[evaluation guide](evaluation.md). Freeze builds, observer capabilities,
detectors, thresholds and whole-session holdouts before scoring. Label synthetic
trace changes as ablations rather than implemented protocol captures.

Evaluate padding or idle-scheduling changes only when measurements justify them.
Independent security review, end-to-end acceptance and reproducible traffic
measurements are required before making corresponding release claims.
