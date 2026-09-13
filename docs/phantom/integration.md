# Integration roadmap

The record layer is implemented separately from the inherited Mosh runtime.
The following work is needed for a usable Phantom Mosh terminal.

## Authenticated bootstrap

Add distinctly named launcher, client and server entry points. Authenticate the
profile identifier, endpoint roles and fresh 256-bit bootstrap secret through
SSH, retaining its host-key authentication. Use an unambiguous startup format
for the 43-character secret rather than the legacy 22-character key parser.
Reject profile mismatches without silent fallback; keep v2 compatibility an
explicit choice and test it against a pinned upstream build.

Bound startup input, redact malformed secret-bearing lines and erase launcher,
environment and parser copies of the bootstrap.

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
