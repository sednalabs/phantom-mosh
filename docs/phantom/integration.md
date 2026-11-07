# Integration status and roadmap

The default branch includes the record layer, SSH startup, session channel, SSP
adapter, experimental Linux terminal, recovery tests and pinned loopback evidence
integrated in [PR #9](https://github.com/sednalabs/phantom-mosh/pull/9).
The inherited Mosh executables continue to use v2. The terminal is a separate,
explicit build/install opt-in, not a production release.

## Implemented

- **Authenticated bootstrap:** the [SSH supervisor](ssh-startup.md) requires
  existing host trust, exact application-profile selection, bounded output,
  EOF and successful SSH exit. Address-bound offers avoid guessing an SSH
  alias's UDP address. There is no protocol downgrade or UDP-over-SSH tunnel.
- **Remote ownership:** [session owners](remote-session.md) detach before key
  generation and expire unconfirmed startups. The terminal additionally owns
  its PTY and ordinary descendants, with bounded userspace cleanup waits.
- **Transport and SSP:** one [session channel](session-channel.md) owns sockets,
  packet counters, path validation and retry timers. The [SSP adapter](ssp.md)
  reuses inherited state synchronization and accounts for the full 1200-byte
  UDP payload budget. It preserves crypto/replay state during path recovery.
- **Terminal:** the [Linux client/server](terminal-integration.md) exchange
  terminal state and input, report authenticated remote exit status, and restore
  local terminal modes. Both select terminal application profile draft-02.
- **Qualification:** tests cover component boundaries, real OpenSSH/PTYs,
  logical-time outages and [real-clock loopback remapping](terminal-recovery.md).
  A [matched integrated pilot](integrated-loopback-pilot.md) retains metadata-only
  observations, build pins and capture-health evidence.

## Remaining work

### Security and secret lifetime

The custom cryptographic composition still needs independent review. Provider
and allocation fault injection, process/secret-lifetime auditing and broader
failure testing remain open. Symmetric key updates do not provide
post-compromise recovery. Restart, cloning or rollback must never reuse a
bootstrap with reset counters. See the [security notes](security.md).

### Terminal usability and platforms

Account/login-shell and locale selection, local prediction, escape controls and
distribution packaging remain incomplete. Linux process APIs and `C.UTF-8` are
required by the experimental terminal. A native Windows client needs terminal,
process, networking and secret-handling work beyond compiling the record layer.
Packaging must not silently replace upstream Mosh executables.

### Network acceptance

The existing recovery tests use loopback relays, not kernel NAT or a physical
router. WAN conditions, real link changes, path-MTU behavior, congestion and
cross-address-family migration need separate work. The client's server endpoint
is fixed; server-address migration is not implemented. Preserve computed remote
output, exact input delivery and cleanup checks when adding new network fixtures.

### Traffic analysis and release claims

The retained pilots are small, pinned experiments, not classification studies.
Run the [matched measurement campaign](matched-measurement.md) and the separate
[held-out detector evaluation](evaluation.md) before making privacy claims.
Freeze builds, observers, thresholds and whole-session holdouts before scoring;
report failed captures, exclusions and negative results. Equal packet counts do
not establish equivalent traffic distributions.

Independent security review, broader end-to-end acceptance and reproducible
measurements are required before making corresponding production or privacy
claims. Check CI for the exact commit being considered; historical results are
not a guarantee for a later checkout.
