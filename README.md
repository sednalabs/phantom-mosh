# Phantom Mosh

**An experimental roaming terminal and transport research fork of
[Mosh](https://github.com/mobile-shell/mosh).**

Phantom Mosh combines Mosh's State Synchronization Protocol (SSP) with a separate
encrypted UDP transport to explore long-lived session key management, recovery
after network changes and reduced exposure of protocol metadata. The current
tree includes a working Linux SSH-to-PTY terminal, authenticated remote exit
status, recovery tests and reproducible loopback measurements. Upstream history,
attribution and the inherited Mosh v2 executables are preserved. This is an
independently branded fork, not an official Mosh release.

**Experimental, not production-ready.** The custom protocol has not received
independent cryptographic review. Small loopback traffic measurements exist,
but fingerprint resistance has not been established. Read the
[security limitations](docs/phantom/security.md) before trying it.

[Get started](docs/phantom/terminal-integration.md) ·
[Architecture](docs/phantom/architecture.md) ·
[Documentation index](docs/phantom/README.md) ·
[Status and roadmap](docs/phantom/integration.md)

## Why Phantom Mosh?

Interactive terminals need to converge on the latest screen and deliver input
correctly while packets are lost, reordered or delayed. Phantom reuses Mosh's
existing state-diff, compression, fragmentation and acknowledgement engine, then
places session ownership, path validation and cryptographic state behind an
explicit transport boundary.

The research question is how to retain that terminal behaviour while improving
key lifecycle and understanding the metadata a network observer can still see.
Protecting packet numbers alone does not hide packet sizes, timing, direction or
endpoints. The project keeps protocol implementation, terminal acceptance and
traffic measurements separately reviewable.

The [development direction](docs/phantom/integration.md#transport-comparison)
is to preserve the reusable terminal/session work and compare the custom
transport with a QUIC DATAGRAM alternative. That comparison is planned;
there is no QUIC backend or transport-selection option in this checkout.

## What works today

- The record layer provides directional HKDF-SHA-256 key derivation,
  ChaCha20-Poly1305 encryption, protected packet numbers, encrypted epoch
  acknowledgements, acknowledgement-gated key updates and replay protection.
- Linux SSH startup requires existing host trust and noninteractive credentials.
  The session channel validates UDP return paths and supports recovery after
  client source-port changes without resetting cryptographic state.
- The opt-in Linux `phantom-mosh-terminal` and `phantom-mosh-terminal-server`
  connect Mosh's State Synchronization Protocol (SSP) to a real PTY. They carry
  remote exit status and have real-clock loopback recovery coverage.
- The separate `phantom-mosh-probe` and `phantom-mosh-server` are diagnostics for
  authenticated startup, UDP confirmation and close. They do not start a shell.

**The inherited `mosh`, `mosh-client` and `mosh-server` still use upstream Mosh
v2.** Building this fork does not switch those executables to Phantom. There is
no `--protocol=v3` option, native Windows terminal client, local prediction or
Mosh escape-key menu in the experimental terminal. Installation is off by default.

| Executables | Purpose | Build |
| --- | --- | --- |
| `phantom-mosh-terminal`, `phantom-mosh-terminal-server` | Experimental Linux interactive terminal using the Phantom transport | Autotools libraries plus CMake SSP opt-in |
| `phantom-mosh-probe`, `phantom-mosh-server` | Startup, UDP confirmation and shutdown diagnostics; no shell | Standalone Linux CMake build |
| `mosh`, `mosh-client`, `mosh-server` | Inherited Mosh v2 runtime | Original Autotools build |

The exact record, diagnostic-session and terminal application profiles are
documented in the [architecture guide](docs/phantom/architecture.md#compatibility).
The experimental terminal requires matching Phantom endpoints and does not
negotiate a fallback to upstream Mosh.

## Choose a build

Clone the repository and run commands from its root:

```sh
git clone https://github.com/sednalabs/phantom-mosh.git
cd phantom-mosh
```

### Record and session components

Requires a C++17 compiler, CMake 3.16+, Python 3.8+ and OpenSSL development headers.
Use a maintained OpenSSL release. This build does **not** include the terminal.

```sh
cmake -S src/phantom -B build/phantom -DCMAKE_BUILD_TYPE=Release
cmake --build build/phantom --parallel
(cd build/phantom && ctest --output-on-failure)
```

UDP and process tests are POSIX-only. The SSH supervisor and session executables
require Linux with glibc 2.34+; the server also requires `close_range` support
(Linux 5.9+). Use `-DPHANTOM_BUILD_SSH_STARTUP=OFF` when that supervisor is not
supported. OpenSSH tests use an isolated loopback server and disposable keys;
install client/server tools and configure `-DPHANTOM_REQUIRE_SSH_TESTS=ON` to
make missing prerequisites fail instead of skip. A skipped test is not a pass.

### Experimental Linux terminal

Follow the [SSP build guide](docs/phantom/ssp.md#build-and-test) to build the
inherited Mosh libraries and the opt-in terminal from the same checkout. Then
follow [terminal setup](docs/phantom/terminal-integration.md#build-and-run) for
SSH authentication, UDP reachability, shell selection and optional installation.
Both endpoints need compatible terminal draft-02 binaries and `C.UTF-8`.
SSH proxies do not tunnel the UDP session. No production deployment is implied.

Once matching binaries are built on both hosts, start the terminal with your
ordinary SSH account and an absolute remote server path:

```sh
build/ssp/phantom-mosh-terminal \
  --server /absolute/path/phantom-mosh-terminal-server user@host
```

The server selects a UDP port dynamically. `--udp-port` changes the client's
destination only; it does not set the server's listening port. Check the
[network prerequisites and CLI reference](docs/phantom/terminal-integration.md)
before trying a host behind a firewall or NAT.

### What recovery means

Recovery keeps an existing session alive while its processes and cryptographic
state survive a network interruption. The terminal can revalidate a changed
client source port; its server endpoint remains fixed. A process crash, reboot
or restored snapshot requires a fresh authenticated startup. There is no
saved-session reattachment or restart-resume feature. See the
[recovery guide](docs/phantom/terminal-recovery.md).

### Inherited Mosh v2

The original Autotools build and upstream behavior remain available. Its
[inherited README](docs/upstream-mosh.md) and [manual pages](man/) describe v2,
not the experimental Phantom terminal.

For sanitizer builds, dependency examples and contribution checks, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [Documentation index and reading paths](docs/phantom/README.md)
- [Architecture, compatibility and transport boundaries](docs/phantom/architecture.md)
- [Terminal setup and limitations](docs/phantom/terminal-integration.md)
- [SSP build and transport adapter](docs/phantom/ssp.md)
- [Current integration status and roadmap](docs/phantom/integration.md)
- [Security assumptions and review priorities](docs/phantom/security.md)
- [Security reporting](SECURITY.md)
- [Record protocol draft-01](docs/phantom/protocol-draft-01.md)
- [Startup codec and secret handoff](docs/phantom/startup.md)
- [SSH startup supervisor](docs/phantom/ssh-startup.md)
- [Remote-session control](docs/phantom/remote-session.md)
- [Application datagram channel](docs/phantom/session-channel.md)
- [Terminal recovery qualification](docs/phantom/terminal-recovery.md)
- [Record protocol review](docs/phantom/protocol-review-2026-11-05.md)
- [Traffic-analysis evaluation](docs/phantom/evaluation.md)
- [Matched measurement protocol](docs/phantom/matched-measurement.md)
- [Historical ACK-loop before/after pilot](docs/phantom/loopback-pilot.md)
- [Integrated loopback pilot](docs/phantom/integrated-loopback-pilot.md)
- [CI runner policy](docs/phantom/ci-runners.md)

Measurement reports pin the revisions and binaries they tested. Their results do
not automatically apply to later commits. Loopback tests do not establish WAN,
kernel-NAT, physical-link or statistical privacy acceptance.

The retained integrated pilot used six matched pairs of real terminal sessions
running scripted workloads. In its 12-second windows, both implementations sent eight
idle datagrams; typing produced 14 for stock Mosh and 17 for Phantom, with
different payload rates. Those results document a bounded regression check and
remaining visible differences. The full
[statistical evaluation contract](evaluation/contract.json) is still
`not_measured`; no anonymity, indistinguishability or traffic-analysis resistance
claim follows from the pilot.

See [the roadmap](docs/phantom/integration.md) for independent review, terminal
usability, real-network qualification, platform support and transport comparison.
The default branch is `master`; development documentation describes that branch,
while dated reports describe only their pinned source and binary revisions.

[MoshWatch](https://github.com/sednalabs/moshwatch) is a separate monitoring
project, not a transport dependency.

## License

Upstream licenses and attribution are preserved. See [COPYING](COPYING),
[COPYING.iOS](COPYING.iOS) and [COPYING.phantom](COPYING.phantom) for the applicable
terms and the OpenSSL linking permission for new files.
