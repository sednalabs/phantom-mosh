# Phantom Mosh

Phantom Mosh is an experimental fork of [Mosh](https://github.com/mobile-shell/mosh)
exploring long-lived session key management and reduced exposure of transport
metadata. It preserves upstream history and is not an official Mosh release.

**Experimental, not production-ready.** The custom protocol has not received
independent cryptographic review. Small loopback traffic measurements exist,
but fingerprint resistance has not been established. Read the
[security limitations](docs/phantom/security.md) before trying it.

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

### Inherited Mosh v2

The original Autotools build and upstream behavior remain available. Its
[inherited README](docs/upstream-mosh.md) and [manual pages](man/) describe v2,
not the experimental Phantom terminal.

For sanitizer builds, dependency examples and contribution checks, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

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
- [Integrated loopback pilot](docs/phantom/integrated-loopback-pilot.md)
- [CI runner policy](docs/phantom/ci-runners.md)

Measurement reports pin the revisions and binaries they tested. Their results do
not automatically apply to later commits. Loopback tests do not establish WAN,
kernel-NAT, physical-link or statistical privacy acceptance.

[MoshWatch](https://github.com/sednalabs/moshwatch) is a separate monitoring
project, not a transport dependency.

## License

Upstream licenses and attribution are preserved. See [COPYING](COPYING),
[COPYING.iOS](COPYING.iOS) and [COPYING.phantom](COPYING.phantom) for the applicable
terms and the OpenSSL linking permission for new files.
