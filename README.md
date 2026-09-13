# Phantom Mosh

Phantom Mosh is an experimental fork of [Mosh](https://github.com/mobile-shell/mosh)
exploring long-lived session key management and reduced exposure of transport
metadata. It preserves upstream history and is not an official Mosh release.

## Status

The new record layer implements directional HKDF-SHA-256 key derivation,
ChaCha20-Poly1305 encryption, protected packet numbers, encrypted epoch
acknowledgements, acknowledgement-gated key updates, replay protection and
previous-key retirement.

Startup support includes a strict message codec, a POSIX descriptor-handoff
reader and a Linux OpenSSH supervisor. The supervisor verifies SSH completion,
requires existing host trust and handles deadlines, cancellation and child cleanup.

**The existing `mosh`, `mosh-client` and `mosh-server` executables still use
upstream Mosh v2.** The startup components are not yet connected to a production
server, terminal handling or Mosh's State Synchronization Protocol (SSP). There is no
`--protocol=v3` option or native Windows client yet.

The protocol is experimental and needs independent security review before
production use. Traffic fingerprint resistance has not been measured. See the
[security notes](docs/phantom/security.md) for limitations.

## Build and test

The standalone record layer requires a C++17 compiler, CMake 3.16+, Python 3.8+
and OpenSSL development headers. Use a maintained OpenSSL release.

```sh
cmake -S src/phantom -B build/phantom -DCMAKE_BUILD_TYPE=Release
cmake --build build/phantom --parallel
(cd build/phantom && ctest --output-on-failure)
```

Tests cover cryptographic reference vectors, an independent wire-format oracle,
key updates, replay, loss and reordering, simulated long outages, UDP rebinding
and evaluation input validation. Startup tests cover malformed and fragmented
messages, secret ownership, deadlines and a child-process/pipe/UDP exchange.
UDP and process tests are POSIX-only. The SSH supervisor currently requires
Linux/glibc 2.34+; disable it with `PHANTOM_BUILD_SSH_STARTUP=OFF` elsewhere.
Real SSH tests create an isolated loopback server with disposable keys. Install
OpenSSH client/server tools and set `PHANTOM_REQUIRE_SSH_TESTS=ON` to require
these tests; without the tools, developer builds report an explicit skip.

For sanitizer builds and formatting, see [CONTRIBUTING.md](CONTRIBUTING.md).
The inherited Autotools build is unchanged; its instructions are in the
[upstream README](docs/upstream-mosh.md).

## Documentation

- [Protocol specification](docs/phantom/protocol-draft-01.md): wire format, key schedule and state machine.
- [Startup and secret handoff](docs/phantom/startup.md): message format and launcher responsibilities.
- [SSH startup supervisor](docs/phantom/ssh-startup.md): authentication, process ownership and integration tests.
- [Security notes](docs/phantom/security.md): assumptions, limitations and review targets.
- [Integration roadmap](docs/phantom/integration.md): bootstrap, SSP and platform work.
- [Traffic-analysis evaluation](docs/phantom/evaluation.md): observer inputs and experiment design.

[MoshWatch](https://github.com/sednalabs/moshwatch) remains a separate monitoring
project, not a transport dependency. Evaluation draws on PHANTOM WEAVE research;
the methods and limitations are described in the evaluation guide.

## License

Upstream licenses and attribution are preserved. See [COPYING](COPYING),
[COPYING.iOS](COPYING.iOS) and [COPYING.phantom](COPYING.phantom) for the applicable
terms and the OpenSSL linking permission for new files.
