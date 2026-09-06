# Phantom Mosh

An experimental, upstream-derived Mosh descendant investigating long-lived key
management and unnecessary wire metadata. This is an independent project, not an
official Mosh release and not a claim of undetectability.

## What is implemented

The initial contribution implements a C++17/OpenSSL record layer with directional
HKDF-SHA-256 secrets, ChaCha20-Poly1305 authenticated encryption, protected full
packet numbers, encrypted epoch acknowledgements, bounded key selection,
automatic acknowledgement-gated key updates, replay rejection and old-key
retirement. It includes RFC known-answer tests, an independently implemented
Python wire oracle, a deterministic lossy-network model, actual loopback UDP
migration tests and executable evaluation-leakage guards.

**The inherited `mosh`, `mosh-client` and `mosh-server` still use upstream Mosh v2.**
The new record layer is not yet connected to SSH bootstrap, SSP, terminal state or
packaging. There is no working `--protocol=v3` option in this PR. Keeping that
boundary visible is preferable to silently changing the protocol of existing
binaries. See the [integration plan](docs/phantom/integration.md).

## Build and test the record layer

Use a maintained OpenSSL installation with development headers, CMake 3.16+,
a C++17 compiler and Python 3.8+:

```sh
cmake -S src/phantom -B build/phantom -DCMAKE_BUILD_TYPE=Release
cmake --build build/phantom --parallel
ctest --test-dir build/phantom --output-on-failure
```

For Clang address/undefined-behavior sanitizer tests, add
`-DCMAKE_CXX_COMPILER=clang++ -DPHANTOM_SANITIZERS=ON` in a separate build directory.
The core and tests do not require a running SSH server. The real UDP test is
POSIX-only; native Windows terminal support has not been implemented or validated.
The upstream Autotools build remains unchanged. Its original instructions and
attribution are preserved byte-for-byte in [the upstream README](docs/upstream-mosh.md).

## What the results do not establish

Removing the original clear sequence marker does not prove statistical traffic
fingerprint resistance. Fixed overhead, lengths, direction, timing, bootstrap
correlation and roaming may remain identifying. A symmetric key ratchet is not
post-compromise recovery, and does not introduce a fresh DH exchange or
post-quantum key exchange. This new protocol composition needs independent review
before production use.

PHANTOM WEAVE informs the [evaluation contract](docs/phantom/evaluation.md), not a
certification. PW1, PW2 and PW3 are research generations. There is no asserted
PW4 assurance level. Unit tests and simulated outages are not a traffic-analysis
study, a six-month deployment, or proof of universal concealment.

## Project boundaries and provenance

This repository preserves `mobile-shell/mosh` ancestry. MoshWatch remains a
separate observer/evaluator, not a dependency of the transport or a source of
privileged features for a passive classifier. The first clear-header experiment
remains in [MoshWatch PR #60](https://github.com/sednalabs/moshwatch/pull/60);
this implementation supersedes that proposed wire layout rather than publishing
it as a privacy improvement.

Read the [protocol draft](docs/phantom/protocol-draft-01.md),
[security review notes](docs/phantom/security.md),
[repository decision](docs/phantom/adr-0001.md) and
[engineering evidence](engineering/initial-pr/README.md).
Inherited licenses and credits remain intact. New-file terms and the OpenSSL
linking permission are in [COPYING.phantom](COPYING.phantom).
