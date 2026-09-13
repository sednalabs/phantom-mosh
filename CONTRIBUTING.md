# Contributing

Keep pull requests focused and include tests for changed behavior. The record
layer is experimental; its protocol specification and test vectors must stay in
step with the implementation.

## Build and test

Follow the [README](README.md) for the release build. For Clang AddressSanitizer
and UndefinedBehaviorSanitizer:

```sh
cmake -S src/phantom -B build/phantom-sanitizers \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=clang++ \
  -DPHANTOM_SANITIZERS=ON
cmake --build build/phantom-sanitizers --parallel
(cd build/phantom-sanitizers && ctest --output-on-failure)
```

Use clang-format 14 with the repository's `.clang-format`:

```sh
find src/phantom tests/phantom -type f \( -name '*.cc' -o -name '*.h' \) \
  -exec clang-format-14 -i {} +
```

Changes to inherited Mosh code must also pass its existing Autotools tests.
Build instructions are in [the upstream README](docs/upstream-mosh.md).

## Protocol and evaluation changes

Include negative tests for malformed records, replay, reordered delivery, lost
acknowledgements and key transitions. Preserve unique packet-number ownership,
bounded receiver work and explicit key retirement. Tests must remain active in
release builds. Wire-format changes need updated independent vectors and a new
authenticated profile identifier.

Keep evaluator-only session metadata out of passive classifier inputs. Report
capture failures and unsuccessful experiments, and distinguish simulated tests
from actual terminal or network measurements. See the
[evaluation guide](docs/phantom/evaluation.md).

Do not include live session keys, terminal contents or private packet captures
in issues, test fixtures or logs. Preserve upstream attribution and the applicable
license notices when changing or importing code.
