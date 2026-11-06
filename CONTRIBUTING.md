# Contributing

Keep pull requests focused and include tests for changed behavior. The record
layer is experimental; its protocol specification and test vectors must stay in
step with the implementation.

## Build and test

Follow the [README](README.md) for the standalone component build, or the
[SSP guide](docs/phantom/ssp.md#build-and-test) for Linux terminal dependencies
and a same-checkout inherited-library build. Run commands from the repository
root. Enable `PHANTOM_REQUIRE_SSH_TESTS=ON` when claiming real SSH coverage;
report missing prerequisites and skipped tests explicitly.

For standalone Clang AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S src/phantom -B build/phantom-sanitizers \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=clang++ \
  -DPHANTOM_SANITIZERS=ON
cmake --build build/phantom-sanitizers --parallel
(cd build/phantom-sanitizers && ctest --output-on-failure)
```

SSP/terminal sanitizer builds also require rebuilding the inherited libraries
with matching sanitizer/compiler flags; do not link sanitized adapters to stale
or differently instrumented archives. The
[SSP workflow](.github/workflows/phantom-ssp.yml) shows the complete sequence.

Use clang-format 14 with the repository's `.clang-format`:

```sh
find src/phantom tests/phantom -type f \( -name '*.cc' -o -name '*.h' \) \
  -exec clang-format-14 -i {} +
```

Changes to inherited Mosh code must also pass its existing Autotools tests.
Build instructions are in [the upstream README](docs/upstream-mosh.md).

## Documentation and public reports

Check commands, option names, relative links and documented build directories
against the current source. Keep the inherited v2 executables, record draft-01,
control-session draft-01 and terminal application draft-02 clearly distinguished.
Update current guidance when implementation lands, but preserve historical
measurement data, source/binary hashes and the scope of dated reports. Never
present past CI or measurements as a result for a new commit.

Useful repository checks, without compiling C++, include:

```sh
python3 -m unittest discover -s evaluation -p 'test_*.py' -v
python3 tools/check_runners.py
python3 -m unittest discover -s tests/ci -p 'test_*.py' -v
git diff --check
```

Report what ran, what passed and what was skipped. For suspected vulnerabilities,
follow [SECURITY.md](SECURITY.md) rather than publishing sensitive details.

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
