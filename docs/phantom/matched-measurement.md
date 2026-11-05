# Matched traffic measurement protocol

Status: the harness has synthetic regression tests and a separate
[small real-terminal loopback pilot](loopback-pilot.md). The full campaign below
has not been run. Neither this protocol nor that pilot establishes resistance
to identification, activity inference, or cross-flow linkage. The pilot uses
experimental terminal binaries from PR #7; these are not included in this
evaluation branch. Do not substitute control-probe traffic for terminals.

## Reproduce the available validation

From the repository root (Python 3 standard library only):

```sh
python3 -m unittest discover -s evaluation -p 'test_*.py' -v
python3 evaluation/compare.py evaluation/examples/synthetic-pair.json > summary.json
```

The example is two identical, hand-authored two-packet traces with placeholder
build digests, explicitly marked `synthetic`. It should produce zero paired
differences, 2 packets/s and 150 UDP payload bytes/s for each side. It is a tool
smoke test, not captured traffic, a performance benchmark or a privacy result.
The CMake test suite also runs these comparison guard tests.

## Capture campaign prerequisites

1. Obtain functioning stock Mosh and Phantom terminal client/server pairs. Pin
   source commits and SHA-256 hashes of the actual binaries. Record compiler,
   flags, library versions, OS, kernel, terminal dimensions and locale in a
   separate campaign manifest. A branch name is not a build pin. Retain both
   endpoint binary hashes in the campaign manifest; the normalized run's
   `binary_sha256` identifies a canonical JSON manifest of those two hashes.
2. Use a controlled, isolated test network and disposable sessions containing
   only synthetic terminal input. Capture only these test flows. Do not collect
   real terminal contents, keys or unrelated traffic. Do not commit raw captures.
3. Use the same acquisition point and timestamp precision for both protocols,
   including the same direction convention. Record observation health and drop
   counters independently of session success. Unknown/nonzero capture loss
   makes the pair ineligible, not evidence of quiet traffic.
4. Have an independent check confirm remote command completion and screen
   convergence. Client-side prediction is not a remote success acknowledgement.
   The terminal lane must supply the executable invocation and this check before
   collecting a real terminal corpus. PR #7 supplies an experimental frontend;
   the pilot runner checks computed remote output, not local echo.

## Matched collection

Freeze the campaign manifest before collecting data: revisions, workload script
and digest, network settings, acquisition procedure, fixed observation windows,
number of session pairs, order randomization seed and failure handling. Begin
with at least 30 independent paired sessions per workload/network condition as a
pilot, not a power calculation or acceptance threshold. Use new sessions rather
than treating packets or overlapping windows as independent samples.

Include separate idle, deterministic typing, editing/redraw and bulk-output
workloads, each with a 60-second observation window after startup. Keep SSH
startup outside that primary window; if startup is studied, collect a separate
matched campaign. Freeze exact workload timing, terminal size and remote command
before acquisition. Alternate/randomize which protocol runs first. Keep
application input and path conditions identical within each pair. Do not modify
packet lengths or timing after collection to make the implementations resemble
one another.

Start with loopback as an instrumentation check, then use two controlled hosts
and record actual path conditions. Additional paired campaigns should vary
latency, loss, reordering and MTU. Migration/outage experiments require their own
matching criteria and external health evidence. Loopback cannot establish
Internet/NAT behavior or realistic wireless/radio costs.

Normalize each packet to exactly these passive fields:

- `time_ms`: nonnegative milliseconds relative to the fixed window start.
- `udp_payload_bytes`: UDP length minus its 8-byte header, not frame/IP size.
- `direction`: +1 for a predeclared observer orientation, -1 for its reverse.

Select the session's flow during collection, including all externally verified
migration endpoints, without making endpoint/port values classifier features.
Handle capture duplication explicitly, preserve original packet order and do not
silently drop malformed, truncated, fragmented or offload-distorted observations.
If the capture cannot be normalized reliably, exclude it with a recorded reason.
A zero-packet window is rejected by this first harness and must be listed as an
excluded observation, not quietly removed from campaign accounting.

## Input and output contract

`evaluation/examples/synthetic-pair.json` shows the strict JSON-array schema.
Each `pair_id` must have exactly one `stock-mosh` and one `phantom-draft-01` run,
with distinct session IDs and identical workload digest, network/acquisition
profiles, evidence kind and observation duration. Profiles must reference frozen
campaign specifications, not vague labels. A comparison cannot mix builds or
synthetic/real evidence. Extra fields, duplicate JSON keys, missing/unhealthy
runs, unknown drops, out-of-window packets and reused session IDs are rejected.
Do not silently retry failed pairs until a favorable outcome appears: maintain
a failure ledger with all attempted pairs and reasons, outside passive inputs.

The comparator computes existing passive length/timing/direction features,
UDP payload byte totals and fixed-window rates, then per-pair Phantom-minus-stock
differences and their descriptive means. Idle leading/trailing time remains in
rate denominators. Byte totals exclude network/link headers and capture storage
size. The report binds the canonical corpus, raw input file, comparator and
observer hashes, and source/binary pins. Keep this report alongside the frozen
campaign manifest and failure ledger. Matching labels, hashes and health flags
are assertions, not proof of faithful collection or independent sessions.

## Claims intentionally left open

Paired summary differences are not classification accuracy or indistinguishability.
No detector is trained, no threshold is selected, and there are no confidence
intervals or automatic pass/fail privacy verdicts. The included loopback pilot is not the full terminal campaign. No background
UDP corpus, independent replication or radio-energy measurement is included. Do not populate `evaluation/contract.json` measurements from the
synthetic fixture or use this comparator as the full privacy evaluation.

After collecting a valid pilot, perform the separate held-out detector experiment
in [the evaluation guide](evaluation.md): realistic background sessions,
whole-session and domain/workload/collection holdouts, frozen thresholds,
absolute residual identification rates and independent challenge construction.
Report exclusions and null/negative results. Precision and power planning must
use the measured session-level variability rather than packet counts.
