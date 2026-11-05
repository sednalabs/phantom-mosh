# Real terminal loopback pilot, 2026-11-05

This is a small descriptive measurement, **not a fingerprint-resistance result**.
The first collection exposed excessive idle traffic in the experimental Phantom
terminal. After an ACK-only echo-loop bugfix, an identical second collection
shows the flood is gone, while payload-size and typing-count differences remain. No classifier, background corpus,
identification rate, linkage outcome, confidence interval or privacy pass is
reported. Do not generalize these counts to Internet paths or other workloads.

## First collection: before the fix

Six matched pairs, comprising three idle pairs and three typing pairs, with a
fixed 12-second post-warmup observation window per independent session. All 12
primary sessions completed successfully, with computed remote warmup/completion
witnesses and clean client exits. All typing sessions produced the three computed
remote results. No primary sessions were excluded or retried. The relay reported
zero socket overflow drops and equal received/forwarded counts in every session.

- Ordinary Mosh: pristine `mobile-shell/mosh` commit
  `decd9b705eb81626f694335b8d5940538beb06da`, independently built here. Its upstream
  master ref was checked directly; local source was clean and its binary version
  reported `decd9b7`. This is an upstream source build, not a packaged release.
- Phantom: experimental terminal PR #7 commit
  `ce7d4a1020c8167df66feecccf0b392a40359a0f`, optimized release binaries with the
  validated UDP-port override. Per-binary hashes are in the manifest.
- Both: `/bin/sh -i`, `C.UTF-8`, `xterm-256color`, local 24x80 PTY, same host and
  loopback userspace relay. Mosh local prediction was disabled. SSH startup and
  session close are outside the measurement window. Phantom startup used an
  isolated disposable SSH daemon with explicit host trust; stock Mosh startup
  used its local server bootstrap. This difference is outside the measured window.
- Typing: at seconds 2, 4 and 6, submit the frozen command bytes in the runner.
  Remote shell arithmetic yields 42, 49 and 56; those results are not present
  literally in the submitted command, so command echo is not a success witness.
  Idle receives no commands during its window. Both get identical warmup and
  final completion checks outside the window.

## Before-fix observations

Each list contains the three independent 12-second windows. Byte counts include
UDP payload only, summed across both directions, not UDP/IP/link headers.

| Workload | Implementation | Datagrams per window | UDP payload bytes per window | Mean datagrams/s | Mean payload bytes/s |
| --- | --- | --- | --- | ---: | ---: |
| Idle | Mosh | 8, 8, 8 | 540, 555, 554 | 0.667 | 45.806 |
| Idle | Phantom | 111, 113, 114 | 12507, 12730, 12909 | 9.389 | 1059.611 |
| Typing | Mosh | 14, 14, 14 | 1431, 1428, 1440 | 1.167 | 119.417 |
| Typing | Phantom | 206, 207, 207 | 23632, 23733, 23750 | 17.222 | 1975.417 |

These are useful regression observations: the implementations have visibly
different length/timing/direction metadata in this setup. They do not establish
which mechanism causes the difference or how well a detector generalizes. No
protocol code changed during this first collection. The subsequent server
correction and separate regression collection are documented below.

## Post-fix regression collection

The terminal lane traced the feedback loop to registering an echo ACK on every
remote SSP state-number change, including ACK-only states with empty UserStream.
PR #7 commit `ebd798fd58cca6540a3c6da9869f7124e194ac7c` registers echo ACKs only
for actual nonempty input, matching the inherited application behavior. The
terminal lane added an independent fail-before/pass-after SSH regression.
This is a correctness fix, not packet camouflage or a statistical privacy claim.

The exact same collector file hash, workload specification and upstream binary
hashes were verified before the rerun. Three new pairs per workload were collected,
again with all 12 sessions passing the remote witnesses and clean exit. There
were no excluded/retried sessions or observed relay socket drops. The original
before corpus is retained unchanged; the
[after-fix corpus](../../evaluation/results/loopback-pilot-2026-11-05-after-fix/)
is a separate collection. Session IDs are local to each corpus.

| Workload | Implementation | Datagrams per window | UDP payload bytes per window | Mean datagrams/s | Mean payload bytes/s |
| --- | --- | --- | --- | ---: | ---: |
| Idle | Mosh | 8, 8, 8 | 506, 557, 558 | 0.667 | 45.028 |
| Idle | Phantom fixed | 8, 8, 8 | 898, 890, 888 | 0.667 | 74.333 |
| Typing | Mosh | 14, 14, 14 | 1408, 1428, 1393 | 1.167 | 117.472 |
| Typing | Phantom fixed | 17, 17, 17 | 2163, 2135, 2154 | 1.417 | 179.222 |

Phantom's idle counts fell from 111–114 to 8, and typing counts from 206–207
to 17. Equal idle packet counts are **not traffic equivalence**: payload bytes
remain different, and typing still has more datagrams. This is a post-fix
regression observation informed by the first collection, not an untouched privacy
holdout. Both collections retain all the instrumentation/sample limitations below.

## Evidence and reproduction

The [evidence directory](../../evaluation/results/loopback-pilot-2026-11-05/)
contains the frozen manifest, normalized metadata-only corpus, complete primary
attempt ledger, descriptive comparator output and build/provenance addendum.
The manifest binds the exact collection runner hash and binary hashes. The
summary binds the canonical corpus, comparator and observer hashes. The
provenance addendum binds the final compact corpus file bytes. No packet payload,
terminal transcript, key, hostname or endpoint address is in the corpus.

To reproduce the analysis without starting sessions:

```sh
python3 evaluation/compare.py evaluation/results/loopback-pilot-2026-11-05/corpus.json
python3 -m unittest discover -s evaluation -p 'test_*.py' -v
```

To recollect the first collection, build the pinned upstream and Phantom sources, then use a fresh
output directory on a controlled Linux host. The runner needs `sshd`,
`ssh-keygen`, Python 3 and Linux `SO_RXQ_OVFL`; it does not require root, packet
capture privileges or changes to the operator's SSH configuration. Substitute
absolute binary paths:

```sh
python3 evaluation/loopback_pilot.py \
  --stock-client /absolute/upstream/mosh-client \
  --stock-server /absolute/upstream/mosh-server \
  --phantom-client /absolute/phantom/phantom-mosh-terminal \
  --phantom-server /absolute/phantom/phantom-mosh-terminal-server \
  --stock-sha decd9b705eb81626f694335b8d5940538beb06da \
  --phantom-sha ce7d4a1020c8167df66feecccf0b392a40359a0f \
  --pairs 3 --output /fresh/output/directory
```

For the post-fix collection, use Phantom binaries built from
`ebd798fd58cca6540a3c6da9869f7124e194ac7c`, pass that revision as
`--phantom-sha`, and choose another fresh output directory. Analyze its corpus
with the same comparator command. The evidence regression test reanalyzes both
published corpora and checks their file hashes and complete attempt ledgers.

The runner writes its plan before launching sessions, alternates implementation
order by pair index, records every attempted session, stops on failure, and never
substitutes a failed session with a quiet trace. A dedicated subreaper cleans up
its own remaining test descendants. Only lengths, relative monotonic timestamps
and direction survive relay forwarding; encrypted datagram bytes are transient.

## Limitations and prior exploration

- This is a userspace forwarding observer, not a passive wire capture. Its own
  scheduling and load can affect timings. Zero relay socket drops and successful
  `sendto` do not prove zero end-to-end loss. Health claims are confined to the
  collector and remote witnesses actually checked.
- Three sessions per workload and 12-second windows are a pilot, not the proposed
  30-pair/60-second campaign. There is no held-out detector evaluation, independent
  collection or domain/path variation. Do not treat packets as independent trials.
- The clients differ beyond the record layer: frontend rendering, prediction,
  scheduling, startup and build settings are not identical. This experiment
  cannot isolate the effect of encrypted headers. Full terminal-screen equality
  and shell exit-status propagation are not independently established here.
- The baseline full upstream `make check` suite was not run for this local build;
  actual terminal operation was checked in each measured session. The evaluation
  Python suite and CMake observer guards passed separately.
- Before this primary run, four preflight sessions and twelve sessions against
  this fork's inherited v2 binaries all completed. Their results informed the
  decision to build a verifiable upstream baseline; they are not mixed into this
  corpus. Those earlier runs are exploratory, not held-out evidence. No primary
  measurement was selected for favorable traffic counts.
- No raw captures or terminal contents are retained. No claims are made about
  cellular radio energy, NAT rebinding, outages, traffic identification, activity
  inference or cross-flow linkage. `evaluation/contract.json` remains
  `not_measured` for its planned classifier/privacy outcomes; this pilot does not
  satisfy those gates.
