# Integrated draft-02 and recovery loopback pilot

Ops w18887. This is the next matched descriptive collection after the
[ACK-loop before/after pilot](loopback-pilot.md), not a detector or privacy result.
The new corpus is retained at
`evaluation/results/loopback-pilot-2026-11-06-integrated/`.

## Sources and unchanged controls

- Integrated Phantom: `f52273b183e7f9f4a99549804b4f43a3ca3e959d`,
  [PR #8](https://github.com/sednalabs/phantom-mosh/pull/8), combining terminal
  draft-02/status/lifecycle improvements from #7 `bb5c907` and #6 recovery.
- Stock Mosh: pristine upstream `decd9b705eb81626f694335b8d5940538beb06da`.
  Client/server SHA-256 values exactly match the prior pilot's stock binaries.
- The original collector is unchanged: SHA-256
  `8cb0a6e47256925f4016b4e089ecce033795b961db81b813a7cf498e13d5a3fe`.
- Identical synthetic workload, three idle pairs and three typing pairs, alternating
  implementation order, each with a fixed 12-second post-warmup observation window.
- The collector's fixed `phantom-draft-01` implementation label is retained for
  compatibility with the existing evaluator. It is not the negotiated terminal
  application profile: these binaries strictly select `phantom-mosh/terminal/draft-02`.
  Source and binary hashes, rather than that legacy label, identify the tested build.

All 12 sessions passed their computed remote-output witnesses and clean client
exits. Every relay ledger balances received/forwarded datagrams and has zero
observed socket drops. Keys, datagram payloads, endpoint identities and terminal
transcripts were not retained. Manifest, corpus, complete ledger, provenance and
computed summary are preserved. A regression guard reanalyzes the corpus and
checks its provenance, unchanged controls and all 12 health records.
All 16 Python evaluation tests and all 18 standalone component/evaluation CTests
passed on the final evidence tree. Hosted CI is checked separately for each
published revision.

## Observations

Values below are per 12-second window. Payload rates exclude IP/UDP headers.

| Workload | Stock datagrams | Phantom datagrams | Stock mean payload bytes/s | Phantom mean payload bytes/s |
| --- | ---: | ---: | ---: | ---: |
| Idle, 3 pairs | 8 each | 8 each | 44.3 | 73.2 |
| Typing, 3 pairs | 14 each | 17 each | 117.9 | 185.2 |

The idle and typing counts remain exactly the historical post-ACK-fix counts.
The feedback flood has not returned in this fixture after integrating recovery
and draft-02 terminal state. Residual size/count/rate differences remain plainly
visible; equal idle counts are not traffic equivalence.

The earlier post-fix corpus is retained unchanged. This is a regression
comparison against that historical collection, not a randomized concurrent
component-ablation experiment. Any payload-rate difference cannot be uniquely
attributed to one terminal or recovery change from these observations.

## Separate reliability evidence and limits

PR #8 has separate wall-clock SSH/PTY tests for two relay remaps, loss, duplication,
delay, a real two-second blackout, UTF-8/resize/counter witnesses and authenticated
remote exit status 7 after recovery. Its integrated release suite passed 23/23.
Those impairment tests are not the passive-metadata corpus here; this pilot uses
the unchanged normal-loopback profile to preserve the earlier measurement setup.

This remains a small synthetic workload on a userspace IPv4 loopback relay, not a
passive wire tap, kernel-NAT/router or WAN capture. There is no realistic background
corpus, classifier, blind holdout, independent replication or privacy acceptance.
The full statistical evaluation contract remains `not_measured`. No claim of
fingerprint resistance, anonymity or production readiness follows from this pilot.
