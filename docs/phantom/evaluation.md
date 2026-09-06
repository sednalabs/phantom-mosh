# PHANTOM WEAVE transfer and evaluation contract

The research informs how this design is questioned. It has not certified this
implementation. The initial conclusion is narrowly testable: the old explicit
sequence/direction field and the prototype's clear epoch/ACK header are absent
from the new record grammar. Statistical identification remains unmeasured.

| Research generation | Decision adopted here | Executable evidence / remaining work |
| --- | --- | --- |
| PW1 | Freeze stock, clear-header and opaque candidates; inventory wire markers, sizes and timing before concealment changes. | Primitive and full-record vectors bind this candidate's bytes. Actual matched traffic corpora remain uncollected. |
| PW2 | Distinguish observation failure from privacy, and protocol identification from activity inference and cross-flow linkage. Keep evaluator truth out of passive features. | observer.py rejects unknown/privileged fields and invalid observation attestations; tests exercise session/domain split leakage. Independent capture health, hard negatives and false-join experiments remain required. |
| PW3 | Challenge residual joint signals, sparse/asymmetric observations, epoch transitions, multiple timescales and unseen workload/path combinations. Freeze candidate-aware detectors before holdouts. | Loss/reorder/epoch tests preserve protocol behavior; partition and frozen-threshold guards implement part of the evaluation discipline. No trained classifier, held-out PW challenge or replication has been run. |

PW generations are not assurance levels. A hypothetical stronger future observer
requires its own contract. No existing PW4 test or universal undetectability claim
is asserted.

## Observer and truth separation

For the initial executable feature scaffold, each packet has only `time_ms`,
`udp_payload_bytes` and `direction` (+1/-1 from a declared network-observer
orientation, not an oracle-provided client identity). Times must be ordered.
Absolute time is not emitted as a feature. Empty or incomplete observations fail
validation. The small aggregate feature set is a scaffold, not the strongest
possible detector and not a complete PW classifier implementation.

Ground-truth session, workload, domain and collection identities are evaluator-only
inputs to partition validation. Host process identity, true RTT, migration labels,
key epoch and MoshWatch fields are forbidden in the feature input. Separate files
and allowlists help, but cannot establish independent administration by themselves.
Feature values may still encode acquisition nuisance variables: use acquisition
matching, label permutation and host/generator/serialization audits.

A wire-marker detector may inspect raw payload bytes under a SEPARATELY declared
observer contract. Do not silently broaden this scaffold's input vocabulary.
Observation-health metrics must account for capture loss, supported instrumentation
and functioning sessions without supplying privileged labels to the classifier.

## Candidate-aware challenge design

Compare exact builds of stock Mosh, PR60's clear-header experiment and opaque
Phantom records. An adapter-free record test is not an SSP terminal capture.
Collect matched human-like typing, editing, redraw, bulk output and idle workloads,
with loss/reorder/MTU/latency variation and migration around key transitions.

Include realistic interactive UDP near-neighbours, not only bulk traffic. Score
protocol identification, interactive-activity inference and cross-flow joins
separately; continuity must report false joins as well as missed true joins.
Shared NAT, unrelated concurrent sessions and asymmetric pre/post-migration views
are important challenge cases. Evaluate sparse windows and long histories, and
hold out entire sessions plus workload, domain or collection families. Random
packet-level splits from the same session are invalid.

Select candidate-aware detector hyperparameters and operating thresholds using
training/validation only. Seal a manifest of candidate, detector, corpus,
observer, duration, split and thresholds before exposing test labels. Failed
holdouts become evidence, not another training split advertised as unseen.
Fresh candidates require fresh holdouts. Independent challenge construction and
replication are not replaced by this repository's own tests.

## Scoring and acceptance

`score_fixed_threshold` reports absolute TP/FP counts, TPR/FPR and descriptive
95% Wilson intervals. It never searches a threshold on test labels or returns
an automatic privacy pass. Its inputs must represent independent evaluation units;
overlapping windows require session-clustered analysis instead. Boolean attestations
are caller assertions, not proof of healthy observation or an honest partition.
Report abstention and review rates separately; do not drop uncertain samples to
inflate performance. Low-FPR claims require enough independent background units
and useful confidence bounds, not zero errors in a tiny sample.

The research's suggested 50% relative TPR reduction at 1% FPR and about 5 ms added
p95 remote-confirmed latency are proposed engineering budgets, not ratified release
criteria. Absolute residual detectability, uncertainty, byte/radio costs and
security/recovery gates also matter. `contract.json` intentionally has no accepted
threshold or measured result yet. Timing/length shaping, padding, cover traffic
and artificial roaming are deferred until measurements identify material benefit.
