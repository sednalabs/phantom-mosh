# Traffic-analysis evaluation

This evaluation approach separates removal of explicit wire markers from
statistical resistance to identification.
No traffic-classification results or independent replication are available yet.

The executable tools in `evaluation/` validate inputs, dataset partitions and
fixed-threshold scores. They are not a trained detector or a complete experiment.

## Available evidence

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| Synthetic evaluator tests | Input validation, accounting and partition/score safeguards for their fixtures | Observed network behaviour or classifier performance |
| [ACK-loop pilot](loopback-pilot.md) | A revision-pinned before/after regression measurement | An independent privacy holdout or isolated header-protection benefit |
| [Integrated terminal pilot](integrated-loopback-pilot.md) | Descriptive counts and payload rates for six matched pairs on a userspace loopback relay | WAN performance, identification resistance, anonymity or realistic background comparison |
| [Recovery qualification](terminal-recovery.md) | The documented process and session outcomes under its controlled impairments | A passive traffic corpus or production-network acceptance |

The checked-in [evaluation contract](../../evaluation/contract.json) still says
`not_measured`: its classification/linkage measurements and acceptance thresholds
are unset, and independent review and replication are not performed. This does
not mean no measurements exist; it means the descriptive pilots have not satisfied
that separate statistical contract.

## Observer inputs and ground truth

The initial passive feature extractor accepts only `time_ms`,
`udp_payload_bytes` and `direction`. Direction is +1 or -1 according to the
observer's declared endpoint orientation, not a privileged client identity.
Timestamps must be ordered; absolute time is not emitted as a feature. Empty,
malformed and incomplete packet records are rejected.

Session, workload, domain and collection identities are evaluator-only grouping
inputs. Process IDs, true RTT, key epochs, migration labels and MoshWatch telemetry
must not enter classifier features. Allowlists help prevent direct leakage, but
acquisition hosts, generators, timestamp precision and missingness can still
introduce indirect clues. Match acquisition methods and audit those variables.

Raw-payload inspection requires a separately declared observer contract. Track
capture loss and session health independently: broken instrumentation or a failed
session must not count as improved privacy.

## Experimental design

Compare pinned upstream Mosh and Phantom builds under matched typing, editing,
redraw, bulk-output and idle workloads. An optional clear-header reference can
help isolate the contribution of header protection. Capture actual traffic from
each implementation; label manually altered traces as ablations. Standalone
record tests are not captures of an integrated SSP terminal.

Include realistic interactive UDP background traffic, not just bulk transfers.
Measure three outcomes separately: identifying the protocol, characterizing
interactive activity, and linking flows across migrations. Linkage tests must
report false joins between unrelated sessions as well as missed true joins.

Challenge combined length, direction and timing signals at multiple timescales.
Vary latency, loss, reordering and MTU, and examine sparse or asymmetric views
around key updates, outages and migrations. Include shared NATs and concurrent
unrelated sessions as difficult background cases.

Hold out entire sessions and additional workload, path/domain or collection
families. Randomly splitting packets from the same session is invalid. Train
detectors against the candidate itself, select settings and thresholds on
training/validation data, then freeze the build, detector, corpus, observer,
observation duration and partition before exposing test labels. Revisions tuned
on a failed holdout require a fresh holdout.

## Reporting

`score_fixed_threshold` reports true/false-positive counts, rates and descriptive
95% Wilson intervals. It neither selects a threshold on test labels nor returns
an automatic privacy pass. Inputs must be independent evaluation units;
overlapping windows require session-clustered analysis instead. Caller-supplied
health flags are assertions, not proof of valid collection or independent units.

Report observation health, abstention, absolute residual identification rates and
uncertainty alongside remote-confirmed latency, recovery, byte overhead and radio
cost. Low false-positive claims require enough independent background samples,
not simply zero errors in a small dataset. Publish null and negative results.

The [experiment contract](../../evaluation/contract.json) leaves acceptance
thresholds and measurements unset until an experiment is specified and run.
Independent challenge construction and replication are needed for stronger
claims. Padding, traffic shaping and idle-scheduling changes should follow
measured benefit rather than assumptions about how random traffic ought to look.

## Reproducible matched summaries

The [matched measurement protocol](matched-measurement.md) and
`evaluation/compare.py` provide strict paired metadata summaries, pinned artifact
provenance and synthetic regression tests. New campaigns require actual terminal
capture with their own source and binary pins; the retained historical corpora are not measurements of the current branch.
These summaries are not classifier or privacy results.

The [roadmap](integration.md) proposes comparing a future QUIC DATAGRAM backend
with the custom transport. No such backend or comparison is included in this
evidence. Adding a candidate requires an explicit experiment and schema change;
do not relabel an existing corpus as a QUIC or current-build result.
