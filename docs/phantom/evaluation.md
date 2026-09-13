# Traffic-analysis evaluation

This evaluation approach is informed by PHANTOM WEAVE research. It separates
removal of explicit wire markers from statistical resistance to identification.
No traffic-classification results or independent replication are available yet.

The executable tools in `evaluation/` validate inputs, dataset partitions and
fixed-threshold scores. They are not a trained detector or a complete experiment.

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
