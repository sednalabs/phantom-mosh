# Phantom Mosh documentation

This directory documents the experimental Phantom transport and Linux terminal.
The [project README](../../README.md) is the starting point. The repository's
default branch is `master`; the inherited `mosh` executables still use Mosh v2.

## Choose a reading path

| Goal | Read |
| --- | --- |
| Understand what Phantom is and what has landed | [Architecture](architecture.md), then [status and roadmap](integration.md) |
| Build and try a Linux terminal | [SSP build guide](ssp.md#build-and-test), then [terminal setup](terminal-integration.md#build-and-run) |
| Understand outages, remapping and session lifetime | [Terminal recovery](terminal-recovery.md), [session channel](session-channel.md) and [remote ownership](remote-session.md) |
| Review cryptography and its limits | [Security notes](security.md), [record draft](protocol-draft-01.md) and [dated review](protocol-review-2026-11-05.md) |
| Understand authentication and secret handoff | [Startup codec](startup.md) and [OpenSSH supervisor](ssh-startup.md) |
| Assess the traffic evidence | [Evaluation contract](evaluation.md), [matched measurement method](matched-measurement.md) and [integrated pilot](integrated-loopback-pilot.md) |
| Contribute or check a change | [Contributing](../../CONTRIBUTING.md) and [CI runner policy](ci-runners.md) |
| Report a security concern | [Security policy](../../SECURITY.md) |
| Use the inherited Mosh v2 executables | [Preserved upstream README](../upstream-mosh.md) and [manual pages](../../man/) |

## Current implementation reference

| Document | Scope |
| --- | --- |
| [Architecture](architecture.md) | Layer ownership, executable families, compatibility and the proposed transport comparison |
| [Integration](integration.md) | Implemented capabilities, remaining work and acceptance criteria |
| [Terminal integration](terminal-integration.md) | Linux SSH-to-PTY setup, command options, exit status, process ownership and installation |
| [Terminal recovery](terminal-recovery.md) | Recovery behaviour, executable test coverage and limits of retained loopback evidence |
| [SSP](ssp.md) | Same-checkout build, connection adapter, scheduling, timing and byte accounting |
| [Session channel](session-channel.md) | One socket/crypto owner, bounded receive work, send outcomes and recovery deadlines |
| [Remote session](remote-session.md) | Detached server lifetime, path confirmation and control-only diagnostics |
| [SSH startup](ssh-startup.md) | Host trust, process supervision and authenticated bootstrap acceptance |
| [Startup](startup.md) | Strict profile selection, framing and descriptor-based secret handoff |
| [Record protocol](protocol-draft-01.md) | The implemented experimental record format and key schedule |
| [Security](security.md) | Assumptions, review scope, secret lifetime and supported claims |
| [Evaluation](evaluation.md) | Observer inputs and requirements for a future statistical claim |
| [Matched measurement](matched-measurement.md) | Comparable workloads, provenance and capture-health requirements |
| [CI runners](ci-runners.md) | Standard public-runner policy and verification |

## Dated evidence

These reports are retained research records. Their hashes, measured values and
original scope are not revised to describe later commits.

| Report | What it records | What it does not establish |
| --- | --- | --- |
| [5 November record review](protocol-review-2026-11-05.md) | A bounded review of the named record-layer revision and its tests | Independent cryptographic assurance or a whole-system audit |
| [ACK-loop pilot](loopback-pilot.md) | Before/after observations around the terminal acknowledgement fix | A current-build benchmark or statistical privacy result |
| [Integrated draft-02 pilot](integrated-loopback-pilot.md) | Six matched pairs with pinned source, binaries, collector and session-health evidence | WAN behaviour, a realistic background corpus or classifier acceptance |
| [Recovery qualification](terminal-recovery.md) | Current test design plus separately pinned historical recovery runs | Recovery after process restart or physical-network acceptance |

Test definitions describe checks available in the repository. A passing run is
evidence only for its actual checkout and environment. Missing prerequisites,
skipped tests and collection failures must remain visible in reports. The
[machine-readable statistical contract](../../evaluation/contract.json) remains
`not_measured`.

MoshWatch is a [separate project](https://github.com/sednalabs/moshwatch), not a
transport dependency. Its results do not automatically qualify Phantom Mosh.
