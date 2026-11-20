# Security policy

Phantom Mosh is experimental and has not received independent cryptographic
review. There is no production security-support or backport commitment. The
[security notes](docs/phantom/security.md) describe the known limitations and
outstanding review work; passing tests is not security certification. This policy
covers this fork, including its experimental executables. It does not change the
upstream Mosh project's support policy.

## Review and support status

The custom record protocol, session lifecycle and Linux terminal remain research
software. Source review, primitive vectors, regression tests and sanitizer runs
provide evidence for their stated scope and revision; they are not an external
audit of the complete terminal stack. There is no supported production release
or promise of compatibility between experimental application profiles.

Network recovery keeps an existing process and its cryptographic state alive.
Process restart, restore and cloning are different operations: start a fresh
authenticated session instead of reusing live session state. See the
[ownership and recovery limits](docs/phantom/security.md#limitations).

## Reporting a suspected vulnerability

Do not put live session keys, credentials, terminal contents, private packet
captures or exploit details affecting other users in a public issue or pull
request.

Check the repository's [Security page](https://github.com/sednalabs/phantom-mosh/security)
for a private reporting option. If GitHub displays **Report a vulnerability**,
use that flow. If private reporting is unavailable, do not publish vulnerability
details in a pull request or another public channel. No dedicated private
contact is listed here; a maintainer must provide an agreed private reporting
route before sensitive details can be shared. GitHub reporting and Issues
availability are repository settings, so check the live page rather than assuming
a public channel is an acceptable substitute.

A report shared through an agreed private channel should identify the affected
commit, platform, component, expected and actual behavior, and a minimal
reproducer using disposable data. Describe impact and uncertainty separately.
Do not test systems or accounts you do not control.

For non-sensitive documentation or code corrections, open a pull request with
the exact revision and sanitized test results. See
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[documentation index](docs/phantom/README.md).
