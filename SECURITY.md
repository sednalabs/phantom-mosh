# Security policy

Phantom Mosh is experimental and has not received independent cryptographic
review. There is no production security-support or backport commitment. The
[security notes](docs/phantom/security.md) describe the known limitations and
outstanding review work; passing tests is not security certification.

## Reporting a suspected vulnerability

Do not put live session keys, credentials, terminal contents, private packet
captures or exploit details affecting other users in a public issue or pull
request.

Check the repository's [Security page](https://github.com/sednalabs/phantom-mosh/security)
for a private reporting option. If GitHub displays **Report a vulnerability**,
use that flow. If private reporting is unavailable, do not publish vulnerability
details in a pull request or another public channel. This fork currently has Issues
disabled and lists no dedicated private contact here; a maintainer must provide
a private reporting route before sensitive details can be shared.

A report shared through an agreed private channel should identify the affected
commit, platform, component, expected and actual behavior, and a minimal
reproducer using disposable data. Describe impact and uncertainty separately.
Do not test systems or accounts you do not control.

For non-sensitive documentation or code corrections, open a pull request with
the exact revision and sanitized test results. This repository currently has
Issues disabled. See [CONTRIBUTING.md](CONTRIBUTING.md).
