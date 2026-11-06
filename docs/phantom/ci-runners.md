# CI runner policy

Workflows use only the reviewed standard GitHub-hosted Linux and macOS labels:
`ubuntu-latest`, `ubuntu-22.04`, `ubuntu-24.04`, `macos-15`, and `macos-15-intel`.
GitHub currently provides standard hosted execution free for public repositories;
larger runners remain billable even when a repository is public.

The inherited macOS release jobs now select standard `macos-15-intel`, not the
retired `macos-12` image and not a `large`/`xlarge` variant. Their MacPorts installer
is pinned for macOS 15 with a SHA-256 check, and cache keys separate architecture,
OS image and MacPorts version. This is a runner/dependency configuration update,
not evidence that a release package has been produced or tested.

`tools/check_runners.py` (Python with PyYAML) scans every workflow, including
release jobs and matrix include rows. It rejects unapproved labels, self-hosted
arrays, runner groups, dynamic runner expressions and unaudited reusable jobs.
The runner-policy workflow checks both the source tree and negative test cases.
Adding a new label requires verifying its current standard/free status in GitHub's
reference and updating the allowlist deliberately.

This check is review-time protection, not a billing lock. A modified workflow can
schedule its own jobs before a different check fails, and administrators can
change policy. Do not interpret the lint result as an account spending guarantee.
Artifact/cache storage has separate billing rules; short retention and small
artifacts still matter. Changing repository visibility also changes the billing
assumptions. No self-hosted or organization-specific runner is required here.

References:
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/billing/concepts/product-billing/github-actions
