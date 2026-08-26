# Security policy

## Supported versions

Security fixes are developed against the default branch and included in the next release. Users
should run the most recent published version and independently validate generated review-package,
report, diagram, and scaffold integrity before relying on an artifact.

## Report a vulnerability

Use the repository's private **Report a vulnerability** option under the GitHub Security tab when
available. Include the affected version, component, reproduction steps, impact, and any proposed
mitigation. Do not attach customer repositories, credentials, private keys, proprietary guidance,
or sensitive assurance evidence.

If private vulnerability reporting is unavailable, open a minimal issue requesting a private
contact channel without disclosing exploit details. Please do not publish an unpatched
vulnerability in a normal issue or pull request.

## Security boundary

PySFMEA is designed to scan source without importing or executing the target repository. Optional
assurance-test execution is a separate, explicit workflow that requires an approved disposable
container. Report and diagram integrity detect unreconciled change but do not authenticate an
author; governed review packages support optional detached Ed25519 authentication.

The scanner is not a malware sandbox, security certification, complete SAST engine, or proof that
a repository is safe. Run it with least privilege against repositories and configuration files
you are authorized to inspect. Treat HTML reports, CSV exports, runtime traces, model endpoints,
container images, imported evidence, and organizational guidance packs according to your own
data-handling and supply-chain policy.
