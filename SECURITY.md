# Security policy

Do not open a public issue containing credentials, API-client configuration,
customer evidence, private infrastructure details, or other sensitive data.

Before publishing a release, run `./utils/validate-public-export.py` and a
history-aware secret scanner such as Gitleaks. Rotate any credential that may
have entered Git history; removing it from the current tree is insufficient.

Use the repository
[private vulnerability reporting page](https://github.com/ig-labs/velociraptor-skills/security/advisories/new)
when it is enabled. If it is unavailable, ask a maintainer for a private reporting
channel without including sensitive details in a public issue.
