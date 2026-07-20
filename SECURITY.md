# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this service, please report it
privately. **Do not open a public issue.**

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's *Security* tab), or contact the
maintainers directly.

Please include:

- a description of the issue and its impact;
- steps to reproduce (a proof of concept if possible);
- the affected version or commit.

We will acknowledge your report as quickly as we can and keep you updated on the
fix and disclosure timeline.

## Scope notes

This service downloads caller-supplied URLs and posts to caller-supplied
webhooks. Both are protected by the SSRF guard in `ssrf.py` (IP-range blocking,
resolved-IP pinning, per-hop redirect re-validation). If you find a way to reach
an internal/metadata address, to have an unscanned file reported as clean, or to
exhaust worker resources, we especially want to hear about it.
