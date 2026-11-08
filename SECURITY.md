# Security policy

AgentTrap is a honeypot. Its facade is built to look vulnerable: the planted
keys, tokens, passwords, "exposed" files, web shells and cloud credentials in
`personas/`, `adapters/` and `modules/` are decoys on purpose. None of them
grants access to anything real, so reports about them are not vulnerabilities.

A real vulnerability is one that lets someone get past the decoy, for example:

- reaching the hub, its admin API or dashboard, Postgres or Redis from a public network
- spoofing a spoke or the hub, or bypassing the spoke↔hub mTLS
- reading real files, running real commands or making the host send arbitrary
  outbound requests through a decoy
- injecting script into the admin dashboard through recorded attacker data
- crashing or exhausting the host through a decoy

## Reporting

Report privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**. Do not open a public issue for a security
problem. Include the affected version (commit), steps to reproduce and the
impact you observed.

## Supported versions

Only the latest commit on `main` is supported.
