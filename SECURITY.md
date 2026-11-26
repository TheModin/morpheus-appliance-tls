# Security policy

This plugin handles a TLS private key, a DNS API token, and it installs a small root-side helper on the appliance, so
security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting instead:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability** and describe the problem.

Useful details: the plugin version, the Morpheus version, what an attacker needs (a logged-in user, a role, local access
on the appliance), and the steps to reproduce. Please do not include real private keys or tokens in a report.

This is a personal project maintained in spare time. I will try to acknowledge a report within a week and to publish a fix
for confirmed issues as soon as I can, but I cannot promise a fixed timeline. Reporters are credited in the release notes
unless they prefer to stay anonymous.

## Supported versions

Only the latest release gets security fixes.

## What is in scope

- The plugin code: admin page, API routes, settings storage, the renewal logic.
- The root-side pieces the setup installs: `morpheus-tls-helper`, the sudoers rule, and the setup script
  (`morpheus-tls-setup.sh`).
- Anything that exposes the private key, the ACME account key or the DNS token, or lets a non-admin use the plugin.

Out of scope: vulnerabilities in Morpheus itself, in Let's Encrypt or in third-party libraries (report those upstream; I
will update a bundled library when a fixed version exists), and problems that need an attacker who already has root on the
appliance.

## How it is designed (for reviewers)

- The plugin runs as the unprivileged Morpheus application user. Root access is limited to two sudoers entries: the
  helper, and `morpheus-ctl restart nginx`. No general `sudo install`, `cp`, `rm` or `cat`.
- The helper only touches files below `/etc/morpheus/ssl/` (symlinks resolved, `..` refused), only `*.pem`, `*.crt`
  and `*.key`, only PEM content, and only the file modes 0600, 0640 and 0644. It cannot run commands and cannot reach
  `morpheus.rb` or `morpheus-secrets.json`. Key material is passed on stdin and is never logged.
- Known limitation: `sudo` lets the application user run the helper, so any code that runs as that user (including
  other Morpheus plugins) can read or replace `/etc/morpheus/ssl/*.pem|crt|key` through it. The helper narrows what
  can be done (see above) but cannot tell the TLS plugin apart from other code running as the same OS user.
- On a clustered Morpheus the scheduled renewal takes a short lease in Cypher so only one node runs it. Cypher has no
  compare-and-set, so this is best effort.
- The DNS token is stored in Morpheus Cypher and is never returned by the API (only a "token is set" flag). The ACME
  account key is `/etc/morpheus/ssl/acme-account.pem` with mode 0600.
- The admin page and API routes require the `tlsApplianceCert` permission. POST routes require the Morpheus CSRF token
  and an AJAX header.
- The setup script is installed by an administrator, never by the plugin, so a plugin upgrade cannot widen its own
  privileges. It validates the sudoers file with `visudo -c`, backs up `/etc/morpheus` first, and restores `morpheus.rb`
  if the reconfigure fails.
