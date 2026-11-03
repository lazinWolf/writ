# Security policy

writ is a security tool, so we treat reports about it seriously and handle them privately.

## Reporting a vulnerability

Please **don't open a public issue.** Report it privately through GitHub instead:
https://github.com/lazinWolf/writ/security/advisories/new

Include what you found, how to reproduce it, and which commit or version you tested. We aim to acknowledge reports within 5 working days.

## What counts as a vulnerability

The guarantees writ makes, and the ones it doesn't, are stated in the README and in the threat model (`plan-v2.md` §5.2 and §6). Please report anything that breaks a stated guarantee, for example:

- A `tools/call` that a policy denies but that reaches the wrapped server.
- A policy that loads but doesn't enforce something it declares.
- A decision that is forwarded without first being recorded in the flight log.
- A redacted or omitted value that appears in the flight log.
- A way for one user to reach another user's writd socket.

These are **known limits** in this build, already documented, so they aren't vulnerabilities on their own:

- In cooperative mode, an agent with a shell or raw network access can bypass writ.
- `WRIT_TASK` is an unsigned ID: any process running as the same user can claim any task.
- The flight log's hash chain isn't externally anchored, so whoever can write the file can rewrite it.

## Supported versions

writ is pre-release. Only the latest commit on `main` is supported.
