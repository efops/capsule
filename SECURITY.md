# Security Policy

capsule is a security tool: it decides what may run on a host, and confines it. Reports of ways around those decisions are taken seriously and are welcome.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Fixes go into the latest release. Until 1.0 there are no back-ports to older minor versions.

## Reporting a vulnerability

**Do not open a public issue or discussion for a security problem.**

Report it privately: on the repository's **Security** tab, choose **Report a vulnerability**. Only the maintainers can see the report.

Please include:

- the capsule version (`capsule version`), kernel version and distribution
- whether capsule ran as root, without root, or without root with the helper
- what you expected to be prevented, and what happened instead
- the steps, manifest or commands that reproduce it

A working proof of concept helps, but a clear description is enough to start.

## What to expect

- **Acknowledgement** within 3 working days.
- **An assessment** within 10 working days: whether it is accepted, how severe it is, and what the plan is.
- **Updates** at least every two weeks until it is resolved.
- **If accepted:** a fix in a new release, and a published advisory that credits you unless you would rather not be named. Please keep the details private until the release is out; the aim is to do that within 90 days.
- **If declined:** an explanation of why, for example because it falls under the limits below. You are then free to discuss it publicly.

## What counts

In scope, for example:

- running a capsule that is not sealed by a trusted key, or whose policy (approvals, time lock, expiry, run limit, host list, revocation) should have refused it
- escaping the sandbox, or gaining capabilities, system calls or file access the manifest does not allow
- forging, altering, replaying or redirecting an order, a grant, a card, a receipt or a log entry
- reaching a mesh peer or cell receptor the manifest or a grant does not allow
- recovering an encrypted root filesystem, volume or order result without the key
- getting the helper to act outside its four requests, on another user's capsule, or on paths or images it did not make
- weaknesses in how the cryptography is used

Out of scope, because capsule says plainly that it does not defend against them (see "What it does not protect against" in the README):

- actions by root on the host, including reading a running capsule's memory
- a host clock set wrong, as far as `expires` is concerned
- a ledger operator deleting or delaying entries
- members of the `capsule` group using what the group is documented to grant: ports below 1024 and disk space
- vulnerabilities in the Linux kernel or in the software packaged inside a capsule
