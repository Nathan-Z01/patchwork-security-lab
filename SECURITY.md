# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could put users at
risk. Use GitHub's private vulnerability reporting feature for this repository
and include a minimal reproduction, affected version, and expected impact.

## Scanner boundaries

AI Security Checker performs defensive, passive analysis. Its URL scanner sends
bounded `GET` requests only, follows a limited number of same-origin links, and
rejects loopback, private, link-local, multicast, reserved, and otherwise
non-public network destinations. It does not attempt authentication bypass,
payload injection, exploitation, fuzzing, or destructive verification.

Automated findings are evidence for review, not proof that a target is safe or
unsafe. Obtain authorization before scanning systems you do not own.

FreshPatch executes untrusted repository code only through its constrained
container backend by default. Runner images must be digest-pinned, and task and
result artifacts record the isolation/resource policy. Local execution requires
an explicit unsafe flag, is labeled as unsafe in evidence, and should only be
used with code you trust.
