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

## SignalLab boundaries

SignalLab is an educational research tool, not financial advice, a brokerage,
or a promise of future performance. It produces a probabilistic opinion about
relative performance over a stated horizon, not an instruction to buy or sell.
Do not rely on it alone for an investment decision. Automated output can be
wrong because of bad or stale data, model error, market regime changes, and
factors outside the recorded features.

The local API reads market-data CSV files only beneath the configured workspace.
Inputs are bounded and strictly validated. Model artifacts are versioned JSON
and never executable pickle or joblib files. The project does not fetch market
data, store brokerage credentials, place trades, assess suitability, or account
for a person's objectives, finances, tax position, or risk tolerance.

Strict JSON prevents executable deserialization; it does not authenticate a
model artifact or prove that its weights and reported metrics were produced from
the claimed data digest. Use CLI artifacts only when you trained or independently
reviewed them. Third-party artifact trust would require signatures and a trusted
key-distribution process.

See the SEC's Investor.gov guidance on
[artificial intelligence and investment fraud](https://www.investor.gov/introduction-investing/general-resources/news-alerts/alerts-bulletins/investor-alerts/artificial-intelligence-fraud)
and the limitations of
[automated investment tools](https://www.investor.gov/introduction-investing/general-resources/news-alerts/alerts-bulletins/investor-alerts/investor-56).
