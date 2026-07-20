# SignalLab model card

SignalLab is a transparent machine-learning research pipeline for studying one
question:

> Given information available at the end of a trading session, what is the
> calibrated probability that a stock's adjusted-close return will exceed its
> benchmark's adjusted-close return over the next _N_ trading sessions?

The default benchmark is `SPY` and the default horizon is 20 sessions. The
output is a **Bullish**, **Neutral**, or **Bearish** research opinion, not a
price target or an instruction to buy or sell. Each result includes the
probability, benchmark, horizon, as-of date, factor evidence, held-out test
metrics, known limitations, and a research-only disclaimer.

## Model design

SignalLab implements its training and inference code with the Python standard
library so the statistical logic is inspectable:

1. A regularized logistic regression learns a smooth linear relationship
   between standardized features and the outperform label.
2. A small gradient-boosted ensemble of decision stumps learns bounded,
   additive nonlinear thresholds through residual fitting.
3. The validation period selects their blend and fits a slope/intercept
   probability calibration.
4. The final chronological test period is evaluated once and is not used to fit
   preprocessing, either base model, the blend, or calibration. Its metrics act
   as a deployment-style quality gate: a model that does not beat basic holdout
   checks cannot present a directional opinion with elevated evidence strength.

This is intentionally a compact research baseline. A larger model is not
automatically a better financial model; trustworthy evaluation and leakage
control matter more than parameter count.

## Target and point-in-time features

For a stock `S`, benchmark `B`, date `t`, and horizon `h`, the binary target is:

```text
1 when return(S, t → t+h) - return(B, t → t+h) > 0
0 otherwise
```

Features use observations at or before `t` only:

- 5-, 20-, and 60-session stock momentum
- 20-session annualized volatility
- distance from 20- and 60-session simple moving averages
- 14-session relative strength index, scaled to 0–1
- current volume relative to its prior 20-session average
- 60-session drawdown from the rolling high
- 20- and 60-session benchmark momentum
- 20- and 60-session stock-minus-benchmark relative momentum
- 60-session beta to the benchmark

SignalLab prefers `adjusted_close` so splits and distributions do not appear as
economic returns. If the optional column is absent, it falls back to `close` and
calls out that limitation in the opinion.

## Leakage controls

Rows are ordered by date and split into approximately 60% training, 20%
validation, and 20% test periods. A row immediately before a boundary is removed
when its forward label ends inside the next period. Therefore:

```text
last training label endpoint < first validation feature date
last validation label endpoint < first test feature date
```

Feature means and scales are calculated from training rows only. Model weights
and decision stumps use training rows only. Ensemble choice and calibration use
validation rows only. Test labels are used for final metrics and the conservative
presentation gate, never to change the predicted probability or fitted
parameters. The JSON artifact records every boundary and the number of purged
rows so this can be audited.

These controls prevent leakage inside SignalLab. They cannot repair upstream
data that was itself created with future knowledge, survivorship bias, or
incorrect historical adjustments.

## Evaluation evidence

The artifact and every dashboard opinion expose:

- **Accuracy:** share of correct classifications at probability 0.5.
- **Balanced accuracy:** average of sensitivity and specificity, which gives
  both classes equal weight.
- **Brier score:** mean squared probability error; lower is better.
- **ROC AUC:** ranking quality across thresholds; 0.5 is random ordering.
- **Base rate:** share of test rows that actually outperformed.
- **Constant Brier:** error from always predicting the training-period base rate.

A model result is not validated merely because one metric exceeds 0.5. Compare
its Brier score with the constant baseline, inspect the test dates and sample
count, and repeat the experiment across regimes and universes. SignalLab reports
evidence; it does not hide a weak holdout result.

Forward labels overlap: with a 20-session horizon, adjacent daily labels share
most of their future price path. SignalLab therefore reports both raw labeled
rows and **effective windows**, conservatively defined as
`floor(distinct test dates / horizon)`. Effective windows do not make the
remaining blocks perfectly independent, especially across stocks exposed to the
same market regime, but they prevent raw row counts from being presented as
independent evidence.

## Opinion and evidence-strength rules

The API field is named `confidence` for schema stability, but the dashboard calls
it **heuristic evidence strength**. It is not a statistical confidence level,
confidence interval, or probability that the complete opinion is correct.

A directional opinion is allowed only when the held-out test has at least 100
labeled rows and 5 effective windows, ROC AUC of at least 0.53, balanced accuracy
of at least 0.52, and Brier score at least 0.002 better than the constant
baseline. It then labels probabilities at least 0.58 Bullish, at most 0.42
Bearish, and the middle Neutral. When any gate fails, the opinion is forced to
Neutral with Low evidence strength while the raw probability remains visible.

For a passing model, SignalLab calculates a heuristic score:

```text
0.7 × (2 × |probability - 0.5|) + 0.3 × clamp(2 × (test AUC - 0.5), 0, 1)
```

Scores below 0.28 are Low and scores from 0.28 are Moderate. High additionally
requires a score of at least 0.60, at least 200 labeled test rows, 20 effective
windows, ROC AUC of at least 0.60, balanced accuracy of at least 0.55, and Brier
improvement of at least 0.01. High is available only when the model fitted one
non-benchmark stock, because pooled multi-stock metrics are not symbol-specific;
multi-stock evidence strength is capped at Moderate.

## Input data contract

Input is one UTF-8, long-format CSV with one row per date and symbol:

```csv
date,symbol,open,high,low,close,volume,adjusted_close
2024-01-02,ACME,101.2,103.0,100.8,102.4,1250000,102.4
2024-01-02,SPY,472.1,473.7,470.5,472.6,84200000,472.6
```

Required columns are `date`, `symbol`, `open`, `high`, `low`, `close`, and
`volume`; `adjusted_close` is optional. Dates must be exact `YYYY-MM-DD` values,
symbols must already be uppercase, prices must be positive, volume must be
non-negative, and OHLC relationships must be valid. Duplicate date/symbol rows,
unknown columns, missing cells, non-finite numbers, oversized input, and
insufficient histories fail closed.

SignalLab does not download or license market data. That keeps credentials and
provider-specific assumptions outside the model boundary. Export daily data
from a provider you are permitted to use, normalize it to this contract, and
retain its provenance. The optional synthetic generator exists only to exercise
the full pipeline; it uses the unmistakably artificial identifiers `SYNTH_MKT`,
`SYNTH_A`, and `SYNTH_B`, is visibly labeled, and supports no real-market claim.

## Safe, reproducible artifacts

Model artifacts are strict JSON—not pickle, joblib, or another executable
format. They contain:

- schema, artifact, and feature versions;
- SHA-256 of the exact training CSV;
- benchmark, horizon, seed, symbols, and training cutoff;
- feature names and training-only standardization values;
- logistic and boosted-stump parameters;
- validation-selected blend and calibration parameters;
- purged chronological split metadata; and
- validation, test, and constant-baseline metrics.

Loading rejects incompatible versions, unexpected or missing fields, invalid
dimensions, non-finite values, unsafe sizes, and out-of-range parameters.
Artifacts are not signed or authenticated: strict JSON prevents executable
deserialization but cannot prove that claimed metrics or weights came from the
claimed CSV. Reuse only artifacts you trained or independently reviewed. A
signature and trusted key-distribution process would be required to trust an
artifact received from someone else.

## How to improve it responsibly

Treat each change as a new experiment rather than tuning until one test period
looks good:

1. Write down the hypothesis and metric before viewing new holdout results.
2. Add features that can be reconstructed point in time and document their data
   availability lag.
3. Tune only on training/validation data or nested walk-forward folds.
4. Preserve a genuinely untouched final period and compare probability error
   with a constant baseline.
5. Test across multiple market regimes, sectors, symbols, and benchmark choices.
6. Measure calibration and subgroup stability, not just direction accuracy.
7. Include fees, slippage, liquidity, delistings, and survivorship-free data
   before making any separate strategy or backtest claim.
8. Version the feature contract and retain data/model digests so results remain
   reproducible.

## Limitations and intended use

SignalLab uses historical daily price/volume behavior only. It does not include
fundamentals, valuation, news, macroeconomics, events, options, intraday data,
liquidity constraints, costs, taxes, portfolio interactions, or a person's
objectives and risk tolerance. Markets change, correlations break, probabilities
can be poorly calibrated, and losses—including total loss—are possible.

Do not rely solely on an AI-generated output for an investment decision. The
SEC's Investor.gov materials likewise warn that AI output can be inaccurate,
incomplete, misleading, or outdated and that automated tools may not account for
an investor's complete circumstances: [AI and investment fraud alert](https://www.investor.gov/introduction-investing/general-resources/news-alerts/alerts-bulletins/investor-alerts/artificial-intelligence-fraud),
[automated investment tools alert](https://www.investor.gov/introduction-investing/general-resources/news-alerts/alerts-bulletins/investor-alerts/investor-56).

SignalLab is suitable for ML education, reproducible experimentation, model-risk
discussion, and portfolio demonstration. It is not suitable for autonomous
trading, personalized advice, or claims of expected profit.
