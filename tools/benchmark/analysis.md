# Repeatable benchmark comparisons

`http-analysis.mjs` contains pure analysis helpers for independently repeated
measurements. They do not generate traffic, access infrastructure or decide a
release outcome.

`runOrder(repeats, seed)` includes all four modes once per repetition and shuffles
their order with a seeded xorshift32 source. The seed must be a positive unsigned
32-bit integer, and repetitions are bounded to 1–20. Pair baseline and candidate
measurements by repetition before comparison, regardless of execution order.

`pairedComparison(baseline, candidate, seed?)` requires equal nonempty arrays,
positive finite baseline values and nonnegative finite candidate values. It
calculates relative change within each pair, then resamples whole pairs 10,000
times. The mean relative change and 2.5%/97.5% percentiles of bootstrap means
form a reproducible observation and 95% percentile confidence interval. This
method does not treat individual requests as independent experimental repeats.

Results include minimum/maximum paired change and the baseline sample
coefficient of variation. One baseline repeat has no estimable sample variance,
reported as `null`. Fewer than five repeats set `sufficientlyRepeated:false`.
Every comparison has `releaseGate:false`; confidence intervals alone cannot
approve an uncalibrated regression threshold or establish production capacity.

Run the deterministic checks with a supported Node runtime:

```sh
node --test tools/benchmark/test/http-analysis.unit.test.mjs
```

## Single sustained HTTP pilot

`http.mjs ABSOLUTE_EVIDENCE_DIRECTORY --pilot` selects one four-mode sustained
trial when the full repeated campaign is being deferred. Each independently
owned server has the existing 60-second warmup and 180-second measured phase,
with the same signed authentication, PostgreSQL workload, payload, fixed arrival
rate and resource collection as a campaign. Seeded order includes each mode
exactly once. Allow approximately 16 minutes plus setup and cleanup. This command
requires the same clean committed source, controlled disposable VM, pinned k6,
fixture metadata, database and collector prerequisites as a full campaign.

The pilot exports the same raw measurements and JSON/CSV observations, marked
`evidenceKind: single-sustained-pilot`, `calibrationStatus: NOT_CALIBRATED` and
`sufficientlyRepeated: false`. Relative changes are descriptive observations from
one paired trial. Its comparison confidence intervals and baseline variance are
`null`; a repeated-infrastructure variance or regression threshold cannot be
inferred from individual request samples. `releaseGate` remains `false`.

The explicit pilot does not run or replace the five-repeat campaign or the
one-hour soak. Existing default campaign, `--smoke` and `--soak` policies retain
their timing, repetitions and report semantics. A short smoke is suitable for
checking execution; it is not a sustained pilot or calibrated acceptance.
