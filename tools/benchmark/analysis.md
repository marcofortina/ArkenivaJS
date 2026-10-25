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
