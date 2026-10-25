// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';

/** Seeded randomization makes run order and confidence intervals reproducible. */
export function randomSource(seed) {
  assert.ok(Number.isSafeInteger(seed) && seed > 0 && seed <= 0xffffffff);
  let state = seed;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };
}
export function quantile(values, probability) {
  assert.ok(values.length && values.every(Number.isFinite));
  assert.ok(probability >= 0 && probability <= 1);
  const sorted = [...values].sort((a, b) => a - b);
  const index = (sorted.length - 1) * probability;
  return (
    sorted[Math.floor(index)] + (sorted[Math.ceil(index)] - sorted[Math.floor(index)]) * (index % 1)
  );
}
/** Resample whole paired repetitions, never individual requests as independent experiments. */
export function pairedComparison(baseline, candidate, seed = 137) {
  assert.equal(baseline.length, candidate.length);
  assert.ok(baseline.length && baseline.every((value) => Number.isFinite(value) && value > 0));
  assert.ok(candidate.every((value) => Number.isFinite(value) && value >= 0));
  const ratios = candidate.map((value, index) => 100 * (value / baseline[index] - 1));
  const mean = (values) => values.reduce((sum, value) => sum + value, 0) / values.length;
  const random = randomSource(seed),
    draws = [];
  for (let draw = 0; draw < 10000; draw++) {
    let sum = 0;
    for (let index = 0; index < ratios.length; index++)
      sum += ratios[Math.floor(random() * ratios.length)];
    draws.push(sum / ratios.length);
  }
  return {
    pairedRepeats: ratios.length,
    meanChangePercent: mean(ratios),
    confidence95Percent: [quantile(draws, 0.025), quantile(draws, 0.975)],
    minChangePercent: Math.min(...ratios),
    maxChangePercent: Math.max(...ratios),
    coefficientOfVariationBaseline:
      baseline.length > 1
        ? Math.sqrt(
            baseline.reduce((sum, value) => sum + (value - mean(baseline)) ** 2, 0) /
              (baseline.length - 1),
          ) / mean(baseline)
        : null,
    sufficientlyRepeated: ratios.length >= 5,
    releaseGate: false,
  };
}
/** A deterministic shuffle balances mode order without conflating separate repetitions. */
export function runOrder(repeats, seed) {
  assert.ok(Number.isInteger(repeats) && repeats >= 1 && repeats <= 20);
  const random = randomSource(seed),
    result = [];
  for (let repeat = 1; repeat <= repeats; repeat++) {
    const modes = ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'];
    for (let index = modes.length - 1; index > 0; index--) {
      const other = Math.floor(random() * (index + 1));
      [modes[index], modes[other]] = [modes[other], modes[index]];
    }
    result.push(...modes.map((mode) => ({ repeat, mode })));
  }
  return result;
}
