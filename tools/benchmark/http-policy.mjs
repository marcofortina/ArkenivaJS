// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { pairedComparison, runOrder } from './http-analysis.mjs';

/** Keep a single sustained observation separate from repeated campaigns and soak. */
export function httpBenchmarkPolicy(policy, seed = 137) {
  assert.ok(
    ['campaign', 'smoke', 'soak', 'pilot'].includes(policy),
    'Unknown HTTP measurement policy',
  );
  const repeats = policy === 'campaign' ? 5 : 1;
  return Object.freeze({
    warmupSeconds: policy === 'smoke' ? 1 : 60,
    measuredSeconds: policy === 'smoke' ? 3 : policy === 'soak' ? 3600 : 180,
    repeats,
    order: policy === 'soak' ? [{ repeat: 1, mode: 'STANDARD' }] : runOrder(repeats, seed),
  });
}

/** A single pilot reports observed changes without an estimable confidence interval. */
export function compareHttpMetric(baseline, candidate, policy, seed = 137) {
  httpBenchmarkPolicy(policy, seed);
  if (policy === 'pilot')
    assert.equal(baseline.length, 1, 'A pilot contains one independent trial');
  const result = pairedComparison(baseline, candidate, seed);
  return policy === 'pilot'
    ? {
        ...result,
        confidence95Percent: null,
        calibrationStatus: 'NOT_CALIBRATED',
        interpretation:
          'Descriptive change from one sustained paired trial; no regression decision',
      }
    : result;
}

/** Capture CLI policy before allocating fixtures, workers or evidence directories. */
export function parseHttpBenchmarkArguments(args) {
  assert.ok(Array.isArray(args) && (args.length === 1 || args.length === 2));
  assert.ok(typeof args[0] === 'string' && args[0].length > 0, 'An evidence directory is required');
  if (args.length === 2)
    assert.ok(
      [
        '--smoke',
        '--soak',
        '--pilot',
        '--smoke-https',
        '--smoke-http2',
        '--smoke-http1-fallback',
      ].includes(args[1]),
    );
  if (args[1] === '--smoke-https')
    return { directory: args[0], policy: 'smoke', transport: 'https' };
  if (args[1] === '--smoke-http2')
    return { directory: args[0], policy: 'smoke', transport: 'http2' };
  if (args[1] === '--smoke-http1-fallback')
    return { directory: args[0], policy: 'smoke', transport: 'http1-fallback' };
  return { directory: args[0], policy: args[1]?.slice(2) ?? 'campaign' };
}
