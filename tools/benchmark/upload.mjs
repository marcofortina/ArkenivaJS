// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; streaming performance sampling remains separate',
);
const fixture = { marker: 'owned-upload-content-π', note: 'owned-upload-field-€' };
await runPureComparison(
  {
    scenarioId: 'upload-streaming-protocol-verification',
    fixture,
    privacyValues: [...Object.values(fixture), 'owned.bin', 'empty.bin', '127.0.0.1'],
    privacyField: 'inputOccurrences',
    worker: new URL('./upload-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'Fastify and native multipart streaming parser',
      requestsPerProfile: 2,
      filesPerRequest: 2,
      sourceChunkBytesMaximum: 8192,
      concurrency: 1,
    },
    observationCoverage:
      'Actual chunked HTTP multipart, single-pass fragmented UTF8 input, exact field/file order, empty file and SHA256 of consumed file chunks; actual SDK exports exclude payload and fields.',
    limitations:
      'Functional valid-corpus verification only. Public owned test route; no authentication, shared storage or persistence performance claim. Baseline delegates to the same parser and limits but omits framework wire-byte, metadata, admission and lifecycle policy. No latency, first-byte, backpressure-duration, peak-buffer, large-file heap or throughput acceptance; sampling rejected. Five repetitions and one-hour soak remain separate.',
  },
  args,
);
