// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
assert.ok(
  args[0] !== '--smoke' || process.env.ARKENIVA_UPLOAD_BENCHMARK_DISPOSABLE === '1',
  'Upload smoke requires an explicitly disposable measurement environment',
);
const fixture = {
  marker: 'owned-upload-content-π',
  note: 'owned-upload-field-€',
  sampleMultipart: args[0] === '--smoke',
};
await runPureComparison(
  {
    scenarioId: 'upload-streaming-protocol-verification',
    fixture,
    privacyValues: [fixture.marker, fixture.note, 'owned.bin', 'empty.bin', '127.0.0.1'],
    privacyField: 'inputOccurrences',
    worker: new URL('./upload-worker.mjs', import.meta.url),
    superviseProcessTree: true,
    inputs: {
      nativeBackend: 'Fastify and native multipart streaming parser',
      requestsPerProfile: args[0] === '--smoke' ? 122 : 2,
      verificationRequestsPerProfile: 2,
      filesPerRequest: 2,
      sourceChunkBytesMaximum: 8192,
      sourceHighWaterMarkBytes: 16384,
      clientHighWaterMarkBytes: 4096,
      sinkHighWaterMarkBytes: 4096,
      concurrency: 1,
      samplingSupported: true,
      sampledRequestsPerProfile: args[0] === '--smoke' ? 100 : 0,
      warmupRequestsPerProfile: args[0] === '--smoke' ? 20 : 0,
      measuredScenario:
        'Ordered field, streamed file and empty file with a cooperative SHA256 sink',
    },
    observationCoverage:
      'Actual chunked HTTP multipart, single-pass fragmented UTF8 input, exact field/file order, empty file and independently consumed SHA256/byte counts. Optional bounded smoke retains latency, first-file/response byte, physical source/HTTP/sink completion, actual write/drain waits and observed application-owned queue maxima. Framework HTTP body counters reconcile actual source bytes. Actual SDK exports exclude payload and fields.',
    limitations:
      'Small fixed single-request closed-loop corpus and deliberately cooperative application sink. Explicitly public owned route; no authentication, storage or durability performance claim. Baseline delegates to the same parser and limits but omits framework HTTP-body, metadata, admission and lifecycle policy; native body observation unavailable. Client/source/sink queue maxima are observed user-space values, not opaque parser/kernel buffers or total peak memory. No large-file heap, calibrated policy-equivalent overhead, dedicated-runner budget, five repeated campaigns, one-hour soak or release acceptance. STANDARD/DETAILED force diagnostic samplingRatio1; no normal production sampling budget claim.',
  },
  args,
);
