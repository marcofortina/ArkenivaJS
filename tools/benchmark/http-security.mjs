// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';

const marker = 'owned-header-response-value';
await runPureComparison({
  scenarioId: 'http-security-headers-comparison',
  fixture: { marker },
  privacyValues: [marker],
  privacyField: 'inputOccurrences',
  worker: new URL('./http-security-worker.mjs', import.meta.url),
  inputs: {
    operations: ['headers'],
    nativeBackend: 'Fastify and native Helmet onSend',
    responsesPerProfile: 3,
    samplesPerOperation: 100,
    warmupIterations: 20,
    concurrency: 1,
  },
  observationCoverage:
    'Actual loopback HTTP success,404 and500 responses retain CSP,HSTS,nosniff and referrer policy; real SDK exports exclude response contents.',
  limitations:
    'Header-only comparison with CSRF disabled; test-only CSRF dependencies reject every storage and authorization call. No CSRF, durable-store, TLS handshake or distributed-policy performance claim. Native baseline omits framework routing validation, lifecycle, logging and request context. Whole child resources include the local client and server. No dedicated-runner budget, release acceptance, five repetitions or one-hour soak claim.',
});
