// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createIssuer } from './http-issuer.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete realtime resource sampling remains separate',
);
const issuer = await createIssuer();
try {
  const token = await issuer.token(),
    parts = token.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  const fixture = {
    issuer: issuer.origin,
    audience: issuer.audience,
    token,
    invalidToken: parts.join('.'),
    foreignTenantToken: await issuer.token({ claims: { tenant_id: 'foreign-tenant' } }),
    tenant: 'synthetic-tenant',
  };
  await runPureComparison(
    {
      scenarioId: 'realtime-native-authenticated-websocket-and-sse-verification',
      fixture,
      privacyValues: [
        ...Object.values(fixture),
        'owned_realtime_message',
        'Unicode: π 😀',
        '127.0.0.1',
        'localhost',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./realtime-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@fastify/websocket@11.3.4, @fastify/sse@0.6.1, jose@6.2.13',
        sseEvents: 3,
        samplingSupported: false,
      },
      observationCoverage:
        'Actual signed-JWT admission precedes native/public WebSocket and SSE traffic. Exact Unicode/multiline/empty SSE frames, owned cursor resume, invalid/expired/foreign cursor rejection, denied anonymous/tampered-token requests and a binary WebSocket envelope are verified. Parent independently observes four real JWKS fetches. Actual SDK exports exclude identities, tokens and event data.',
      limitations:
        'Loopback-only test issuer/listeners, no production TLS claim. Fixed synthetic durable-source corpus, no actual durable event store or cross-pod broker. Native reference omits runtime identity provenance, connection quotas, backpressure, cancellation and stream quarantine policy. No complete independent-client/server resource accounting, full performance campaign or release acceptance.',
    },
    args,
  );
  const observed = issuer.observations();
  assert.equal(observed.jwks, 4);
  assert.equal(observed.unknown, 0);
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ actualJwksRequests: observed.jwks, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await issuer.close();
}
