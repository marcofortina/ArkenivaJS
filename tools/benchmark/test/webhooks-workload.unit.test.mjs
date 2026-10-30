// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  webhookPorts,
  nativeWebhooks,
  verifyWebhooks,
  webhookWorkload,
  webhookObservations,
} from '../webhooks-workload.mjs';

test('Webhook comparison rejects foreign provider targets before accessing a secret or store', () => {
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://127.0.0.1:1/other',
  ])
    assert.throws(() => webhookPorts({ endpoint }));
});

test('Webhook entry rejects unsupported campaigns and unmarked sampling before fixture or evidence creation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-webhook-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_WEBHOOKS_BENCHMARK_DISPOSABLE;
  delete env.ARKENIVA_POSTGRES_DISPOSABLE;
  delete env.DATABASE_URL;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../webhooks.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full webhook campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Untimed webhook helper accounting preserves fresh paired calls and final replay denial without exposing receipts', async () => {
  const secret = randomBytes(32),
    claims = new Set();
  // This bounded in-memory unit fixture tests accounting only, never SQL durability or performance.
  const server = createServer((request, response) => {
    void (async () => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const { method, args } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      let result;
      if (method === 'secret') result = { encoded: secret.toString('base64url'), version: 'one' };
      else if (method === 'authorize')
        result = {
          issuer: 'unit-issuer',
          subject: 'unit-subject',
          tenant: { tenantId: 'unit-tenant' },
        };
      else {
        assert.equal(method, 'claimOnce');
        assert.equal(args[0], 'webhooks.nonces.v1');
        result = !claims.has(args[1]);
        claims.add(args[1]);
      }
      response
        .writeHead(200, { 'content-type': 'application/json' })
        .end(JSON.stringify({ result }));
    })().catch(() => response.writeHead(500).end('{}'));
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  try {
    const fixture = {
        endpoint: 'http://127.0.0.1:' + server.address().port + '/provider',
        bearer: 'unit-private-bearer',
        marker: 'unit-private-payload',
      },
      service = nativeWebhooks(fixture);
    assert.throws(() => webhookWorkload(service, fixture));
    await verifyWebhooks(service, fixture);
    const work = webhookWorkload(service, fixture)['sign-and-durable-verify'];
    assert.equal(await work(), true);
    const observed = await webhookObservations(service, { measure: false, records: [] });
    assert.deepEqual(observed, {
      actualPairedCallbacks: 1,
      successfulPairedVerifications: 1,
      finalReplayDenials: 1,
      expectedAcceptedClaims: 2,
      expectedClaimAttempts: 4,
      expectedAuthorizations: 8,
      expectedSecretReads: 8,
    });
    assert.equal(claims.size, 2);
    assert.doesNotMatch(JSON.stringify(observed), /unit-private|nonce|signature/);
    assert.deepEqual(await webhookObservations(service, { measure: false, records: [] }), observed);
    await assert.rejects(
      webhookObservations(service, {
        measure: true,
        records: [
          {
            operation: 'sign-and-durable-verify',
            sampleCount: 100,
            warmupIterations: 20,
            rawLatency: { unit: 'milliseconds', values: Array(100).fill(1) },
          },
        ],
      }),
    );
  } finally {
    server.closeAllConnections();
    await new Promise((done) => server.close(done));
    secret.fill(0);
  }
});
