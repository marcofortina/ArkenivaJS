// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIssuer } from '../http-issuer.mjs';
import { startWorker } from '../http-worker.mjs';

test('All four HTTP modes enforce signed identity and execute the same live TLS PostgreSQL work', async () => {
  assert.equal(
    process.env.ARKENIVA_POSTGRES_DISPOSABLE,
    '1',
    'A disposable PostgreSQL fixture is required',
  );
  assert.ok(process.env.ARKENIVAJS_OTLP_ENDPOINT, 'A real disposable OTel collector is required');
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-http-equivalence-'));
  const issuer = await createIssuer();
  const token = await issuer.token();
  try {
    for (const mode of ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED']) {
      const location = join(directory, mode);
      await mkdir(location, { mode: 0o700 });
      const worker = await startWorker({
        mode,
        directory: location,
        issuer: issuer.origin,
        audience: issuer.audience,
        otlpEndpoint: process.env.ARKENIVAJS_OTLP_ENDPOINT,
      });
      const request = async (path, bearer, headers = {}) => {
        const reply = await globalThis.fetch(worker.address + path, {
          headers: { ...headers, ...(bearer ? { authorization: 'Bearer ' + bearer } : {}) },
          signal: AbortSignal.timeout(10000),
        });
        return { status: reply.status, body: Buffer.from(await reply.arrayBuffer()) };
      };
      try {
        await worker.begin();
        for (const path of ['/json', '/authenticated', '/database']) {
          const reply = await request(path, token, { 'x-tenant-id': 'forged-tenant' });
          assert.equal(reply.status, 200, mode + path);
          assert.equal(reply.body.byteLength, 128);
          assert.deepEqual(JSON.parse(reply.body), { ok: true, value: 7, padding: 'x'.repeat(94) });
        }
        for (const path of ['/authenticated', '/database']) {
          assert.equal((await request(path)).status, 401);
          assert.equal((await request(path, 'invalid')).status, 401);
          assert.equal(
            (await request(path, await issuer.token({ audience: 'api://wrong' }))).status,
            401,
          );
          assert.equal(
            (await request(path, await issuer.token({ expiration: '1m ago' }))).status,
            401,
          );
          assert.equal(
            (await request(path, await issuer.token({ claims: { scope: 'orders:write' } }))).status,
            403,
          );
        }
        const result = await worker.finish();
        assert.equal(result.counts.completed, 13);
        assert.equal(result.counts.failed, 10);
        assert.equal(result.counts.active, 0);
        assert.ok(result.cpuDeltaMicros.user > 0);
        assert.ok(result.rssBytes.max > 0);
        assert.equal(result.gc.discardedObservations, 0);
        if (result.api) assert.equal(result.api.observerFailures, 0);
        assert.equal(result.meter === null, ['BASELINE', 'FRAMEWORK'].includes(mode));
        if (result.afterFlush.meter) {
          assert.equal(result.afterFlush.meter.enqueued, result.afterFlush.meter.exported);
          assert.equal(result.afterFlush.meter.dropped, 0);
          assert.equal(result.afterFlush.meter.failedExports, 0);
          assert.equal(result.afterFlush.telemetry.spansStarted, 14);
          assert.equal(result.afterFlush.telemetry.spansEnded, 14);
        }
      } finally {
        await worker.close();
        await worker.close();
      }
      const logs = await readFile(join(location, 'application.jsonl'), 'utf8');
      assert.ok(logs.length > 0);
      assert.ok(!logs.includes(token));
      if (['STANDARD', 'DETAILED'].includes(mode)) {
        const events = (await readFile(join(location, 'metering.jsonl'), 'utf8'))
          .trim()
          .split('\n')
          .map(JSON.parse);
        assert.equal(events.length, 2);
        assert.ok(!JSON.stringify(events).includes('forged-tenant'));
      }
    }
  } finally {
    await issuer.close();
    await rm(directory, { recursive: true, force: true });
  }
});
