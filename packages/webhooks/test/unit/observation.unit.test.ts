// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { setImmediate } from 'node:timers/promises';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import type { ManagedTelemetry } from '@arkenivajs/telemetry';
import { WEBHOOKS_CAPABILITY, webhooksPlugin } from '../../dist/index.js';
import type { WebhookService } from '../../dist/index.js';
import { fixture, fixtureSettings } from './fixture.js';

test(
  'Actual SDK diagnostics observe native localhost delivery and verification failure without webhook contents',
  { timeout: 15000 },
  async () => {
    const exports: string[] = [],
      received: Buffer[] = [];
    const collector = createServer((request, response) => {
      void (async () => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          assert.ok(bytes <= 1048576);
          chunks.push(chunk);
        }
        exports.push(Buffer.concat(chunks).toString());
        response.writeHead(200, { 'content-type': 'application/json' }).end('{}');
      })().catch(() => response.writeHead(500).end('{}'));
    });
    const accept = () =>
        createServer((request, response) => {
          void (async () => {
            const chunks: Buffer[] = [];
            let bytes = 0;
            for await (const chunk of request) {
              bytes += chunk.length;
              assert.ok(bytes <= 65536);
              chunks.push(chunk);
            }
            received.push(Buffer.concat(chunks));
            response.writeHead(204).end();
          })().catch(() => response.writeHead(500).end());
        }),
      ipv4 = accept(),
      ipv6 = accept();
    let f: Awaited<ReturnType<typeof fixture>> | undefined;
    try {
      await new Promise<void>((done) => collector.listen(0, '127.0.0.1', done));
      await new Promise<void>((done) => ipv4.listen(0, '127.0.0.1', done));
      const address = collector.address(),
        receiver = ipv4.address();
      assert.ok(address && typeof address === 'object');
      assert.ok(receiver && typeof receiver === 'object');
      await new Promise<void>((done, reject) => {
        ipv6.once('error', reject);
        ipv6.listen(receiver.port, '::1', done);
      });
      f = await fixture(
        fixtureSettings('http://localhost:' + receiver.port),
        'http://127.0.0.1:' + address.port,
      );
      const raw = Buffer.from('private-webhook-body'),
        context = f.context(),
        signature = await f.asTenant('tenant-a', () => f!.service.sign(raw, 'current', context));
      await f.asTenant('tenant-a', () => f!.service.verify(raw, signature, context));
      await assert.rejects(
        f.asTenant('tenant-a', () => f!.service.verify(Buffer.from('changed'), signature, context)),
        { code: 'EK_WEBHOOK_SIGNATURE' },
      );
      const delivery = await f.asTenant('tenant-a', () =>
        f!.service.send('receiver', {
          id: 'private-event-id',
          type: 'private-event-type',
          payload: { value: 'private-event-value' },
        }),
      );
      assert.equal(delivery.status, 'accepted');
      assert.equal(delivery.attemptCount, 1);
      assert.equal(received.length, 1);
      assert.equal(JSON.parse(received[0]!.toString()).id, 'private-event-id');
      await f.app.telemetry.flush();
      const output = exports.join('');
      for (const name of [
        'webhook.duration.ms',
        'webhook.payload.bytes',
        'webhook.delivery.attempts',
        'webhook.verification.failures',
      ])
        assert.ok(output.includes(name), name);
      for (const value of [
        'private-webhook-body',
        'private-event-id',
        'private-event-type',
        'private-event-value',
        signature.signature,
        context.nonce,
        'tenant-a',
        f.keys.get('current')!.bytes.toString('hex'),
      ])
        assert.equal((output + f.logs.join('')).includes(value), false);
      const quality = (f.app.telemetry as ManagedTelemetry).stats();
      for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'] as const)
        assert.equal(quality[key], 0);
    } finally {
      try {
        await f?.close();
      } finally {
        for (const server of [ipv4, ipv6, collector]) {
          server.closeAllConnections();
          if (server.listening) await new Promise<void>((done) => server.close(() => done()));
        }
      }
    }
  },
);

test('Throwing and asynchronously rejecting webhook diagnostics cannot change cryptographic work or repeat claims', async () => {
  const base = fixtureSettings();
  let observations = 0;
  const telemetry: Telemetry = {
    async measure(_name, work) {
      return work();
    },
    async withSpan(_name, work) {
      return work();
    },
    addCounter() {
      observations++;
      throw new Error('Private diagnostic failure');
    },
    async recordHistogram() {
      observations++;
      throw new Error('Private async diagnostic failure');
    },
    setGauge() {
      throw new Error('Unexpected gauge');
    },
    async flush() {},
  };
  const observer: Plugin = {
    id: 'owned-faulting-telemetry',
    version: '1.0.0',
    capabilities: new Set(['telemetry']),
    init(context) {
      context.provide(COMPONENTS.telemetry, telemetry);
    },
    close() {},
  };
  const app = await createApplication({
    service: { name: 'webhook-observer-fault', version: '1.0.0', environment: 'test' },
    plugins: [observer, webhooksPlugin(base.settings)],
  });
  try {
    await app.start();
    const service = app.resolve<WebhookService>(WEBHOOKS_CAPABILITY),
      ctx = base.context(),
      raw = Buffer.from('owned');
    const signature = await base.asTenant('tenant-a', () => service.sign(raw, 'current', ctx));
    assert.equal(
      (await base.asTenant('tenant-a', () => service.verify(raw, signature, ctx))).eventId,
      ctx.eventId,
    );
    await assert.rejects(
      base.asTenant('tenant-a', () => service.verify(Buffer.from('changed'), signature, ctx)),
      { code: 'EK_WEBHOOK_SIGNATURE' },
    );
    await setImmediate();
    assert.equal(base.state.claimCalls, 1);
    assert.equal(base.state.secretCalls, 3);
    assert.ok(observations > 0);
  } finally {
    await app.stop();
    for (const key of base.keys.values()) key.bytes.fill(0);
  }
});
