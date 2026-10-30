// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer, request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, body, send, boundary } from './fixture.js';
import type { ManagedTelemetry } from '@arkenivajs/telemetry';

interface Point {
  asDouble?: number;
  asInt?: string;
  attributes?: { key: string; value: { stringValue?: string } }[];
}
interface Metric {
  name: string;
  unit: string;
  sum?: { dataPoints: Point[] };
}
interface Payload {
  resourceMetrics?: { scopeMetrics?: { metrics?: Metric[] }[] }[];
}
async function until(check: () => boolean) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (check()) return;
    await delay(10);
  }
  assert.ok(check(), 'The owned upload did not settle');
}
test(
  'Real upload exports count completed requests, parts and aborted streams once without private metadata',
  { timeout: 15000 },
  async () => {
    const records = new Map<string, Metric>(),
      exports: string[] = [];
    const collector = createServer((incoming, response) => {
      void (async () => {
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of incoming) {
          size += chunk.length;
          assert.ok(size <= 1048576);
          chunks.push(chunk);
        }
        const encoded = Buffer.concat(chunks).toString();
        exports.push(encoded);
        const payload = JSON.parse(encoded) as Payload;
        for (const resource of payload.resourceMetrics ?? [])
          for (const scope of resource.scopeMetrics ?? [])
            for (const metric of scope.metrics ?? []) records.set(metric.name, metric);
        response.writeHead(200, { 'content-type': 'application/json' }).end('{}');
      })().catch(() => response.writeHead(500).end('{}'));
    });
    let owned: Awaited<ReturnType<typeof fixture>> | undefined;
    try {
      await new Promise<void>((done) => collector.listen(0, '127.0.0.1', done));
      const address = collector.address();
      assert.ok(address && typeof address === 'object');
      let chunksReceived = 0;
      owned = await fixture(
        {
          async handler(upload) {
            let files = 0,
              bytes = 0;
            for await (const part of upload.parts)
              if (part.kind === 'file') {
                files++;
                for await (const chunk of part.stream) {
                  bytes += chunk.byteLength;
                  chunksReceived++;
                }
              }
            return { files, bytes, order: [] };
          },
        },
        5000,
        undefined,
        'http://127.0.0.1:' + address.port,
      );
      const token = await owned.token(),
        privateValues = [
          'private-upload-field',
          'private-upload-value',
          'private-upload.bin',
          'private-upload-content',
        ],
        file = {
          name: 'file',
          filename: privateValues[2]!,
          type: 'application/octet-stream',
          value: privateValues[3]!,
        };
      const success = await send(
        owned.origin,
        body([{ name: privateValues[0]!, value: privateValues[1]! }, file]),
        token,
      );
      assert.equal(success.status, 200);
      assert.equal(
        (await send(owned.origin, body([{ ...file, type: 'image/svg+xml' }]), token)).status,
        415,
      );
      const pending = request(owned.origin + '/uploads', {
        method: 'POST',
        headers: {
          authorization: token,
          'content-type': 'multipart/form-data; boundary=' + boundary,
        },
      });
      pending.on('error', () => undefined);
      try {
        pending.write(body([{ ...file, value: Buffer.alloc(32768, 0x71) }], false));
        await until(() => owned!.calls() === 3 && chunksReceived >= 2);
        pending.destroy();
        await until(
          () => owned!.stats().activeRequests === 0 && owned!.stats().rejectedRequests === 2,
        );
      } finally {
        pending.destroy();
      }
      await owned.app.telemetry.flush();
      const quality = (owned.app.telemetry as ManagedTelemetry).stats();
      for (const key of ['droppedSpans', 'droppedMetrics', 'exportFailures'] as const)
        assert.equal(quality[key], 0);
      const counter = (name: string, outcome?: string) => {
        const metric = records.get(name);
        assert.ok(metric, name);
        assert.ok(metric.sum, name);
        return metric.sum.dataPoints
          .filter(
            (point) =>
              !outcome ||
              point.attributes?.some(
                (attribute) =>
                  attribute.key === 'upload.outcome' && attribute.value.stringValue === outcome,
              ),
          )
          .reduce((sum, point) => sum + Number(point.asDouble ?? point.asInt), 0);
      };
      assert.equal(counter('upload.requests'), 3);
      assert.equal(counter('upload.requests', 'ok'), 1);
      assert.equal(counter('upload.requests', 'error'), 2);
      assert.equal(counter('upload.parts'), 4);
      assert.equal(counter('upload.files'), 2);
      assert.equal(counter('upload.aborted.requests'), 1);
      assert.equal(counter('upload.request.bytes'), owned.stats().observedBytes);
      assert.equal(records.get('upload.parts')?.unit, '{part}');
      const emitted = exports.join('') + owned.logs();
      for (const value of [...privateValues, token, token.slice('Bearer '.length)])
        assert.equal(emitted.includes(value), false);
    } finally {
      try {
        await owned?.close();
      } finally {
        collector.closeAllConnections();
        await new Promise<void>((done) => collector.close(() => done()));
      }
    }
  },
);
