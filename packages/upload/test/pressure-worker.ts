// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fixture, policy } from './unit/fixture.js';

assert.equal(process.env.ARKENIVA_UPLOAD_PRESSURE_DISPOSABLE, '1');
assert.ok(process.send, 'The pressure server requires an owned IPC parent');
const gib = 1024 ** 3;
let active = 0,
  peakActive = 0,
  aborted = 0;
const f = await fixture(
  {
    policy: { ...policy, maxRequestBytes: gib + 4096, maxFileBytes: gib, maxFiles: 1 },
    responseSchema: {
      type: 'object',
      required: ['bytes', 'digest', 'tenant'],
      additionalProperties: false,
      properties: {
        bytes: { type: 'integer' },
        digest: { type: 'string' },
        tenant: { type: 'string' },
      },
    },
    async handler(input) {
      active++;
      peakActive = Math.max(peakActive, active);
      input.context.signal.addEventListener(
        'abort',
        () => {
          aborted++;
        },
        { once: true },
      );
      try {
        const hash = createHash('sha256');
        let bytes = 0;
        for await (const part of input.parts) {
          assert.equal(part.kind, 'file');
          if (part.kind === 'file')
            for await (const chunk of part.stream) {
              bytes += chunk.byteLength;
              hash.update(chunk);
            }
        }
        return { bytes, digest: hash.digest('hex'), tenant: input.context.auth!.tenantId };
      } finally {
        active--;
      }
    },
  },
  90000,
);

const baseline = process.memoryUsage();
const peak = {
  heapUsed: baseline.heapUsed,
  rss: baseline.rss,
  arrayBuffers: baseline.arrayBuffers,
};
const sample = () => {
  const memory = process.memoryUsage();
  for (const key of ['heapUsed', 'rss', 'arrayBuffers'] as const)
    peak[key] = Math.max(peak[key], memory[key]);
};
const timer = setInterval(sample, 10);
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  clearInterval(timer);
  await f.close();
}
process.once('disconnect', () => {
  void close();
});
process.on('message', (message: { id: number; kind: string }) => {
  if (message.kind === 'stats') {
    sample();
    process.send!({
      id: message.id,
      stats: f.stats(),
      active,
      peakActive,
      aborted,
      baseline,
      peak,
    });
  } else if (message.kind === 'stop') {
    void close().then(() =>
      process.send!({ id: message.id, stopped: true }, () => process.disconnect!()),
    );
  }
});
process.send!({ kind: 'ready', origin: f.origin, authorization: await f.token() });
