// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import { native } from '../../dist/backend.js';
import { capture } from '../../dist/settings.js';
import { Call, Runtime } from '../../dist/runtime.js';
import type { NativeRequest } from '../../dist/backend-contracts.js';
import { fixture } from '../fixture.js';

test('SAML operation deadlines, cancellation and unexpected provider failures preserve sanitized cleanup', async (context) => {
  let releases = 0;
  const controller = new AbortController();
  const canceled = new Call(1000, [controller.signal], () => {
    releases++;
  });
  controller.abort();
  assert.throws(() => canceled.check(), { code: 'EK_ABORTED' });
  canceled.finish();
  canceled.finish();
  const expired = new Call(1000, [], () => {
    releases++;
  });
  const clock = context.mock.method(performance, 'now', () => expired.started + 1001);
  assert.throws(() => expired.check(), { code: 'EK_TIMEOUT' });
  clock.mock.restore();
  expired.finish();
  assert.equal(releases, 2);
  const active: number[] = [];
  const runtime = new Runtime(undefined, undefined, (count) => active.push(count));
  try {
    await assert.rejects(
      runtime.run(undefined, async () => {
        throw new Error('Private provider failure');
      }),
      { code: 'EK_BACKEND_UNAVAILABLE', message: 'The SAML provider is unavailable' },
    );
    await assert.rejects(
      runtime.run(undefined, (call) =>
        call.step('EK_SAML_ASSERTION', async () => {
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Private unexpected provider code',
          });
        }),
      ),
      { code: 'EK_SAML_ASSERTION', message: 'The SAML message could not be accepted' },
    );
  } finally {
    await runtime.close();
  }
  assert.equal(active.at(-1), 0);
});

test(
  'Malformed replies, native worker errors and premature exits cannot fabricate SAML acceptance',
  { timeout: 15000 },
  async (context) => {
    const f = await fixture();
    try {
      const settings = capture(f.settings);
      const input: NativeRequest = {
        action: 'metadata',
        requestId: '_' + randomBytes(20).toString('hex'),
        instant: new Date().toISOString(),
        relayState: '',
        configuration: {
          entityId: settings.entityId,
          acsUrl: settings.acsUrl,
          audience: settings.audience,
          issuer: settings.trusted.issuer,
          certificates: settings.trusted.certificates,
          loginUrl: settings.trusted.loginUrl,
          clockSkewSeconds: 0,
          binding: 'redirect',
        },
      };
      for (const mode of ['empty-result', 'error', 'exit']) {
        const emit = Worker.prototype.emit;
        const workers = new Set<Worker>();
        const intercepted = context.mock.method(
          Worker.prototype,
          'emit',
          function (this: Worker, event: string | symbol, ...args: unknown[]) {
            workers.add(this);
            if (event === 'online' && mode === 'error')
              Reflect.apply(emit, this, ['error', new Error('Private native worker diagnostic')]);
            if (event === 'online' && mode === 'exit') void this.terminate();
            if (event === 'message' && mode === 'empty-result')
              return Reflect.apply(emit, this, [event, { ok: true }]);
            return Reflect.apply(emit, this, [event, ...args]);
          },
        );
        try {
          await assert.rejects(native(input, new AbortController().signal), (error: unknown) => {
            assert.equal((error as { code: string }).code, 'EK_SAML_ASSERTION');
            assert.doesNotMatch(String(error), /Private native worker diagnostic/);
            return true;
          });
          assert.equal(workers.size, 1);
          assert.ok([...workers].every((worker) => worker.threadId === -1));
        } finally {
          intercepted.mock.restore();
          await Promise.all([...workers].map((worker) => worker.terminate()));
        }
      }
    } finally {
      await f.close();
    }
  },
);
