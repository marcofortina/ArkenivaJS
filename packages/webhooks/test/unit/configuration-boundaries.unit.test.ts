// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import { webhooksPlugin } from '../../dist/index.js';
import type { WebhooksPluginSettings } from '../../dist/index.js';
import { fixture, fixtureSettings } from './fixture.js';

test('Webhook destination and resource policies reject unsafe or unbounded deployment values before provider work', () => {
  const f = fixtureSettings(),
    base = f.settings,
    profile = base.destinations[0]!;
  try {
    const profiles = [
      { ...profile, name: 'Uppercase' },
      { ...profile, name: 'x'.repeat(65) },
      ...[
        'ftp://localhost',
        'https://user:private@localhost',
        'https://localhost/path',
        'https://localhost/?q=x',
        'https://localhost/#fragment',
      ].map((origin) => ({ ...profile, origin })),
      ...[
        '127.0.0.1',
        '127.0.0.1/01',
        '127.0.0.1/-1',
        'invalid/1',
        '::1/129',
        '127.0.0.1/32/extra',
        '192.0.2.1/32',
      ].map((cidr) => ({ ...profile, allowedCidrs: [cidr] })),
      { ...profile, idempotent: 'true' },
      { ...profile, maxRetries: 3, idempotent: true },
      { ...profile, timeoutMs: 120001 },
      { ...profile, verificationKeys: [{ keyId: 'one', hmacKeyRef: 'old', expiresAt: 'invalid' }] },
      {
        ...profile,
        verificationKeys: Array.from({ length: 2 }, () => ({
          keyId: 'one',
          hmacKeyRef: 'old',
          expiresAt: new Date(Date.now() + 60000).toISOString(),
        })),
      },
    ];
    for (const value of profiles)
      assert.throws(
        () => webhooksPlugin({ ...base, destinations: [value] } as WebhooksPluginSettings),
        { code: 'EK_CONFIG_INVALID' },
      );
    for (const change of [
      { destinations: [profile, profile] },
      { destinations: [] },
      { policy: { ...base.policy, maxConcurrent: 17 } },
      { policy: { ...base.policy, timeoutMs: 120001 } },
      { policy: { ...base.policy, maxInputBytes: 8388609 } },
      { policy: { ...base.policy, maxOutputBytes: 1048577 } },
      { nonceStore: { ...base.nonceStore, securityLevel: 'invalid' } },
      { nonceStore: { ...base.nonceStore, operationTimeoutMs: 120001 } },
      { secretProvider: { ...base.secretProvider, usage: 'invalid' } },
      { authority: { ...base.authority, usage: 'invalid' } },
    ])
      assert.throws(() => webhooksPlugin({ ...base, ...change } as WebhooksPluginSettings), {
        code: 'EK_CONFIG_INVALID',
      });
    const { maxInputBytes, maxOutputBytes, ...policy } = base.policy;
    void [maxInputBytes, maxOutputBytes];
    assert.ok(webhooksPlugin({ ...base, policy }));
    assert.ok(
      webhooksPlugin({
        ...base,
        destinations: [
          { ...profile, origin: 'https://[::1]', allowedCidrs: ['::1/128'], verificationKeys: [] },
        ],
      }),
    );
    assert.equal(f.state.secretCalls, 0);
    assert.equal(f.state.authorityCalls, 0);
    assert.equal(f.state.claimCalls, 0);
  } finally {
    for (const key of f.keys.values()) key.bytes.fill(0);
  }
});

test('Webhook JSON limits reject excessive depth, breadth, key bytes and executable or non-JSON values', async () => {
  const f = await fixture();
  try {
    let deep: unknown = null;
    for (let index = 0; index < 34; index++) deep = { nested: deep };
    const sparse = new Array(2);
    sparse[1] = 'owned';
    const payloads = [
      deep,
      Array.from({ length: 4097 }, () => null),
      sparse,
      { ['x'.repeat(65536)]: null },
      'x'.repeat(65536),
      { unpaired: '\ud800' },
      { undefined },
      { function: () => undefined },
      { number: NaN },
      { number: Infinity },
      { bigint: 1n },
      { symbol: Symbol('owned') },
      Object.create({ inherited: 'private' }),
      Object.defineProperty({}, 'owned', {
        enumerable: true,
        get() {
          throw new Error('A payload getter must not run');
        },
      }),
    ];
    for (const payload of payloads)
      await assert.rejects(
        f.asTenant('tenant-a', () =>
          f.service.send('receiver', { id: 'one', type: 'owned', payload }),
        ),
      );
    for (const input of [
      'null',
      '[]',
      '1',
      'true',
      '{"id":"one","type":"owned"}',
      '{"id":"one","type":"owned","payload":null,"extra":true}',
    ])
      assert.throws(() => f.service.parseEvent(Buffer.from(input)), {
        code: 'EK_WEBHOOK_DELIVERY',
      });
    const parsed = f.service.parseEvent(
      Buffer.from('{"id":"one","type":"owned","payload":[null,true,1,"text",{}]}'),
    );
    assert.ok(Object.isFrozen(parsed));
    assert.ok(Object.isFrozen(parsed.payload));
    assert.equal(f.state.secretCalls, 0);
    assert.equal(f.state.claimCalls, 0);
  } finally {
    await f.close();
  }
});
