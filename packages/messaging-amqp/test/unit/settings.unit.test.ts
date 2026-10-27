// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { AmqpPluginSettings } from '../../dist/index.js';
import { capture, endpoint } from '../../dist/settings.js';

const code = (error: unknown) => error instanceof KitError && error.code === 'EK_AMQP_CONFIG';
function settings(): AmqpPluginSettings {
  return {
    connections: [
      {
        name: 'events',
        connectionUriSecretRef: 'fixture-uri',
        maxInFlightPublishes: 10,
        maxMessageBytes: 65536,
        topology: {
          exchanges: [{ name: 'events', type: 'topic', routingKeys: ['created'] }],
          queues: [{ name: 'audit' }],
          bindings: [{ exchange: 'events', queue: 'audit', routingKey: 'created' }],
        },
      },
    ],
    resolveSecret: async () => {
      throw new Error('Capture must not invoke a resolver');
    },
  };
}
function uri() {
  const url = new URL('amqps://broker.fixture.invalid/%252F');
  url.username = 'synthetic-user';
  url.password = randomBytes(24).toString('base64url');
  return url;
}
test('AMQP captures a fail-closed trusted topology, exact publisher routes and explicit provisioning policy without I/O', () => {
  const original = settings(),
    value = capture(original);
  assert.equal(value.connections[0]!.allowTopologyProvisioning, false);
  assert.equal(value.connections[0]!.topology.exchanges[0]!.durable, true);
  assert.deepEqual(value.connections[0]!.topology.exchanges[0]!.routingKeys, ['created']);
  assert.ok(Object.isFrozen(value.connections[0]!.topology));
  assert.equal(
    capture({
      ...original,
      connections: [{ ...original.connections[0]!, allowTopologyProvisioning: true }],
    }).connections[0]!.allowTopologyProvisioning,
    true,
  );
});
test('AMQP rejects absent topology, duplicate names, invalid exchange kinds, unrestricted routing and oversized admission budgets', () => {
  const original = settings(),
    connection = original.connections[0]!,
    topology = connection.topology;
  for (const patch of [
    { topology: undefined },
    { maxInFlightPublishes: 0 },
    { maxMessageBytes: 0 },
    { maxMessageBytes: 16 * 1024 * 1024, maxInFlightPublishes: 5 },
    { tlsCaFile: 'relative.pem' },
    { allowTopologyProvisioning: 'yes' },
    { topology: { ...topology, exchanges: [{ ...topology.exchanges[0]!, type: 'unknown' }] } },
    { topology: { ...topology, exchanges: [{ ...topology.exchanges[0]!, routingKeys: [] }] } },
    {
      topology: {
        ...topology,
        bindings: [{ exchange: 'foreign', queue: 'audit', routingKey: 'created' }],
      },
    },
    { topology: { ...topology, queues: [{ name: 'amq.forbidden' }] } },
    { topology: { ...topology, exchanges: [topology.exchanges[0]!, topology.exchanges[0]!] } },
    { topology: { ...topology, bindings: [topology.bindings[0]!, topology.bindings[0]!] } },
  ])
    assert.throws(
      () =>
        capture({ ...original, connections: [{ ...connection, ...patch }] } as AmqpPluginSettings),
      code,
    );
  assert.throws(() => capture({ ...original, connections: [connection, connection] }), code);
  assert.throws(() => capture({ ...original, connections: [] }), code);
});
test('AMQP validates inherited resolver markers without invoking accessors or custom bind properties', () => {
  let calls = 0;
  const resolver = async () => {
    calls++;
    throw new Error('Must not execute');
  };
  Object.defineProperty(resolver, 'bind', {
    get() {
      throw new Error('A custom bind accessor must not run');
    },
  });
  Object.setPrototypeOf(resolver, { usage: 'test-only' });
  assert.equal(capture({ ...settings(), resolveSecret: resolver }).resolverUsage, 'test-only');
  assert.equal(calls, 0);
  const accessor = Object.defineProperty(async () => '', 'usage', {
    get() {
      calls++;
      throw new Error('Must not execute');
    },
  });
  assert.throws(() => capture({ ...settings(), resolveSecret: accessor }), code);
  assert.equal(calls, 0);
});
test('AMQP secret URIs require verified AMQPS fields and preserve percent-encoded vhost identity exactly once', () => {
  const value = uri(),
    parsed = endpoint(value.href);
  assert.equal(parsed.protocol, 'amqps');
  assert.equal(parsed.hostname, 'broker.fixture.invalid');
  assert.equal(parsed.port, 5671);
  assert.ok(parsed.password === value.password);
  assert.equal(parsed.vhost, '%252F');
  assert.equal(parsed.heartbeat, 10);
  assert.equal(parsed.frameMax, 131072);
  const missing = new URL(value);
  missing.username = '';
  missing.password = '';
  const insecure = new URL(value);
  insecure.protocol = 'amqp:';
  const query = new URL(value);
  query.search = '?heartbeat=0';
  const zero = new URL(value);
  zero.port = '0';
  const invalid = new URL(value);
  invalid.username = '%00';
  for (const text of [
    missing.href,
    insecure.href,
    query.href,
    zero.href,
    invalid.href,
    value.href + '#',
    ' ' + value.href,
    value.href + '?',
  ])
    assert.throws(() => endpoint(text), code);
});
