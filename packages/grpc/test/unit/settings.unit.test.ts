// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { grpcPlugin } from '../../dist/index.js';
import { capture, operation, policy } from '../../dist/settings.js';
import type { GrpcPluginSettings } from '../../dist/index.js';

function settings(): GrpcPluginSettings {
  return {
    services: [
      {
        name: 'Inventory',
        descriptorFile: '/trusted/inventory.proto',
        endpoint: 'service.example:443',
        allowedMethods: ['ReadStock'],
        maxMessageBytes: 4096,
      },
    ],
    tlsProfiles: {
      client: {
        trustRootsRef: 'roots',
        certRef: 'certificate',
        keyRef: 'private-material',
        allowedIdentities: ['spiffe://fixture/server'],
        revocation: 'crl-required',
      },
    },
    handlers: {},
    authority: {
      async require(_action, subject) {
        if (!subject) throw new Error('Authentication is required');
        return subject;
      },
    },
    policy: { maxConcurrent: 4, timeoutMs: 3000 },
  };
}
test('gRPC factories are resource-free and capture immutable explicit TLS configuration', () => {
  const input = settings(),
    result = capture(input);
  assert.equal(result.services[0]!.endpoint, 'service.example:443');
  assert.equal(result.services[0]!.tlsProfile, 'client');
  assert.ok(Object.isFrozen(result.services[0]));
  assert.ok(Object.isFrozen(result.tlsProfiles));
  assert.equal(grpcPlugin(input).id, 'grpc');
});
test('Ambiguous client TLS profiles fail closed until one profile is explicitly selected', () => {
  const input = settings(),
    tlsProfiles = { ...input.tlsProfiles, alternate: input.tlsProfiles.client! };
  assert.throws(() => capture({ ...input, tlsProfiles }), { code: 'EK_CONFIG_INVALID' });
  assert.equal(
    capture({
      ...input,
      tlsProfiles,
      services: [{ ...input.services[0]!, tlsProfile: 'alternate' }],
    }).services[0]!.tlsProfile,
    'alternate',
  );
  assert.throws(() =>
    capture({ ...input, services: [{ ...input.services[0]!, tlsProfile: 'missing' }] }),
  );
});
test('Authority methods retain class ownership without executing accessors', () => {
  class Authority {
    async require() {
      return { issuer: 'https://issuer.example', subject: 'service' };
    }
  }
  assert.equal(typeof capture({ ...settings(), authority: new Authority() }).require, 'function');
  let accesses = 0;
  const authority = Object.defineProperty({}, 'require', {
    get() {
      accesses++;
      return () => undefined;
    },
  });
  assert.throws(() =>
    capture({ ...settings(), authority: authority as GrpcPluginSettings['authority'] }),
  );
  assert.equal(accesses, 0);
});
test('Configuration rejects unsafe destinations, limits and duplicate service profiles', () => {
  for (const endpoint of [
    'http://localhost:8080',
    'dns:///localhost:8080',
    'localhost:0',
    'localhost:65536',
    'user@localhost:443',
    'localhost:443/path',
  ])
    assert.throws(() =>
      capture({ ...settings(), services: [{ ...settings().services[0]!, endpoint }] }),
    );
  for (const timeoutMs of [0, -1, 0.5, NaN, Infinity, 60001])
    assert.throws(() => capture({ ...settings(), policy: { maxConcurrent: 4, timeoutMs } }));
  assert.throws(() =>
    capture({ ...settings(), services: [...settings().services, ...settings().services] }),
  );
  assert.throws(() =>
    policy({
      maxInboundBytes: 0,
      maxOutboundBytes: 1,
      concurrencyLimit: 1,
      requireAuthentication: true,
      methodAllowlist: ['ReadStock'],
    }),
  );
});
test('Call metadata and cancellation are copied without getter execution or timeout bypasses', () => {
  const controller = new AbortController(),
    result = operation(
      {
        timeoutMs: 1,
        signal: controller.signal,
        metadata: { authorization: 'Bearer public-placeholder' },
      },
      3000,
    );
  assert.equal(result.signal?.aborted, false);
  controller.abort();
  assert.equal(result.signal?.aborted, true);
  assert.equal(result.timeoutMs, 1);
  for (const metadata of [
    { 'grpc-timeout': 'infinite' },
    { authorization: 'line\r\nbreak' },
    { 'opaque-bin': 'not-bytes' },
    { authorization: 'x'.repeat(16385) },
  ])
    assert.throws(() => operation({ metadata }, 3000));
  for (const timeoutMs of [0, -1, 0.5, NaN, Infinity])
    assert.throws(() => operation({ timeoutMs }, 3000));
});
