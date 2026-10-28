// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { proxyPlugin } from '../../dist/index.js';
import type { ProxyRouteConfig, ProxyPluginSettings } from '../../dist/index.js';

const route: ProxyRouteConfig = {
  routeId: 'reviewed',
  prefix: '/orders',
  upstreamOrigin: 'https://upstream.example.test',
  methods: ['GET'],
  auth: { required: false, reason: 'This owned configuration test has no protected data' },
  maxRequestBytes: 1024,
  maxResponseBytes: 1024,
  timeoutMs: 1000,
  destinationPolicy: { kind: 'public-only' },
};

test('Strict route configuration rejects coercion, accessors, unsafe rewrites and ambiguous trust before startup', () => {
  for (const change of [
    { routeId: 'arbitrary label' },
    { prefix: '/orders/:id' },
    { rewritePrefix: '//foreign.invalid' },
    { rewritePrefix: '/../private' },
    { methods: ['CONNECT'] },
    { methods: ['GET', 'GET'] },
    { timeoutMs: 0 },
    { timeoutMs: 30001 },
    { maxRequestBytes: Infinity },
    { maxResponseBytes: '1024' },
    { auth: { required: false } },
    { auth: { required: true, reason: 'ignored' } },
    {
      destinationPolicy: {
        kind: 'private-allowlisted',
        allowedHosts: ['foreign.test'],
        allowedCidrs: ['127.0.0.1/32'],
      },
    },
    {
      destinationPolicy: {
        kind: 'private-allowlisted',
        allowedHosts: ['upstream.example.test'],
        allowedCidrs: ['127.0.0.1/33'],
      },
    },
    { identityDelegation: 'none', serviceCredentialSecretRef: 'secret/ref' },
    { unknown: true },
  ])
    assert.throws(() => proxyPlugin({ routes: [{ ...route, ...change }] } as ProxyPluginSettings), {
      code: 'EK_PROXY_CONFIG',
    });
  assert.throws(
    () =>
      proxyPlugin({ routes: [route, { ...route, routeId: 'second', prefix: '/orders/nested' }] }),
    { code: 'EK_PROXY_CONFIG' },
  );
  let invoked = 0;
  const settings = Object.defineProperty({}, 'routes', {
    enumerable: true,
    get() {
      invoked++;
      return [route];
    },
  });
  assert.throws(() => proxyPlugin(settings as ProxyPluginSettings), { code: 'EK_PROXY_CONFIG' });
  const getter = Object.defineProperty({ ...route }, 'upstreamOrigin', {
    get() {
      invoked++;
      return route.upstreamOrigin;
    },
  });
  assert.throws(() => proxyPlugin({ routes: [getter] }), { code: 'EK_PROXY_CONFIG' });
  assert.equal(invoked, 0);
});

test('A required inbound authority or outbound mTLS capability cannot be replaced by a caller object', async () => {
  for (const candidate of [
    { ...route, auth: { required: true as const, scopes: [] } },
    {
      ...route,
      upstreamTlsProfile: {
        trustRootsRef: 'approved/root',
        certRef: 'approved/cert',
        keyRef: 'approved/key',
        allowedIdentities: ['spiffe://fixture/upstream'],
        revocation: 'crl-required' as const,
      },
    },
  ]) {
    const app = await createApplication({
      service: { name: 'proxy-missing-authority', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), apiPlugin(), proxyPlugin({ routes: [candidate] })],
    });
    try {
      await assert.rejects(app.start());
    } finally {
      await app.stop();
    }
  }
});

test('Facade routes cannot silently shadow a proxy namespace during listener activation', async () => {
  const app = await createApplication({
    service: { name: 'proxy-route-ownership', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [loggingPlugin(), apiPlugin(), proxyPlugin({ routes: [route] })],
  });
  app.api.get('/orders/private', {
    auth: { required: false },
    schema: { response: { type: 'object' } },
    handler: () => ({}),
  });
  try {
    await assert.rejects(app.start());
  } finally {
    await app.stop();
  }
});
