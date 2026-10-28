// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { lookup, LookupAddress } from 'node:dns';
import { Pool } from 'undici';
import { guardedLookup } from '../../dist/network.js';
import { allowedAddress } from '../../dist/policy.js';
import type { ProxyRouteConfig } from '../../dist/index.js';

test('Public-only classification rejects private, metadata, mapped, translated and reserved address space', () => {
  for (const address of [
    '127.0.0.1',
    '0.0.0.0',
    '10.1.2.3',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.100.100.200',
    '192.0.0.1',
    '192.0.2.1',
    '198.51.100.1',
    '203.0.113.1',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    '64:ff9b::a9fe:a9fe',
    '2001:db8::1',
    '2002:7f00:1::',
    '127.1',
    '0x7f000001',
    'fe80::1%lo',
  ])
    assert.equal(allowedAddress(address, { kind: 'public-only' }), false, address);
  for (const address of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111'])
    assert.equal(allowedAddress(address, { kind: 'public-only' }), true, address);
});

test('Actual native pool connections recheck DNS and reject a rebinding before connecting to metadata', async () => {
  let received = 0,
    resolved = 0,
    selected = '127.0.0.1';
  const server = createServer((_request, response) => {
    received++;
    response.end('owned upstream');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const route: ProxyRouteConfig = {
    routeId: 'dns',
    prefix: '/dns',
    upstreamOrigin: 'http://upstream.fixture.invalid:' + address.port,
    methods: ['GET'],
    auth: { required: false, reason: 'The owned upstream fixture has no protected data' },
    destinationPolicy: {
      kind: 'private-allowlisted',
      allowedHosts: ['upstream.fixture.invalid'],
      allowedCidrs: ['127.0.0.1/32'],
    },
    maxRequestBytes: 1024,
    maxResponseBytes: 1024,
    timeoutMs: 1000,
  };
  const resolver = ((
    _hostname: string,
    _options: unknown,
    callback: (error: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
  ) => {
    resolved++;
    callback(null, [{ address: selected, family: 4 }]);
  }) as typeof lookup;
  const connect = guardedLookup(route, resolver);
  const first = new Pool(route.upstreamOrigin, { connect: { lookup: connect }, connections: 1 });
  let second: Pool | undefined;
  try {
    const response = await first.request({ path: '/', method: 'GET' });
    assert.equal(await response.body.text(), 'owned upstream');
    await first.destroy();
    selected = '169.254.169.254';
    second = new Pool(route.upstreamOrigin, { connect: { lookup: connect }, connections: 1 });
    await assert.rejects(second.request({ path: '/', method: 'GET' }), { code: 'EK_PROXY_POLICY' });
    assert.equal(received, 1);
    assert.equal(resolved, 2);
  } finally {
    await first.destroy();
    await second?.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
