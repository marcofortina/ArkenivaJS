// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import type { TestContext } from 'node:test';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { createDnsService } from '../../dist/index.js';
import type { DnsService } from '../../dist/index.js';

async function blackhole(t: TestContext) {
  const socket = dgram.createSocket('udp4');
  let requests = 0;
  socket.on('message', () => {
    // Receiving the actual native query is the synchronization boundary; no DNS parser is needed.
    requests++;
  });
  const listening = once(socket, 'listening');
  socket.bind(0, '127.0.0.1');
  await listening;
  t.after(async () => {
    await new Promise<void>((resolve) => socket.close(resolve));
  });
  return {
    server: '127.0.0.1:' + socket.address().port,
    requests: () => requests,
    arrival: () => once(socket, 'message', { signal: AbortSignal.timeout(2000) }),
  };
}

function safeCode(expected: string, hostname: string, server: string) {
  return (cause: unknown) => {
    assert.ok(cause instanceof KitError);
    assert.equal(cause.code, expected);
    const publicError = JSON.stringify(cause.toSafeJSON());
    assert.equal(publicError.includes(hostname), false);
    assert.equal(publicError.includes(server), false);
    assert.equal(publicError.includes('127.0.0.1'), false);
    return true;
  };
}

async function recoverLookup(service: DnsService) {
  const deadline = performance.now() + 5000;
  while (performance.now() < deadline) {
    try {
      return await service.lookup('127.0.0.1', { family: 4, all: true });
    } catch (cause) {
      if (!(cause instanceof KitError) || cause.code !== 'EK_DNS_TEMPORARY') throw cause;
    }
    await delay(10);
  }
  assert.fail('Native DNS work did not release its physical admission before the fixture deadline');
}

test(
  'A real DNS query outlives its public deadline without releasing physical admission or changing global resolvers',
  { timeout: 10000 },
  async (t) => {
    const before = dns.getServers(),
      authority = await blackhole(t),
      hostname = 'deadline.private.test',
      service = createDnsService({
        resolvers: [{ name: 'owned', servers: [authority.server] }],
        maxConcurrency: 1,
        timeoutMs: 1000,
      });
    try {
      const arrived = authority.arrival(),
        pending = service.resolve({ hostname, type: 'A' }, { timeoutMs: 150 }),
        timedOut = assert.rejects(pending, safeCode('EK_DNS_TIMEOUT', hostname, authority.server));
      await arrived;
      assert.equal(authority.requests(), 1);
      await timedOut;

      await assert.rejects(
        service.resolve({ hostname: 'blocked.private.test', type: 'A' }),
        safeCode('EK_DNS_TEMPORARY', 'blocked.private.test', authority.server),
      );
      await assert.rejects(
        service.lookup('127.0.0.1', { family: 4, all: true }),
        safeCode('EK_DNS_TEMPORARY', hostname, authority.server),
      );
      assert.equal(authority.requests(), 1);
      assert.deepEqual(await recoverLookup(service), [{ address: '127.0.0.1', family: 4 }]);
      assert.equal(authority.requests(), 1);
      assert.deepEqual(dns.getServers(), before);
    } finally {
      await service.close();
    }
  },
);

test(
  'Closing a resolver with an observed native query aborts its public operation and permanently closes only that facade',
  { timeout: 10000 },
  async (t) => {
    const before = dns.getServers(),
      authority = await blackhole(t),
      hostname = 'shutdown.private.test',
      settings = {
        resolvers: [{ name: 'owned', servers: [authority.server] }],
        maxConcurrency: 1,
        timeoutMs: 2000,
      },
      service = createDnsService(settings),
      independent = createDnsService(settings);
    try {
      const arrived = authority.arrival(),
        pending = service.resolve({ hostname, type: 'A' }),
        aborted = assert.rejects(pending, safeCode('EK_ABORTED', hostname, authority.server));
      await arrived;
      assert.equal(authority.requests(), 1);
      await service.close();
      await aborted;
      await service.close();
      await assert.rejects(
        service.resolve({ hostname, type: 'A' }),
        safeCode('EK_RESOURCE_CLOSED', hostname, authority.server),
      );
      await assert.rejects(
        service.lookup('127.0.0.1'),
        safeCode('EK_RESOURCE_CLOSED', hostname, authority.server),
      );
      assert.deepEqual(await independent.lookup('127.0.0.1', { family: 4, all: true }), [
        { address: '127.0.0.1', family: 4 },
      ]);
      assert.equal(authority.requests(), 1);
      assert.deepEqual(dns.getServers(), before);
    } finally {
      await service.close();
      await independent.close();
    }
  },
);
