// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import Fastify from 'fastify';
import nativeProxy from '@fastify/http-proxy';
import { proxyBytes } from './proxy-fixture.mjs';

export const proxyIterations = 100;
export const proxyWarmupIterations = 20;
export const proxyMaximumRetainedReceipts = 128;

export function proxyRoute(fixture) {
  const url = new URL(fixture.upstream);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && fixture.upstream === url.origin && fixture.caFile?.startsWith('/'));
  return {
    routeId: 'owned',
    prefix: '/comparison',
    rewritePrefix: '/origin',
    upstreamOrigin: url.origin,
    upstreamCaFile: fixture.caFile,
    methods: ['GET', 'POST'],
    auth: { required: false, reason: 'Explicit synthetic public route in an owned comparison' },
    destinationPolicy: {
      kind: 'private-allowlisted',
      allowedHosts: ['127.0.0.1'],
      allowedCidrs: ['127.0.0.1/32'],
    },
    maxRequestBytes: 262144,
    maxResponseBytes: 262144,
    timeoutMs: 3000,
  };
}

/** The pinned native proxy uses the same fixed valid route, TLS trust and stripped-header corpus. */
export async function nativeProxyService(fixture) {
  const route = proxyRoute(fixture),
    server = Fastify({ logger: false });
  try {
    await server.register(nativeProxy, {
      upstream: route.upstreamOrigin,
      prefix: route.prefix,
      rewritePrefix: route.rewritePrefix,
      httpMethods: route.methods,
      websocket: false,
      disableRequestLogging: true,
      destroyAgent: true,
      disableCache: true,
      retryMethods: [],
      undici: {
        connections: 16,
        pipelining: 1,
        tls: {
          ca: await readFile(fixture.caFile),
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
        },
      },
      replyOptions: {
        retryDelay: () => null,
        queryString: (_search, raw) => (raw.includes('?') ? raw.slice(raw.indexOf('?') + 1) : ''),
        rewriteRequestHeaders(_request, headers) {
          return Object.fromEntries(
            Object.entries(headers).filter(([key]) =>
              ['host', 'content-type', 'content-length', 'accept'].includes(key),
            ),
          );
        },
      },
    });
    await server.listen({ host: '127.0.0.1', port: 0 });
    return {
      address: () => 'http://127.0.0.1:' + server.server.address().port,
      close: () => server.close(),
    };
  } catch (cause) {
    await server.close();
    throw cause;
  }
}

export async function proxyExchange(service, fixture, method) {
  const origin = new URL(service.address());
  assert.equal(origin.hostname, '127.0.0.1');
  assert.equal(origin.protocol, 'http:');
  assert.ok(origin.port);
  const body = method === 'POST' ? proxyBytes() : Buffer.alloc(0);
  let outgoing,
    closed = Promise.resolve();
  const response = new Promise((done, reject) => {
    outgoing = request(
      origin,
      {
        path: '/comparison/items?value=one%20two&value=three&upstream=https%3A%2F%2Fforeign.invalid',
        method,
        agent: false,
        signal: AbortSignal.timeout(5000),
        headers: {
          'content-type': 'application/octet-stream',
          authorization: 'Bearer ' + fixture.marker,
          cookie: fixture.marker,
          'x-forwarded-user': fixture.marker,
          'x-forwarded-host': 'foreign.invalid',
          'x-tenant-id': fixture.marker,
          'proxy-authorization': fixture.marker,
          baggage: 'subject=' + fixture.marker,
        },
      },
      (incoming) => {
        const chunks = [];
        let size = 0;
        incoming.on('data', (chunk) => {
          size += chunk.length;
          if (size > 262144)
            incoming.destroy(new Error('The owned proxy response exceeded its bound'));
          else chunks.push(Buffer.from(chunk));
        });
        incoming.once('error', reject);
        incoming.once('end', () =>
          done({
            status: incoming.statusCode,
            body: Buffer.concat(chunks),
            headers: incoming.headers,
          }),
        );
      },
    );
    outgoing.once('error', reject);
    outgoing.once('socket', (socket) => {
      closed = new Promise((done) => {
        if (socket.closed) done();
        else socket.once('close', done);
      });
    });
  });
  void response.catch(() => undefined);
  try {
    for (let offset = 0; offset < body.length; offset += 4093)
      if (!outgoing.write(body.subarray(offset, offset + 4093))) await once(outgoing, 'drain');
    outgoing.end();
    return await response;
  } catch (cause) {
    outgoing.destroy();
    throw cause;
  } finally {
    outgoing.destroy();
    await closed;
  }
}

/** Fixed-corpus digest receipts avoid retaining one response buffer for every sample. */
export function createProxySampling(exchange, expected = proxyBytes()) {
  assert.equal(typeof exchange, 'function');
  assert.ok(expected instanceof Uint8Array);
  const state = {
    expectedBytes: expected.byteLength,
    expectedDigest: createHash('sha256').update(expected).digest('hex'),
    receipts: [],
    active: false,
    closed: false,
  };
  return {
    workload: {
      async forwardedGet() {
        assert.equal(state.closed, false);
        assert.equal(state.active, false);
        assert.ok(state.receipts.length < proxyIterations + proxyWarmupIterations);
        assert.ok(state.receipts.length < proxyMaximumRetainedReceipts);
        state.active = true;
        try {
          const response = await exchange();
          const receipt = {
            status: response.status,
            bytes: response.body.length,
            digest: createHash('sha256').update(response.body).digest('hex'),
            contentType: response.headers['content-type'],
          };
          state.receipts.push(receipt);
          return receipt;
        } finally {
          state.active = false;
        }
      },
    },
    complete({ measure, records }) {
      try {
        assert.equal(state.active, false);
        if (!measure) {
          assert.equal(state.receipts.length, 0);
          assert.deepEqual(records, []);
          return { sampledGets: 0, warmupGets: 0, checkedResponses: 0 };
        }
        assert.equal(records.length, 1);
        const record = records[0];
        assert.equal(record.operation, 'forwardedGet');
        assert.equal(record.sampleCount, proxyIterations);
        assert.equal(record.warmupIterations, proxyWarmupIterations);
        assert.equal(record.rawLatency.unit, 'milliseconds');
        assert.equal(record.rawLatency.values.length, record.sampleCount);
        assert.equal(state.receipts.length, record.sampleCount + record.warmupIterations);
        for (const receipt of state.receipts)
          assert.deepEqual(receipt, {
            status: 200,
            bytes: state.expectedBytes,
            digest: state.expectedDigest,
            contentType: 'application/octet-stream',
          });
        return {
          sampledGets: record.sampleCount,
          warmupGets: record.warmupIterations,
          checkedResponses: state.receipts.length,
          actualResponsePayloadBytes: state.expectedBytes * state.receipts.length,
          responseIntegrityVerified: true,
          peakRetainedReceipts: state.receipts.length,
          maximumRetainedReceipts: proxyMaximumRetainedReceipts,
          retainedResponseBuffers: 0,
          activeCallbacks: 0,
        };
      } finally {
        state.closed = true;
        state.receipts.length = 0;
      }
    },
  };
}

export async function verifyProxy(service, fixture) {
  for (const method of ['POST', 'GET']) {
    const result = await proxyExchange(service, fixture, method);
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, proxyBytes());
    assert.equal(result.headers['content-type'], 'application/octet-stream');
  }
  return { actualProxyRequests: 2, exactStreamedResponseBytes: 262144, verifiedUpstreamTls: true };
}
