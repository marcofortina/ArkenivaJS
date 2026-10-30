// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { once } from 'node:events';
import Fastify from 'fastify';
import nativeProxy from '@fastify/http-proxy';
import { proxyBytes } from './proxy-fixture.mjs';

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
  let outgoing;
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
  }
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
