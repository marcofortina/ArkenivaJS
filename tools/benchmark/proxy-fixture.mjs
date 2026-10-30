// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { tlsFixture } from '../../packages/proxy/dist-test/tls-fixture.js';

export const proxyBytes = () => Buffer.from(Array.from({ length: 131072 }, (_, i) => i % 256));
export const forbiddenProxyHeaders = [
  'authorization',
  'cookie',
  'x-forwarded-user',
  'x-forwarded-host',
  'x-tenant-id',
  'proxy-authorization',
  'baggage',
];

export async function startProxyFixture(san, sampleGets = false) {
  assert.equal(typeof sampleGets, 'boolean');
  const tls = await tlsFixture(san),
    received = [],
    tasks = new Set();
  let admitted = 0;
  const body = proxyBytes(),
    digest = createHash('sha256').update(body).digest('hex');
  const server = createServer(
    { cert: tls.cert, key: tls.key, minVersion: 'TLSv1.2' },
    (request, response) => {
      if (admitted >= 512 || tasks.size >= 8) {
        response.writeHead(503, { connection: 'close' }).end();
        return;
      }
      admitted++;
      const controller = new AbortController();
      response.once('close', () => controller.abort());
      const task = (async () => {
        const chunks = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          assert.ok(size <= 262144);
          chunks.push(Buffer.from(chunk));
        }
        const bytes = Buffer.concat(chunks);
        const receipt = {
          method: request.method,
          url: request.url,
          bytes: bytes.length,
          digest: createHash('sha256').update(bytes).digest('hex'),
          headers: request.headers,
          responsePayloadBytes: 0,
          responseComplete: false,
        };
        received.push(receipt);
        response.once('finish', () => {
          receipt.responseComplete = true;
        });
        response.writeHead(200, { 'content-type': 'application/octet-stream' });
        const output = request.method === 'POST' ? bytes : body;
        for (let offset = 0; offset < output.length; offset += 4093) {
          const chunk = output.subarray(offset, offset + 4093),
            writable = response.write(chunk);
          receipt.responsePayloadBytes += chunk.length;
          if (!writable) await once(response, 'drain', { signal: controller.signal });
        }
        response.end();
      })()
        .catch(() => response.destroy())
        .finally(() => tasks.delete(task));
      tasks.add(task);
    },
  );
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  try {
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
  } catch (cause) {
    await tls.close();
    throw cause;
  }
  return {
    fixture: {
      upstream: 'https://127.0.0.1:' + server.address().port,
      caFile: tls.files.certificateFile,
      marker: 'owned-proxy-private-credential',
      ...(sampleGets ? { sampleGets } : {}),
    },
    received,
    verify(profiles, samples = 0) {
      assert.equal(samples, sampleGets ? 480 : 0);
      assert.equal(received.length, profiles * 2 + samples);
      assert.equal(admitted, received.length);
      assert.equal(tasks.size, 0);
      let responseBytes = 0,
        requestBytes = 0;
      for (let i = 0; i < profiles; i++) {
        const count = 2 + samples / profiles;
        const [post, get, ...sampled] = received.slice(i * count, (i + 1) * count);
        assert.equal(post.method, 'POST');
        assert.equal(get.method, 'GET');
        assert.equal(post.bytes, body.length);
        assert.equal(post.digest, digest);
        assert.equal(get.bytes, 0);
        assert.equal(sampled.length, sampleGets ? 120 : 0);
        assert.ok(sampled.every((item) => item.method === 'GET' && item.bytes === 0));
        for (const item of [post, get, ...sampled]) {
          assert.equal(item.responseComplete, true);
          assert.equal(item.responsePayloadBytes, body.length);
          responseBytes += item.responsePayloadBytes;
          requestBytes += item.bytes;
          assert.equal(
            item.url,
            '/origin/items?value=one%20two&value=three&upstream=https%3A%2F%2Fforeign.invalid',
          );
          for (const name of forbiddenProxyHeaders) assert.equal(item.headers[name], undefined);
        }
      }
      return {
        actualUpstreamRequests: received.length,
        exactStreamedBytesAndQueryVerified: true,
        spoofedIdentityHeadersAbsent: true,
        ...(sampleGets
          ? {
              sampledForwardedGets: samples,
              actualResponsePayloadBytes: responseBytes,
              actualRequestPayloadBytes: requestBytes,
              maximumRetainedUpstreamReceipts: 512,
              pendingUpstreamHandlers: tasks.size,
              parentHttpsOriginResources: null,
            }
          : {}),
        releaseGate: false,
      };
    },
    async close() {
      try {
        server.closeAllConnections();
        await new Promise((done, reject) =>
          server.close((error) => (error ? reject(error) : done())),
        );
        await Promise.allSettled([...tasks]);
        assert.equal(tasks.size, 0);
      } finally {
        await tls.close();
      }
    },
  };
}
