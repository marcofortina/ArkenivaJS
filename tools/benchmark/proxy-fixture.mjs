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

export async function startProxyFixture(san) {
  const tls = await tlsFixture(san),
    received = [];
  const body = proxyBytes(),
    digest = createHash('sha256').update(body).digest('hex');
  const server = createServer(
    { cert: tls.cert, key: tls.key, minVersion: 'TLSv1.2' },
    (request, response) => {
      void (async () => {
        const chunks = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          assert.ok(size <= 262144);
          chunks.push(Buffer.from(chunk));
        }
        const bytes = Buffer.concat(chunks);
        received.push({
          method: request.method,
          url: request.url,
          bytes: bytes.length,
          digest: createHash('sha256').update(bytes).digest('hex'),
          headers: request.headers,
        });
        response.writeHead(200, { 'content-type': 'application/octet-stream' });
        const output = request.method === 'POST' ? bytes : body;
        for (let offset = 0; offset < output.length; offset += 4093) {
          if (!response.write(output.subarray(offset, offset + 4093)))
            await once(response, 'drain');
        }
        response.end();
      })().catch(() => response.destroy());
    },
  );
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
    },
    received,
    verify(profiles) {
      assert.equal(received.length, profiles * 2);
      for (let i = 0; i < profiles; i++) {
        const [post, get] = received.slice(i * 2, i * 2 + 2);
        assert.equal(post.method, 'POST');
        assert.equal(get.method, 'GET');
        assert.equal(post.bytes, body.length);
        assert.equal(post.digest, digest);
        assert.equal(get.bytes, 0);
        for (const item of [post, get]) {
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
        releaseGate: false,
      };
    },
    async close() {
      try {
        server.closeAllConnections();
        await new Promise((done, reject) =>
          server.close((error) => (error ? reject(error) : done())),
        );
      } finally {
        await tls.close();
      }
    },
  };
}
