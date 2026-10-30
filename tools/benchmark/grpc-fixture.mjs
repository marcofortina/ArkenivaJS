// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Server, ServerCredentials, loadPackageDefinition } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { fixture as pkiFixture } from '../../packages/security-mtls/dist-test/fixture.js';

/** Real native RPCs and the existing OpenSSL path/CRL fixture remain independently owned by the parent. */
export async function startGrpcFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-comparison-'));
  const pki = await pkiFixture().catch(async (cause) => {
    await rm(directory, { recursive: true, force: true });
    throw cause;
  });
  const descriptorSource = fileURLToPath(
    new URL('../../packages/grpc/test/fixtures/echo.proto', import.meta.url),
  );
  const descriptorFile = join(directory, 'echo.proto');
  const server = new Server({
    'grpc.max_receive_message_length': 4096,
    'grpc.max_send_message_length': 4096,
  });
  const counts = { unary: 0, streams: 0, streamedMessages: 0 },
    failures = [],
    tasks = new Set();
  const marker = 'owned-grpc-private-value-π',
    bearer = randomBytes(32).toString('base64url');
  let bridge,
    bound = false;
  const close = async () => {
    try {
      if (bridge?.listening) {
        bridge.closeAllConnections();
        await new Promise((done) => bridge.close(done));
      }
      await Promise.allSettled([...tasks]);
      if (bound) await new Promise((done) => server.tryShutdown(done));
      else server.forceShutdown();
    } finally {
      try {
        await pki.close();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  };
  try {
    await writeFile(descriptorFile, await readFile(descriptorSource), { mode: 0o600, flag: 'wx' });
    const definition = loadPackageDefinition(
      loadSync(descriptorFile, { longs: String, bytes: Buffer, keepCase: true }),
    );
    server.addService(definition.fixture.Echo.service, {
      Bounce(call, callback) {
        try {
          assert.equal(call.request.value, marker + '-unary');
          counts.unary++;
          callback(null, call.request);
        } catch (cause) {
          failures.push(cause);
          callback(new Error('The owned gRPC unary fixture rejected its request'));
        }
      },
      Watch(call) {
        try {
          assert.equal(call.request.value, marker + '-stream');
          counts.streams++;
          for (let index = 1; index <= 3; index++) {
            call.write({ ...call.request, sequence: String(index) });
            counts.streamedMessages++;
          }
          call.end();
        } catch (cause) {
          failures.push(cause);
          call.destroy(new Error('The owned gRPC stream fixture rejected its request', { cause }));
        }
      },
    });
    const material = pki.materials.get('server');
    const port = await new Promise((done, reject) =>
      server.bindAsync(
        '127.0.0.1:0',
        ServerCredentials.createSsl(
          Buffer.from(pki.root),
          [{ private_key: Buffer.from(material.key), cert_chain: Buffer.from(material.cert) }],
          true,
        ),
        (cause, value) => (cause ? reject(cause) : done(value)),
      ),
    );
    bound = true;
    bridge = createServer((request, response) => {
      const task = (async () => {
        assert.equal(request.method, 'POST');
        assert.equal(request.url, '/verify');
        const supplied = Buffer.from(request.headers.authorization ?? ''),
          expected = Buffer.from('Bearer ' + bearer);
        assert.equal(supplied.length, expected.length);
        assert.ok(timingSafeEqual(supplied, expected));
        const chunks = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          assert.ok(bytes <= 8192);
          chunks.push(chunk);
        }
        const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        assert.deepEqual(input.policy, {
          trustRootsRef: 'fixture',
          allowedIdentities: [...pki.profiles.client.allowedIdentities],
          hostname: 'localhost',
          revocation: 'crl-required',
        });
        const verified = await pki.trustProvider.verifyChainAndRevocation(
          {
            peerDer: Buffer.from(input.peerDer, 'base64'),
            policy: input.policy,
            now: new Date().toISOString(),
          },
          { timeoutMs: 1500 },
        );
        response
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify(verified));
      })()
        .catch(() => response.writeHead(400).end())
        .finally(() => tasks.delete(task));
      tasks.add(task);
    });
    await new Promise((done, reject) => {
      bridge.once('error', reject);
      bridge.listen(0, '127.0.0.1', done);
    });
    const client = pki.materials.get('client');
    const encoded = {
      ca: client.ca.map((value) => Buffer.from(value).toString('base64')),
      cert: Buffer.from(client.cert).toString('base64'),
      key: Buffer.from(client.key).toString('base64'),
    };
    const fixture = {
      endpoint: 'localhost:' + port,
      descriptorFile,
      material: JSON.stringify(encoded),
      profile: JSON.stringify(pki.profiles.client),
      bridgeUrl: 'http://127.0.0.1:' + bridge.address().port + '/verify',
      bearer,
      marker,
      foreignCa: Buffer.from(pki.foreign).toString('base64'),
    };
    return {
      fixture,
      close,
      trustUnavailable: (value) => pki.unavailable(value),
      privacyValues: [...encoded.ca, encoded.cert, encoded.key],
      verify(profiles) {
        assert.equal(failures.length, 0);
        assert.equal(counts.unary, profiles);
        assert.equal(counts.streams, profiles);
        assert.equal(counts.streamedMessages, profiles * 3);
        assert.ok(pki.verifications() >= profiles - 1);
        return {
          actualUnaryCalls: counts.unary,
          actualStreamCalls: counts.streams,
          actualStreamedMessages: counts.streamedMessages,
          nativeChainAndCrlChecks: pki.verifications(),
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
