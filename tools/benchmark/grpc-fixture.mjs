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
import { grpcReceiptDigest, grpcCorpusPayload } from './grpc-workload.mjs';
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
    'grpc.max_concurrent_streams': 2,
  });
  const counts = {
      unary: 0,
      streams: 0,
      streamedMessages: 0,
      activeHandlers: 0,
      peakActiveHandlers: 0,
      activeBridgeRequests: 0,
      peakBridgeRequests: 0,
      rejectedBridgeRequests: 0,
      activeBridgeConnections: 0,
    },
    receipts = [],
    seen = new Set(),
    privacyValues = [],
    sockets = new Set(),
    failures = [],
    tasks = new Set();
  const marker = 'owned-grpc-private-value-π',
    bearer = randomBytes(32).toString('base64url');
  let bridge,
    closing,
    bound = false;
  const close = () =>
    (closing ??= (async () => {
      try {
        if (bridge?.listening) {
          bridge.closeAllConnections();
          for (const socket of sockets) socket.destroy();
          await new Promise((done) => bridge.close(done));
        }
        await Promise.allSettled([...tasks]);
        if (bound) {
          await new Promise((done, reject) => {
            const timer = setTimeout(() => {
              server.forceShutdown();
              reject(new Error('The owned gRPC server did not retire'));
            }, 5000);
            server.tryShutdown((cause) => {
              clearTimeout(timer);
              if (cause) reject(new Error('The owned gRPC server shutdown failed'));
              else done();
            });
          });
        } else server.forceShutdown();
        assert.equal(counts.activeHandlers, 0);
        assert.equal(counts.activeBridgeRequests, 0);
        for (let attempt = 0; attempt < 100 && sockets.size > 0; attempt++)
          await new Promise((done) => setTimeout(done, 5));
        assert.equal(sockets.size, 0);
      } finally {
        receipts.length = 0;
        seen.clear();
        try {
          await pki.close();
        } finally {
          await rm(directory, { recursive: true, force: true });
        }
      }
    })());
  try {
    await writeFile(descriptorFile, await readFile(descriptorSource), { mode: 0o600, flag: 'wx' });
    const definition = loadPackageDefinition(
      loadSync(descriptorFile, { longs: String, bytes: Buffer, keepCase: true }),
    );
    server.addService(definition.fixture.Echo.service, {
      Bounce(call, callback) {
        try {
          counts.activeHandlers++;
          counts.peakActiveHandlers = Math.max(counts.peakActiveHandlers, counts.activeHandlers);
          assert.ok(receipts.length < 512);
          assert.deepEqual(Object.keys(call.request).sort(), ['payload', 'sequence', 'value']);
          assert.equal(call.request.sequence, '9223372036854775807');
          assert.deepEqual(Buffer.from(call.request.payload), grpcCorpusPayload());
          let receipt = 'verification';
          if (call.request.value !== marker + '-unary') {
            receipt = call.request.value.slice((marker + '-unary-').length);
            assert.equal(call.request.value, marker + '-unary-' + receipt);
            assert.match(receipt, /^[a-f0-9-]{36}$/);
            assert.equal(seen.has(receipt), false);
            seen.add(receipt);
            privacyValues.push(call.request.value, receipt);
          }
          const method = definition.fixture.Echo.service.Bounce,
            decoded = method.responseDeserialize(method.responseSerialize(call.request));
          assert.equal(decoded.value, call.request.value);
          assert.equal(decoded.sequence, '9223372036854775807');
          assert.deepEqual(Buffer.from(decoded.payload), grpcCorpusPayload());
          receipts.push({
            receipt,
            sequence: decoded.sequence,
            payloadHex: Buffer.from(decoded.payload).toString('hex'),
          });
          counts.unary++;
          callback(null, call.request);
        } catch {
          if (failures.length < 4)
            failures.push(new Error('The owned gRPC fixture validation failed'));
          callback(new Error('The owned gRPC unary fixture rejected its request'));
        } finally {
          counts.activeHandlers--;
        }
      },
      Watch(call) {
        try {
          counts.activeHandlers++;
          counts.peakActiveHandlers = Math.max(counts.peakActiveHandlers, counts.activeHandlers);
          assert.equal(call.request.value, marker + '-stream');
          assert.equal(call.request.sequence, '9223372036854775807');
          assert.deepEqual(Buffer.from(call.request.payload), grpcCorpusPayload());
          counts.streams++;
          for (let index = 1; index <= 3; index++) {
            call.write({ ...call.request, sequence: String(index) });
            counts.streamedMessages++;
          }
          call.end();
        } catch {
          if (failures.length < 4)
            failures.push(new Error('The owned gRPC fixture validation failed'));
          call.destroy(new Error('The owned gRPC stream fixture rejected its request'));
        } finally {
          counts.activeHandlers--;
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
      if (tasks.size >= 4) {
        counts.rejectedBridgeRequests++;
        response.writeHead(503).end();
        return;
      }
      counts.activeBridgeRequests++;
      counts.peakBridgeRequests = Math.max(counts.peakBridgeRequests, counts.activeBridgeRequests);
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
        .catch(() => {
          counts.rejectedBridgeRequests++;
          response.writeHead(400).end();
        })
        .finally(() => {
          tasks.delete(task);
          counts.activeBridgeRequests--;
        });
      tasks.add(task);
    });
    bridge.maxConnections = 4;
    bridge.requestTimeout = 3000;
    bridge.headersTimeout = 3000;
    bridge.on('connection', (socket) => {
      sockets.add(socket);
      counts.activeBridgeConnections = sockets.size;
      socket.once('close', () => {
        sockets.delete(socket);
        counts.activeBridgeConnections = sockets.size;
      });
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
    privacyValues.push(
      ...Object.values(fixture),
      ...encoded.ca,
      encoded.cert,
      encoded.key,
      '127.0.0.1',
      'localhost',
    );
    return {
      fixture,
      close,
      trustUnavailable: (value) => pki.unavailable(value),
      privacyValues,
      verify(profiles, completions, measured = false) {
        assert.equal(failures.length, 0);
        const expectedUnary = completions
          ? completions.reduce((sum, row) => sum + row.totalUnaryCalls, 0)
          : profiles;
        assert.equal(counts.unary, expectedUnary);
        assert.equal(receipts.length, expectedUnary);
        if (completions) {
          let offset = 0;
          for (const row of completions) {
            const next = offset + row.totalUnaryCalls;
            assert.ok(Number.isSafeInteger(next) && next <= receipts.length);
            assert.equal(grpcReceiptDigest(receipts.slice(offset, next)), row.receiptDigest);
            offset = next;
          }
          assert.equal(offset, receipts.length);
        }
        assert.equal(counts.streams, profiles);
        assert.equal(counts.streamedMessages, profiles * 3);
        assert.ok(pki.verifications() >= profiles - 1);
        return {
          actualUnaryCalls: counts.unary,
          actualStreamCalls: counts.streams,
          actualStreamedMessages: counts.streamedMessages,
          nativeChainAndCrlChecks: pki.verifications(),
          releaseGate: false,
          ...(measured
            ? {
                measured: true,
                independentReceiptIntegrity: true,
                distinctFixtureReceipts: seen.size,
                activeHandlers: counts.activeHandlers,
                peakActiveHandlers: counts.peakActiveHandlers,
                activeBridgeRequests: counts.activeBridgeRequests,
                peakBridgeRequests: counts.peakBridgeRequests,
                rejectedBridgeRequests: counts.rejectedBridgeRequests,
              }
            : {}),
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
