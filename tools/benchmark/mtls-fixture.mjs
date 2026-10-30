// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createSecureServer } from 'node:http2';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fixture as pkiFixture } from '../../packages/security-mtls/dist-test/fixture.js';

/** The parent owns actual key material, HTTP/2 mutual TLS and independent OpenSSL path/CRL checks. */
export async function startMtlsFixture() {
  const pki = await pkiFixture(),
    material = pki.materials.get('server');
  const bearer = randomBytes(32).toString('base64url'),
    marker = 'owned-mtls-private-response';
  const sessions = new Set(),
    work = new Set(),
    admitted = new WeakMap();
  const counts = { applicationRequests: 0, serverPeerChecks: 0, clientPeerChecks: 0 };
  const policy = (role) => ({
    trustRootsRef: 'fixture',
    allowedIdentities: [...pki.profiles[role].allowedIdentities],
    hostname: 'localhost',
    revocation: 'crl-required',
  });
  const server = createSecureServer({
    ca: pki.root,
    cert: material.cert,
    key: material.key,
    minVersion: 'TLSv1.3',
    requestCert: true,
    rejectUnauthorized: true,
  });
  server.on('session', (session) => {
    sessions.add(session);
    session.once('close', () => sessions.delete(session));
    session.on('error', () => undefined);
    const verification = (async () => {
      assert.equal(session.socket.authorized, true);
      assert.equal(session.socket.alpnProtocol, 'h2');
      const identity = await pki.trustProvider.verifyChainAndRevocation(
        {
          peerDer: session.socket.getPeerCertificate().raw,
          policy: policy('server'),
          now: new Date().toISOString(),
        },
        { timeoutMs: 1500 },
      );
      assert.deepEqual(identity.uriSans, ['spiffe://fixture/client']);
      counts.serverPeerChecks++;
      return true;
    })().catch(() => false);
    admitted.set(session, verification);
  });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => undefined);
    const task = (async () => {
      assert.equal(await admitted.get(stream.session), true);
      assert.equal(headers[':method'], 'GET');
      assert.equal(headers[':path'], '/exchange');
      counts.applicationRequests++;
      stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' });
      stream.end(marker);
    })()
      .catch(() => stream.close())
      .finally(() => work.delete(task));
    work.add(task);
  });
  const bridge = createServer((request, response) => {
    const task = (async () => {
      assert.equal(request.method, 'POST');
      assert.equal(request.url, '/verify');
      const actual = Buffer.from(request.headers.authorization ?? ''),
        expected = Buffer.from('Bearer ' + bearer);
      assert.equal(actual.length, expected.length);
      assert.ok(timingSafeEqual(actual, expected));
      let size = 0;
      const chunks = [];
      for await (const chunk of request) {
        size += chunk.length;
        assert.ok(size <= 8192);
        chunks.push(chunk);
      }
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      assert.deepEqual(input.policy, policy('client'));
      const verified = await pki.trustProvider.verifyChainAndRevocation(
        {
          peerDer: Buffer.from(input.peerDer, 'base64'),
          policy: input.policy,
          now: new Date().toISOString(),
        },
        { timeoutMs: 1500 },
      );
      counts.clientPeerChecks++;
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(verified));
    })()
      .catch(() => response.writeHead(400).end())
      .finally(() => work.delete(task));
    work.add(task);
  });
  const close = async () => {
    try {
      bridge.closeAllConnections();
      for (const session of sessions) session.destroy();
      await Promise.all([
        new Promise((done) => bridge.close(done)),
        new Promise((done) => server.close(done)),
      ]);
      await Promise.allSettled([...work]);
    } finally {
      await pki.close();
    }
  };
  try {
    for (const listener of [server, bridge])
      await new Promise((done, reject) => {
        listener.once('error', reject);
        listener.listen(0, '127.0.0.1', done);
      });
    const client = pki.materials.get('client'),
      encoded = {
        ca: client.ca.map((value) => Buffer.from(value).toString('base64')),
        cert: Buffer.from(client.cert).toString('base64'),
        key: Buffer.from(client.key).toString('base64'),
      };
    return {
      fixture: {
        endpoint: 'https://localhost:' + server.address().port,
        bridgeUrl: 'http://127.0.0.1:' + bridge.address().port + '/verify',
        bearer,
        marker,
        profile: JSON.stringify(pki.profiles.client),
        material: JSON.stringify(encoded),
        foreignCa: Buffer.from(pki.foreign).toString('base64'),
      },
      privacyValues: [
        ...encoded.ca,
        encoded.cert,
        encoded.key,
        'spiffe://fixture/client',
        'spiffe://fixture/server',
        ...[...pki.certificates.values()].map((value) => value.certificate.fingerprint256),
      ],
      close,
      unavailable: (value) => pki.unavailable(value),
      revokeServer: () => pki.revoke('server'),
      observations: () => ({ ...counts }),
      verify(profiles) {
        assert.equal(counts.applicationRequests, profiles);
        assert.equal(counts.clientPeerChecks, profiles);
        assert.ok(counts.serverPeerChecks >= profiles);
        return {
          actualAuthorizedHttp2Requests: counts.applicationRequests,
          actualClientPeerCrlChecks: counts.clientPeerChecks,
          actualServerPeerCrlChecks: counts.serverPeerChecks,
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
