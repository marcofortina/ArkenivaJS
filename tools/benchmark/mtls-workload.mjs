// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { connect } from 'node:http2';
import { once } from 'node:events';

export function mtlsConnection(fixture) {
  const endpoint = new URL(fixture.endpoint),
    bridge = new URL(fixture.bridgeUrl);
  assert.equal(endpoint.protocol, 'https:');
  assert.equal(endpoint.hostname, 'localhost');
  assert.ok(endpoint.port && fixture.endpoint === endpoint.origin);
  assert.equal(bridge.protocol, 'http:');
  assert.equal(bridge.hostname, '127.0.0.1');
  assert.ok(bridge.port && !bridge.username && !bridge.password && !bridge.search && !bridge.hash);
  assert.equal(bridge.pathname, '/verify');
  const profile = JSON.parse(fixture.profile),
    encoded = JSON.parse(fixture.material);
  return {
    profile,
    material: {
      ca: encoded.ca.map((value) => Buffer.from(value, 'base64')),
      cert: Buffer.from(encoded.cert, 'base64'),
      key: Buffer.from(encoded.key, 'base64'),
      minVersion: 'TLSv1.3',
      ALPNProtocols: ['h2'],
    },
  };
}

export function mtlsPolicy(fixture) {
  const { profile } = mtlsConnection(fixture);
  return {
    trustRootsRef: profile.trustRootsRef,
    allowedIdentities: profile.allowedIdentities,
    hostname: 'localhost',
    revocation: profile.revocation,
  };
}

async function verifyWithAuthority(fixture, input, options) {
  const response = await globalThis.fetch(fixture.bridgeUrl, {
    method: 'POST',
    headers: { authorization: 'Bearer ' + fixture.bearer, 'content-type': 'application/json' },
    body: JSON.stringify({
      peerDer: Buffer.from(input.peerDer).toString('base64'),
      policy: input.policy,
    }),
    signal: options?.signal ?? AbortSignal.timeout(2500),
    redirect: 'error',
  });
  assert.equal(response.status, 200);
  return response.json();
}

export function mtlsSettings(fixture) {
  const { profile, material } = mtlsConnection(fixture);
  return {
    profiles: { client: profile },
    reloadMode: 'explicit',
    policy: { maxConcurrent: 2, timeoutMs: 3000 },
    credentialProvider: {
      usage: 'test-only',
      async load(requested) {
        assert.deepEqual(requested, profile);
        return material;
      },
    },
    trustProvider: {
      usage: 'test-only',
      verifyChainAndRevocation: (input, options) => verifyWithAuthority(fixture, input, options),
    },
  };
}

/** Native TLS material and the same actual PKI authority retain the two mandatory trust stages. */
export function nativeMtls(fixture) {
  const { profile, material } = mtlsConnection(fixture);
  return {
    async createClientOptions(requested, servername) {
      assert.deepEqual(requested, profile);
      assert.equal(servername, 'localhost');
      return { ...material, servername };
    },
    toNodeClientOptions(options) {
      return { ...options, rejectUnauthorized: true };
    },
    async verifyPeer(peerDer, policy) {
      assert.deepEqual(policy, mtlsPolicy(fixture));
      const certificate = new X509Certificate(peerDer);
      assert.ok(certificate.checkHost('localhost', { subject: 'never' }));
      const identity = await verifyWithAuthority(fixture, { peerDer, policy });
      assert.equal(identity.certificateFingerprintSha256, certificate.fingerprint256);
      assert.ok(profile.allowedIdentities.some((id) => identity.uriSans.includes(id)));
      return identity;
    },
  };
}

export async function verifyMtls(service, fixture) {
  const { profile } = mtlsConnection(fixture),
    prepared = await service.createClientOptions(profile, 'localhost');
  const options = service.toNodeClientOptions(prepared);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.servername, 'localhost');
  const session = connect(fixture.endpoint, options);
  session.on('error', () => undefined);
  const closed = once(session, 'close').catch(() => undefined);
  try {
    await once(session, 'connect');
    assert.equal(session.socket.authorized, true);
    assert.equal(session.socket.alpnProtocol, 'h2');
    const identity = await service.verifyPeer(
      session.socket.getPeerCertificate().raw,
      mtlsPolicy(fixture),
    );
    assert.deepEqual([...identity.uriSans], ['spiffe://fixture/server']);
    const request = session.request({ ':method': 'GET', ':path': '/exchange' });
    request.setTimeout(3000, () =>
      request.destroy(new Error('The owned mTLS exchange exceeded its deadline')),
    );
    const headers = once(request, 'response');
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      body += chunk;
      assert.ok(body.length <= 4096);
    });
    const ended = once(request, 'end');
    request.end();
    const [response] = await headers;
    assert.equal(response[':status'], 200);
    await ended;
    assert.equal(body, fixture.marker);
    return {
      actualMutualTlsHandshake: true,
      negotiatedHttp2: true,
      asynchronousPeerCrlVerifiedBeforeRequest: true,
      actualAuthorizedResponse: true,
    };
  } finally {
    session.destroy();
    await closed;
  }
}
