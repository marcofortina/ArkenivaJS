// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { connect, createServer } from 'node:tls';
import type { TLSSocket } from 'node:tls';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { fixture } from '../fixture.js';
import { captureSettings, hostname } from '../../dist/settings.js';
import { createRuntime, data, list } from '../../dist/runtime.js';
import { createService } from '../../dist/service.js';
import { captureMaterial, clear } from '../../dist/material.js';
import { fingerprint, nativeCertificate, snapshot } from '../../dist/certificate.js';
import type { MtlsPluginSettings, TlsProfile } from '../../dist/index.js';

let f: Awaited<ReturnType<typeof fixture>>;
before(async () => {
  f = await fixture();
});
after(async () => {
  await f?.close();
});
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;

test('mTLS sparse arrays, executable indexed fields, malformed profile catalogues and hostnames fail before provider work', () => {
  let effects = 0;
  const accessor = Object.defineProperty([1], '0', {
    get() {
      effects++;
      return 1;
    },
  });
  for (const value of [new Array(1), accessor, Object.assign([1], { extra: true })])
    assert.throws(() => list(value, 16));
  for (const value of [
    { [Symbol()]: true },
    Object.defineProperty({}, 'key', {
      get() {
        effects++;
        return 'private';
      },
    }),
  ])
    assert.throws(() => data(value, ['key']));
  for (const value of [
    '-invalid.example',
    'invalid..example',
    'host:443',
    '*.example',
    'a'.repeat(64) + '.example',
  ])
    assert.throws(() => hostname(value));
  for (const profiles of [
    { [Symbol()]: f.profiles.server },
    Object.defineProperty({}, 'server', {
      get() {
        effects++;
        return f.profiles.server;
      },
    }),
    Object.fromEntries(Array.from({ length: 65 }, (_, i) => [String(i), f.profiles.server])),
  ])
    assert.throws(() => captureSettings({ ...f.settings, profiles } as MtlsPluginSettings));
  assert.equal(effects, 0);
  assert.equal(f.loads(), 0);
});

test('mTLS real native mutual TLS preserves secure defaults when ALPN and explicit protocol minimum are omitted', async () => {
  const profiles = Object.fromEntries(
      Object.entries(f.profiles).map(([name, original]) => {
        const { minTlsVersion, alpnProtocols, ...rest } = original;
        void minTlsVersion;
        void alpnProtocols;
        return [name, { ...rest, allowedIdentities: ['127.0.0.1'] }];
      }),
    ),
    settings = captureSettings({
      ...f.settings,
      profiles,
      credentialProvider: {
        async load(profile, options) {
          const { ALPNProtocols, ...material } = await f.credentialProvider.load(profile, options);
          void ALPNProtocols;
          return material;
        },
      },
    }),
    managed = createService(settings),
    sockets = new Set<TLSSocket>();
  let client: TLSSocket | undefined;
  const policy = {
    trustRootsRef: 'fixture',
    allowedIdentities: ['127.0.0.1'],
    revocation: 'crl-required' as const,
  };
  await managed.bootstrap(new AbortController().signal);
  const server = createServer(
    managed.service.toNodeServerOptions(
      await managed.service.createServerOptions(profiles.server!),
    ),
    (socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      void managed.service.verifyPeer(socket.getPeerCertificate().raw, policy).then(
        () => {
          assert.equal(socket.authorized, true);
          assert.equal(socket.alpnProtocol, false);
          socket.end('verified');
        },
        (error: unknown) => socket.destroy(error as Error),
      );
    },
  );
  server.on('connection', (socket) => {
    sockets.add(socket as TLSSocket);
    socket.once('close', () => sockets.delete(socket as TLSSocket));
  });
  server.on('tlsClientError', () => {});
  try {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const native = managed.service.toNodeClientOptions(
      await managed.service.createClientOptions(profiles.client!, 'localhost'),
    );
    assert.equal(native.minVersion, 'TLSv1.3');
    assert.equal(native.ALPNProtocols, undefined);
    assert.equal(native.rejectUnauthorized, true);
    const result = await within(
      () =>
        new Promise<string>((resolve, reject) => {
          client = connect({ ...native, host: '127.0.0.1', port: address.port });
          client.once('error', reject);
          let body = '';
          client.on('data', (chunk: Buffer) => {
            body += chunk.toString();
          });
          client.once('end', () => resolve(body));
        }),
      { timeoutMs: 3000 },
    );
    assert.equal(result, 'verified');
    assert.equal(client?.authorized, true);
    const peer = new X509Certificate(f.materials.get('server')!.cert).raw;
    assert.ok(await managed.service.verifyPeer(peer, { ...policy, hostname: '127.0.0.1' }));
    await assert.rejects(
      managed.service.verifyPeer(peer, { ...policy, hostname: '127.0.0.2' }),
      code('EK_MTLS_INVALID_PEER'),
    );
    const dnsProfile: TlsProfile = { ...f.profiles.client!, allowedIdentities: ['localhost'] },
      dns = createService(captureSettings({ ...f.settings, profiles: { client: dnsProfile } }));
    try {
      await dns.bootstrap(new AbortController().signal);
      assert.ok(
        await dns.service.verifyPeer(peer, { ...policy, allowedIdentities: ['localhost'] }),
      );
    } finally {
      dns.close();
    }
  } finally {
    client?.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    managed.close();
  }
});

test('mTLS issued trust-root bytes cannot be changed before native conversion and rejected conversion preserves provider material', async () => {
  const managed = createService(captureSettings(f.settings)),
    original = Buffer.from(f.materials.get('client')!.ca[0]!);
  try {
    await managed.bootstrap(new AbortController().signal);
    const issued = await managed.service.createClientOptions(f.profiles.client!, 'localhost');
    issued.ca[0]!.fill(0);
    assert.throws(() => managed.service.toNodeClientOptions(issued), code('EK_MTLS_CONFIGURATION'));
    assert.deepEqual(f.materials.get('client')!.ca[0], original);
    const current = await managed.service.createClientOptions(f.profiles.client!, 'localhost');
    assert.equal(managed.service.toNodeClientOptions(current).rejectUnauthorized, true);
    await assert.rejects(
      managed.service.createClientOptions(
        { ...f.profiles.client!, certRef: 'unapproved' },
        'localhost',
      ),
      code('EK_MTLS_CONFIGURATION'),
    );
  } finally {
    managed.close();
  }
});

test('mTLS bounds the final native representation separately from its owned binary credential snapshot', async () => {
  const initial = captureSettings(f.settings),
    profile = [...initial.profiles.values()][0]!,
    material = captureMaterial(await f.credentialProvider.load(profile), profile, initial);
  const size = material.ca.reduce(
    (total, root) => total + root.length,
    material.cert.length + material.key.length,
  );
  clear(material);
  const managed = createService(
    captureSettings({
      ...f.settings,
      profiles: { server: f.profiles.server! },
      policy: { ...f.settings.policy, maxOutputBytes: size },
    }),
  );
  try {
    await managed.bootstrap(new AbortController().signal);
    const issued = await managed.service.createServerOptions(f.profiles.server!);
    assert.throws(() => managed.service.toNodeServerOptions(issued), code('EK_MTLS_CONFIGURATION'));
  } finally {
    managed.close();
  }
});

test('mTLS rejects aborted bootstrap and raw failures, retaining the native error classification without diagnostics', async () => {
  const runtime = createRuntime(captureSettings(f.settings)),
    aborted = new AbortController();
  aborted.abort();
  try {
    assert.throws(() => runtime.bootstrap(aborted.signal), code('EK_ABORTED'));
    await assert.rejects(
      runtime.run(undefined, async () => {
        throw new Error('Private native PKI diagnostic');
      }),
      (error: unknown) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_MTLS_INVALID_PEER');
        assert.equal(JSON.stringify(error).includes('Private native'), false);
        return true;
      },
    );
    for (const signal of [{}, Object.create(AbortSignal.prototype)])
      await assert.rejects(
        runtime.run({ signal } as never, async () => true),
        code('EK_MTLS_CONFIGURATION'),
      );
    runtime.close();
    runtime.close();
    await assert.rejects(
      runtime.run(undefined, async () => true),
      code('EK_RESOURCE_CLOSED'),
    );
  } finally {
    runtime.close();
  }
});

test('mTLS certificate snapshots reject excessive or noncanonical PEM, malformed fingerprints and non-byte input', () => {
  const pem = Buffer.from(f.materials.get('server')!.cert).toString();
  for (const [value, maximum] of [
    [pem, pem.length - 1],
    ['é', 1],
    ['not a certificate', 65536],
    [pem.replace('-----END CERTIFICATE-----', '=\n-----END CERTIFICATE-----'), 65536],
  ] as const)
    assert.throws(() => nativeCertificate(value, maximum), code('EK_MTLS_CONFIGURATION'));
  for (const value of [null, {}, 'bytes']) assert.throws(() => snapshot(value as never));
  for (const value of [null, '', 'x'.repeat(64), 'AA:BB']) assert.throws(() => fingerprint(value));
  const certificate = new X509Certificate(pem);
  assert.equal(
    fingerprint(certificate.fingerprint256),
    certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
  );
});

test('mTLS actual certificate chains accept PEM and DER leaves while rejecting unrelated or non-CA parents and excessive output', () => {
  const settings = captureSettings(f.settings),
    profile = [...settings.profiles.values()][0]!,
    source = f.materials.get('server')!,
    original = Buffer.from(source.key);
  for (const cert of [new X509Certificate(source.cert).raw, Buffer.concat([source.cert, f.root])]) {
    const material = captureMaterial({ ...source, cert }, profile, settings);
    assert.equal(material.leaf.fingerprint256, new X509Certificate(source.cert).fingerprint256);
    clear(material);
  }
  for (const cert of [
    Buffer.concat([source.cert, f.foreign]),
    Buffer.concat([source.cert, f.materials.get('client')!.cert]),
  ])
    assert.throws(
      () => captureMaterial({ ...source, cert }, profile, settings),
      code('EK_MTLS_CONFIGURATION'),
    );
  const maximum = Math.max(
    source.cert.length,
    ...source.ca.map((root) => root.length),
    source.key.length,
  );
  assert.throws(
    () => captureMaterial(source, profile, { ...settings, maxOutputBytes: maximum }),
    code('EK_MTLS_CONFIGURATION'),
  );
  assert.deepEqual(source.key, original);
});
