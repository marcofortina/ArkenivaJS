// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpReceiver } from 'node:http';
import { createTelemetry } from '@arkenivajs/telemetry';
import { X509Certificate } from 'node:crypto';
import { connect, createServer } from 'node:tls';
import type { ConnectionOptions, TLSSocket, TlsOptions } from 'node:tls';
import { COMPONENTS, createApplication, KitError } from '@arkenivajs/core';
import type { Application, OperationOptions, Plugin, Telemetry } from '@arkenivajs/core';
import { mtlsPlugin, MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import type {
  MtlsCredentialProvider,
  MtlsPluginSettings,
  MtlsService,
  MtlsTrustProvider,
  TlsMaterial,
  TlsProfile,
  TlsTrustVerificationPolicy,
  VerifiedPeerIdentity,
} from '@arkenivajs/security-mtls';
import { fixture } from '../fixture.js';
import { captureSettings } from '../../dist/settings.js';
import { createRuntime } from '../../dist/runtime.js';
import { alternativeNames, nativeCertificate, snapshot } from '../../dist/certificate.js';

const service = { name: 'mtls-test', version: '1.0.0', environment: 'test' } as const;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
let f: Awaited<ReturnType<typeof fixture>>;
before(async () => {
  f = await fixture();
});
after(async () => {
  await f?.close();
});
async function start(settings = f.settings) {
  const app = await createApplication({ service, plugins: [mtlsPlugin(settings)] });
  await app.start();
  return { app, mtls: app.resolve<MtlsService>(MTLS_CAPABILITY) };
}
function policy(role: 'client' | 'server'): TlsTrustVerificationPolicy {
  return {
    trustRootsRef: 'fixture',
    allowedIdentities: f.profiles[role]!.allowedIdentities,
    hostname: 'localhost',
    revocation: 'crl-required',
  };
}
const der = (name: string) => new X509Certificate(f.materials.get(name)!.cert).raw;
function identity(name = 'server'): VerifiedPeerIdentity {
  const certificate = new X509Certificate(f.materials.get(name)!.cert),
    known = f.certificates.get(certificate.fingerprint256)!;
  return {
    dnsSans: known.dnsSans,
    uriSans: known.uriSans,
    certificateFingerprintSha256: certificate.fingerprint256,
    issuer: certificate.issuer,
    notAfter: certificate.validToDate.toISOString(),
  };
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { release, promise };
}

test('EK-STD-SEC-008 actual Node TLS options authenticate both roles, negotiate ALPN and wait for asynchronous trust', async () => {
  const { app, mtls } = await start(),
    entered = gate(),
    allow = gate();
  const serverOptions: TlsOptions = mtls.toNodeServerOptions(
    await mtls.createServerOptions(f.profiles.server!),
  );
  const clientOptions: ConnectionOptions = mtls.toNodeClientOptions(
    await mtls.createClientOptions(f.profiles.client!, 'localhost'),
  );
  const sockets = new Set<TLSSocket>();
  let authorized = false,
    verification: Promise<void> | undefined;
  const server = createServer(serverOptions, (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    verification = (async () => {
      assert.equal(socket.authorized, true);
      assert.equal(socket.alpnProtocol, 'h2');
      entered.release();
      await allow.promise;
      const peer = await mtls.verifyPeer(socket.getPeerCertificate().raw, policy('server'));
      assert.deepEqual(peer.uriSans, ['spiffe://fixture/client']);
      authorized = true;
      socket.end('authorized');
    })().catch((error: unknown) => {
      socket.destroy();
      throw error;
    });
  });
  server.on('tlsClientError', () => {});
  let client: TLSSocket | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    client = connect({ ...clientOptions, host: '127.0.0.1', port: address.port, timeout: 3000 });
    client.once('timeout', () => client!.destroy(new Error('Disposable mutual TLS timed out')));
    await new Promise<void>((resolve, reject) => {
      client!.once('secureConnect', resolve);
      client!.once('error', reject);
    });
    assert.equal(client.authorized, true);
    assert.equal(client.alpnProtocol, 'h2');
    assert.equal(client.servername, 'localhost');
    assert.deepEqual(
      (await mtls.verifyPeer(client.getPeerCertificate().raw, policy('client'))).uriSans,
      ['spiffe://fixture/server'],
    );
    await entered.promise;
    assert.equal(authorized, false);
    const received: Buffer[] = [];
    client.on('data', (chunk: Buffer) => received.push(chunk));
    const ended = new Promise<void>((resolve, reject) => {
      client!.once('end', resolve);
      client!.once('error', reject);
    });
    allow.release();
    await ended;
    await verification;
    assert.equal(Buffer.concat(received).toString(), 'authorized');
  } finally {
    allow.release();
    client?.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await app.stop();
  }
});
test('EK-STD-SEC-008 forged material, wrong roles, modified key bytes and native insecure flags cannot be converted', async () => {
  const { app, mtls } = await start();
  try {
    const client = await mtls.createClientOptions(f.profiles.client!, 'localhost'),
      server = await mtls.createServerOptions(f.profiles.server!);
    assert.equal(mtls.toNodeClientOptions(client).rejectUnauthorized, true);
    assert.equal(mtls.toNodeServerOptions(server).requestCert, true);
    assert.throws(() => mtls.toNodeClientOptions({ ...client }), code('EK_MTLS_CONFIGURATION'));
    assert.throws(() => mtls.toNodeClientOptions(server as never), code('EK_MTLS_CONFIGURATION'));
    assert.throws(() => mtls.toNodeServerOptions(client as never), code('EK_MTLS_CONFIGURATION'));
    assert.throws(
      () => mtls.toNodeClientOptions({ ...client, rejectUnauthorized: false } as never),
      code('EK_MTLS_CONFIGURATION'),
    );
    client.key.fill(0);
    assert.throws(() => mtls.toNodeClientOptions(client), code('EK_MTLS_CONFIGURATION'));
    server.cert.fill(0);
    assert.throws(() => mtls.toNodeServerOptions(server), code('EK_MTLS_CONFIGURATION'));
    const ca = await mtls.createClientOptions(f.profiles.client!, 'localhost');
    ca.ca[0]!.fill(0);
    assert.throws(() => mtls.toNodeClientOptions(ca), code('EK_MTLS_CONFIGURATION'));
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 unapproved profiles, caller roots and weakened policies fail without secret retrieval', async () => {
  const { app, mtls } = await start();
  try {
    const before = f.loads(),
      profile = f.profiles.client!;
    for (const forged of [
      { ...profile, certRef: 'foreign' },
      { ...profile, keyRef: 'foreign' },
      { ...profile, allowedIdentities: [] },
      { ...profile, revocation: undefined },
      { ...profile, minTlsVersion: 'TLSv1' },
      { ...profile, unexpected: true },
    ])
      await assert.rejects(
        mtls.createClientOptions(forged as TlsProfile, 'localhost'),
        code('EK_MTLS_CONFIGURATION'),
      );
    await assert.rejects(
      mtls.createClientOptions(profile, 'bad\nname'),
      code('EK_MTLS_CONFIGURATION'),
    );
    assert.equal(f.loads(), before);
    const calls = f.verifications();
    for (const forged of [
      { ...policy('client'), trustRootsRef: 'foreign' },
      { ...policy('client'), allowedIdentities: ['spiffe://foreign/server'] },
      { ...policy('client'), revocation: 'approved-online-checker' },
      { ...policy('client'), hostname: 'foreign.invalid' },
    ])
      await assert.rejects(
        mtls.verifyPeer(der('server'), forged as TlsTrustVerificationPolicy),
        code('EK_MTLS_INVALID_PEER'),
      );
    await assert.rejects(
      mtls.verifyPeer(der('client'), policy('client')),
      code('EK_MTLS_INVALID_PEER'),
    );
    assert.equal(f.verifications(), calls);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 expired, future, CN-only and malformed peer certificates never reach authorization', async () => {
  const { app, mtls } = await start();
  try {
    const before = f.verifications();
    for (const input of [
      der('expired'),
      der('future'),
      der('cn'),
      Buffer.alloc(0),
      Buffer.alloc(65537),
      new Uint8Array(new SharedArrayBuffer(100)),
    ])
      await assert.rejects(mtls.verifyPeer(input, policy('client')), code('EK_MTLS_INVALID_PEER'));
    assert.equal(f.verifications(), before);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 trust-provider outage or unbound success cannot authenticate another certificate', async () => {
  let response: unknown = identity();
  const trustProvider: MtlsTrustProvider = {
    async verifyChainAndRevocation() {
      if (response instanceof Error) throw response;
      return response as VerifiedPeerIdentity;
    },
  };
  const { app, mtls } = await start({ ...f.settings, trustProvider });
  try {
    for (response of [
      new Error('private provider diagnostic'),
      null,
      {},
      { ...identity(), certificateFingerprintSha256: '00'.repeat(32) },
      { ...identity(), issuer: 'foreign' },
      { ...identity(), notAfter: new Date().toISOString() },
      { ...identity(), dnsSans: ['foreign'] },
      { ...identity(), uriSans: [] },
      { ...identity(), unexpected: true },
    ])
      await assert.rejects(mtls.verifyPeer(der('server'), policy('client')), (error) => {
        assert.ok(code('EK_MTLS_INVALID_PEER')(error));
        assert.ok(error instanceof KitError);
        assert.equal(error.cause, undefined);
        assert.equal(error.message.includes('private'), false);
        return true;
      });
    response = identity();
    assert.deepEqual((await mtls.verifyPeer(der('server'), policy('client'))).uriSans, [
      'spiffe://fixture/server',
    ]);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 reload publishes an entire new generation and invalidates previously issued conversion material', async () => {
  const { app, mtls } = await start(),
    original = f.materials.get('server')!;
  try {
    const old = await mtls.createServerOptions(f.profiles.server!),
      before = mtls.toNodeServerOptions(old).cert;
    f.materials.set('server', f.materials.get('rotated')!);
    await mtls.reloadCertificates();
    assert.throws(() => mtls.toNodeServerOptions(old), code('EK_MTLS_CONFIGURATION'));
    const current = mtls.toNodeServerOptions(await mtls.createServerOptions(f.profiles.server!));
    assert.notEqual(current.cert, before);
    assert.equal(
      new X509Certificate(current.cert).fingerprint256,
      new X509Certificate(f.materials.get('rotated')!.cert).fingerprint256,
    );
  } finally {
    f.materials.set('server', original);
    await app.stop();
  }
});
test('EK-STD-SEC-008 failed reload preserves both previous profiles and does not clear provider-owned keys', async () => {
  const { app, mtls } = await start(),
    original = f.materials.get('client')!,
    server = f.materials.get('server')!;
  const originalBytes = Buffer.from(original.key);
  try {
    const old = await mtls.createServerOptions(f.profiles.server!),
      native = mtls.toNodeServerOptions(old);
    f.materials.set('server', f.materials.get('rotated')!);
    f.materials.set('client', { ...original, key: f.materials.get('rotated')!.key });
    await assert.rejects(mtls.reloadCertificates(), code('EK_MTLS_CONFIGURATION'));
    assert.equal(mtls.toNodeServerOptions(old).cert, native.cert);
    assert.equal(
      mtls.toNodeServerOptions(await mtls.createServerOptions(f.profiles.server!)).cert,
      native.cert,
    );
    assert.deepEqual(original.key, originalBytes);
  } finally {
    f.materials.set('server', server);
    f.materials.set('client', original);
    await app.stop();
  }
});
test('EK-STD-SEC-008 unavailable, mismatched, expired or unsupported credential snapshots prevent readiness', async () => {
  const original = f.materials.get('server')!;
  for (const value of [
    { ...original, ca: [] },
    { ...original, ca: [f.foreign] },
    { ...original, key: f.materials.get('client')!.key },
    f.materials.get('expired')!,
    f.materials.get('future')!,
    { ...original, minVersion: 'TLSv1.2' },
    { ...original, ALPNProtocols: ['foreign'] },
    { ...original, unexpected: true },
    { ...original, key: Buffer.alloc(1) },
  ]) {
    const credentialProvider: MtlsCredentialProvider = {
      async load() {
        return value as TlsMaterial;
      },
    };
    const app = await createApplication({
      service,
      plugins: [mtlsPlugin({ ...f.settings, credentialProvider })],
    });
    await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
    assert.equal(app.state, 'CLOSED');
    await app.stop();
  }
  const unavailable: MtlsCredentialProvider = {
    async load() {
      throw new Error('Private backend diagnostic');
    },
  };
  const app = await createApplication({
    service,
    plugins: [mtlsPlugin({ ...f.settings, credentialProvider: unavailable })],
  });
  await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
  await app.stop();
});
test('EK-STD-SEC-008 explicit certificate purposes are enforced before creating material for either role', async () => {
  const server = f.materials.get('server')!,
    client = f.materials.get('client')!;
  f.materials.set('server', f.materials.get('client-only')!);
  f.materials.set('client', f.materials.get('server-only')!);
  const { app, mtls } = await start();
  try {
    await assert.rejects(
      mtls.createServerOptions(f.profiles.server!),
      code('EK_MTLS_CONFIGURATION'),
    );
    await assert.rejects(
      mtls.createClientOptions(f.profiles.client!, 'localhost'),
      code('EK_MTLS_CONFIGURATION'),
    );
  } finally {
    f.materials.set('server', server);
    f.materials.set('client', client);
    await app.stop();
  }
});
test('EK-STD-SEC-008 provider hangs retain slots after timeout and cannot publish late trust', async () => {
  const entered = gate(),
    release = gate();
  let signal: AbortSignal | undefined;
  const trustProvider: MtlsTrustProvider = {
    async verifyChainAndRevocation(_input, options) {
      signal = options?.signal;
      entered.release();
      await release.promise;
      return identity();
    },
  };
  const { app, mtls } = await start({
    ...f.settings,
    trustProvider,
    policy: { maxConcurrent: 1, timeoutMs: 3000 },
  });
  try {
    const pending = mtls.verifyPeer(der('server'), policy('client'), { timeoutMs: 20 });
    await entered.promise;
    await assert.rejects(pending, code('EK_TIMEOUT'));
    assert.equal(signal?.aborted, true);
    await assert.rejects(
      mtls.createServerOptions(f.profiles.server!),
      code('EK_BACKEND_UNAVAILABLE'),
    );
    release.release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(
      (await mtls.verifyPeer(der('server'), policy('client'))).issuer,
      identity().issuer,
    );
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-008 invalid deadlines, aborted calls and closed handles cannot produce credentials', async () => {
  const { app, mtls } = await start();
  try {
    const options = await mtls.createClientOptions(f.profiles.client!, 'localhost'),
      controller = new AbortController();
    controller.abort();
    const operations = [
      (input?: OperationOptions) =>
        mtls.createClientOptions(f.profiles.client!, 'localhost', input),
      (input?: OperationOptions) => mtls.createServerOptions(f.profiles.server!, input),
      (input?: OperationOptions) => mtls.verifyPeer(der('server'), policy('client'), input),
      (input?: OperationOptions) => mtls.reloadCertificates(input),
    ];
    for (const operation of operations) {
      await assert.rejects(operation({ timeoutMs: 0 }), code('EK_MTLS_CONFIGURATION'));
      await assert.rejects(operation({ signal: controller.signal }), code('EK_ABORTED'));
    }
    await app.stop();
    for (const operation of operations)
      await assert.rejects(operation(), code('EK_RESOURCE_CLOSED'));
    assert.throws(() => mtls.toNodeClientOptions(options), code('EK_RESOURCE_CLOSED'));
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 reused plugin factories isolate applications and reject test-only providers outside test', async () => {
  const plugin = mtlsPlugin(f.settings),
    apps: Application[] = [];
  try {
    for (let index = 0; index < 2; index++) {
      const app = await createApplication({ service, plugins: [plugin] });
      await app.start();
      apps.push(app);
    }
    await apps[0]!.stop();
    assert.ok(
      await apps[1]!.resolve<MtlsService>(MTLS_CAPABILITY).createServerOptions(f.profiles.server!),
    );
  } finally {
    await Promise.all(apps.map((app) => app.stop()));
  }
  for (const environment of ['production', 'development'] as const) {
    const app = await createApplication({
      service: { ...service, environment },
      plugins: [plugin],
    });
    await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
    await app.stop();
  }
  await assert.rejects(
    createApplication({ service, plugins: [plugin, plugin] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
});
test('EK-STD-SEC-008 native TLS rejects foreign CAs, hostname mismatch, ALPN mismatch and absent client credentials', async () => {
  const { app, mtls } = await start();
  try {
    const serverOptions = mtls.toNodeServerOptions(
      await mtls.createServerOptions(f.profiles.server!),
    );
    const clientOptions = mtls.toNodeClientOptions(
      await mtls.createClientOptions(f.profiles.client!, 'localhost'),
    );
    for (const variant of [
      { ...clientOptions, ca: [f.foreign] },
      { ...clientOptions, servername: 'foreign.invalid' },
      { ...clientOptions, ALPNProtocols: ['http/1.1'] },
      { ...clientOptions, cert: undefined, key: undefined },
    ]) {
      let accepted = 0;
      const sockets = new Set<TLSSocket>();
      const server = createServer(serverOptions, (socket) => {
        accepted++;
        socket.destroy();
      });
      server.on('tlsClientError', () => {});
      server.on('connection', (socket) => {
        sockets.add(socket as TLSSocket);
        socket.once('close', () => sockets.delete(socket as TLSSocket));
      });
      let client: TLSSocket | undefined;
      try {
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        const address = server.address();
        assert.ok(address && typeof address !== 'string');
        await assert.rejects(
          new Promise<void>((resolve, reject) => {
            client = connect({
              ...variant,
              host: '127.0.0.1',
              port: address.port,
              timeout: 1000,
            } as ConnectionOptions);
            client.once('timeout', () =>
              client!.destroy(new Error('Disposable negative TLS timed out')),
            );
            client.once('error', reject);
            client.once('close', () =>
              accepted ? resolve() : reject(new Error('Native TLS rejected the peer')),
            );
          }),
        );
        assert.equal(accepted, 0);
      } finally {
        client?.destroy();
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 construction rejects unknown fields, unsafe limits and unverified provider methods without getters', () => {
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Private accessor diagnostic');
  };
  const source = f.profiles.server!;
  for (const input of [
    null,
    {},
    { ...f.settings, extra: true },
    { ...f.settings, reloadMode: 'automatic' },
    { ...f.settings, profiles: {} },
    { ...f.settings, profiles: [] },
    { ...f.settings, profiles: { one: source, two: source } },
    { ...f.settings, trustProvider: {} },
    { ...f.settings, trustProvider: null },
    { ...f.settings, credentialProvider: Object.defineProperty({}, 'load', { get: accessor }) },
    { ...f.settings, trustProvider: { ...f.trustProvider, usage: 'unknown' } },
    {
      ...f.settings,
      trustProvider: Object.defineProperty({ ...f.trustProvider }, 'usage', { get: accessor }),
    },
    ...[0, -1, 1.5, 1025, NaN, Infinity].map((maxConcurrent) => ({
      ...f.settings,
      policy: { ...f.settings.policy, maxConcurrent },
    })),
    ...[0, 120001].map((timeoutMs) => ({
      ...f.settings,
      policy: { ...f.settings.policy, timeoutMs },
    })),
    { ...f.settings, policy: { maxConcurrent: 129, timeoutMs: 1 } },
    { ...f.settings, policy: { ...f.settings.policy, maxInputBytes: 1048577 } },
    { ...f.settings, policy: { ...f.settings.policy, maxOutputBytes: 0 } },
    ...[
      { ...source, allowedIdentities: [] },
      { ...source, allowedIdentities: ['a', 'a'] },
      { ...source, allowedIdentities: ['spiffe:///missing-domain'] },
      { ...source, allowedIdentities: ['spiffe://fixture/service?query'] },
      { ...source, allowedIdentities: ['https://user:password@fixture.invalid/'] },
      { ...source, minTlsVersion: 'TLSv1' },
      { ...source, revocation: 'none' },
      { ...source, alpnProtocols: [] },
      { ...source, alpnProtocols: ['x'.repeat(256)] },
      { ...source, alpnProtocols: ['bad protocol'] },
      { ...source, certRef: '' },
      { ...source, unexpected: true },
    ].map((profile) => ({ ...f.settings, profiles: { one: profile } })),
  ])
    assert.throws(() => mtlsPlugin(input as MtlsPluginSettings), code('EK_MTLS_CONFIGURATION'));
  const inherited = Object.create(f.credentialProvider) as MtlsCredentialProvider;
  assert.ok(mtlsPlugin({ ...f.settings, credentialProvider: inherited }));
  assert.equal(invoked, 0);
});
test('EK-STD-SEC-008 credential material is bounded and DER private keys retain native interoperability', async () => {
  const source = f.materials.get('server')!;
  for (const value of [
    { ...source, ca: [source.cert] },
    { ...source, ca: [f.root, f.root] },
    { ...source, cert: Buffer.from('not a certificate') },
    { ...source, key: new Uint8Array(new SharedArrayBuffer(100)) },
    { ...source, cert: Buffer.alloc(1048577) },
  ]) {
    const credentialProvider: MtlsCredentialProvider = {
      async load() {
        return value;
      },
    };
    const app = await createApplication({
      service,
      plugins: [mtlsPlugin({ ...f.settings, credentialProvider })],
    });
    await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
    await app.stop();
  }
  const { app, mtls } = await start({
    ...f.settings,
    policy: { ...f.settings.policy, maxOutputBytes: 4096 },
  });
  try {
    const created = await mtls.createServerOptions(f.profiles.server!);
    assert.ok(mtls.toNodeServerOptions(created).key.length > 0);
    assert.equal(
      nativeCertificate(new X509Certificate(source.cert).raw).fingerprint256,
      new X509Certificate(source.cert).fingerprint256,
    );
  } finally {
    await app.stop();
  }
  const credentialProvider: MtlsCredentialProvider = {
    async load(profile) {
      const value = await f.credentialProvider.load(profile);
      return {
        ...value,
        key: (await import('node:crypto'))
          .createPrivateKey(value.key as Buffer)
          .export({ format: 'der', type: 'pkcs8' }),
      };
    },
  };
  const derKeys = await start({ ...f.settings, credentialProvider });
  try {
    assert.ok(
      derKeys.mtls
        .toNodeClientOptions(
          await derKeys.mtls.createClientOptions(f.profiles.client!, 'localhost'),
        )
        .key.includes('PRIVATE KEY'),
    );
  } finally {
    await derKeys.app.stop();
  }
});
test('EK-STD-SEC-008 reload timeout and overlapping reload cannot replace the previous valid generation', async () => {
  let hanging = false;
  const entered = gate(),
    release = gate();
  const credentialProvider: MtlsCredentialProvider = {
    async load(profile) {
      if (hanging) {
        entered.release();
        await release.promise;
      }
      return f.credentialProvider.load(profile);
    },
  };
  const { app, mtls } = await start({
    ...f.settings,
    credentialProvider,
    policy: { maxConcurrent: 1, timeoutMs: 3000 },
  });
  try {
    const old = await mtls.createServerOptions(f.profiles.server!),
      before = mtls.toNodeServerOptions(old).cert;
    hanging = true;
    const pending = mtls.reloadCertificates({ timeoutMs: 20 });
    await entered.promise;
    await assert.rejects(mtls.reloadCertificates(), code('EK_BACKEND_UNAVAILABLE'));
    await assert.rejects(pending, code('EK_TIMEOUT'));
    assert.equal(mtls.toNodeServerOptions(old).cert, before);
    await assert.rejects(
      mtls.createServerOptions(f.profiles.server!),
      code('EK_BACKEND_UNAVAILABLE'),
    );
    release.release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    hanging = false;
    assert.equal(mtls.toNodeServerOptions(old).cert, before);
    assert.equal(
      mtls.toNodeServerOptions(await mtls.createServerOptions(f.profiles.server!)).cert,
      before,
    );
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-008 accessor input, malformed signals and runtime clock overrides cannot bypass validation', async () => {
  const { app, mtls } = await start();
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Private accessor diagnostic');
  };
  try {
    const options = Object.defineProperty({}, 'timeoutMs', { get: accessor, enumerable: true });
    const controller = new AbortController();
    Object.defineProperty(controller.signal, 'aborted', { get: accessor });
    for (const value of [
      options,
      { signal: {} },
      { signal: controller.signal },
      { timeoutMs: 3001 },
      { now: 0 },
    ])
      await assert.rejects(
        mtls.createServerOptions(f.profiles.server!, value as OperationOptions),
        code('EK_MTLS_CONFIGURATION'),
      );
    const input = Object.defineProperty({}, 'allowedIdentities', {
      get: accessor,
      enumerable: true,
    });
    await assert.rejects(
      mtls.verifyPeer(der('server'), input as TlsTrustVerificationPolicy),
      code('EK_MTLS_INVALID_PEER'),
    );
    assert.equal(invoked, 0);
    const entered = gate(),
      release = gate();
    const trustProvider: MtlsTrustProvider = {
      async verifyChainAndRevocation(_input, operation) {
        entered.release();
        await release.promise;
        assert.equal(operation?.signal?.aborted, true);
        return identity();
      },
    };
    const active = await start({ ...f.settings, trustProvider });
    try {
      const controller = new AbortController(),
        pending = active.mtls.verifyPeer(der('server'), policy('client'), {
          signal: controller.signal,
        });
      const rejected = assert.rejects(pending, code('EK_ABORTED'));
      await entered.promise;
      controller.abort();
      await rejected;
      release.release();
    } finally {
      release.release();
      await active.app.stop();
    }
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 bounded SAN decoding rejects spoofed DNS entries, malformed JSON and trailing certificate bytes', () => {
  assert.deepEqual(alternativeNames(undefined), { dnsSans: [], uriSans: [] });
  assert.deepEqual(
    alternativeNames('URI:"spiffe://fixture/path, DNS:evil.invalid", DNS:localhost'),
    { dnsSans: ['localhost'], uriSans: ['spiffe://fixture/path, DNS:evil.invalid'] },
  );
  for (const value of [
    'URI:"unterminated',
    'DNS:',
    'URI:"\\n"',
    'missing-colon',
    'URI:"valid"junk',
    'DNS:' + 'x'.repeat(2049),
    'x'.repeat(65537),
    Array(257).fill('DNS:a').join(', '),
  ])
    assert.throws(() => alternativeNames(value), code('EK_MTLS_CONFIGURATION'));
  assert.throws(() => snapshot(Buffer.alloc(0)), code('EK_MTLS_CONFIGURATION'));
  assert.throws(
    () => nativeCertificate(Buffer.concat([der('server'), Buffer.from([0])])),
    code('EK_MTLS_CONFIGURATION'),
  );
});
test('EK-STD-SEC-008 diagnostics observe only fixed status classes and cannot authorize an untrusted peer', async () => {
  const events: unknown[] = [];
  let broken = false;
  const record = (...values: unknown[]) => {
    if (broken) throw new Error('Private telemetry diagnostic');
    events.push(values);
  };
  const telemetry: Telemetry = {
    async measure(_name, work) {
      return work();
    },
    async withSpan(name, work, options) {
      if (broken) throw new Error('Private trace diagnostic');
      record(name, options);
      return work();
    },
    addCounter: record,
    recordHistogram: record,
    setGauge: record,
    async flush() {},
  };
  const observer: Plugin = {
    id: 'mtls-test-telemetry',
    version: '1.0.0',
    capabilities: new Set(['telemetry']),
    init(context) {
      context.provide(COMPONENTS.telemetry, telemetry);
    },
    close() {},
  };
  const app = await createApplication({ service, plugins: [mtlsPlugin(f.settings), observer] });
  await app.start();
  try {
    const mtls = app.resolve<MtlsService>(MTLS_CAPABILITY);
    assert.ok(await mtls.verifyPeer(der('server'), policy('client')));
    const serialized = JSON.stringify(events);
    for (const value of [
      'localhost',
      'spiffe',
      identity().issuer,
      identity().certificateFingerprintSha256,
    ])
      assert.equal(serialized.includes(value), false);
    broken = true;
    assert.ok(await mtls.verifyPeer(der('server'), policy('client')));
    await assert.rejects(
      mtls.verifyPeer(der('client'), policy('client')),
      code('EK_MTLS_INVALID_PEER'),
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-008 shutdown cancels pending verification and bootstrap timeout never permits readiness', async () => {
  const entered = gate(),
    release = gate();
  let providerSignal: AbortSignal | undefined;
  const trustProvider: MtlsTrustProvider = {
    async verifyChainAndRevocation(_input, options) {
      providerSignal = options?.signal;
      entered.release();
      await release.promise;
      return identity();
    },
  };
  const { app, mtls } = await start({ ...f.settings, trustProvider });
  try {
    const retained = await mtls.createServerOptions(f.profiles.server!),
      pending = mtls.verifyPeer(der('server'), policy('client'));
    const rejected = assert.rejects(
      pending,
      (error) => code('EK_ABORTED')(error) || code('EK_RESOURCE_CLOSED')(error),
    );
    await entered.promise;
    await app.stop();
    await rejected;
    assert.equal(providerSignal?.aborted, true);
    assert.throws(() => mtls.toNodeServerOptions(retained), code('EK_RESOURCE_CLOSED'));
  } finally {
    release.release();
    await app.stop();
  }
  const held = gate();
  let signal: AbortSignal | undefined;
  const credentialProvider: MtlsCredentialProvider = {
    async load(profile, options) {
      signal = options?.signal;
      await held.promise;
      return f.credentialProvider.load(profile);
    },
  };
  const startup = await createApplication({
    service,
    plugins: [
      mtlsPlugin({
        ...f.settings,
        credentialProvider,
        policy: { maxConcurrent: 1, timeoutMs: 20 },
      }),
    ],
  });
  try {
    await assert.rejects(startup.start(), code('EK_PLUGIN_FAILED'));
    assert.equal(startup.state, 'CLOSED');
    assert.equal(signal?.aborted, true);
  } finally {
    held.release();
    await startup.stop();
  }
});
test('EK-STD-SEC-008 native rotation preserves an authenticated connection while parallel new handshakes use the new certificate', async () => {
  const { app, mtls } = await start(),
    original = f.materials.get('server')!;
  const sockets = new Set<TLSSocket>(),
    clients = new Set<TLSSocket>(),
    validations: Promise<void>[] = [];
  const server = createServer(
    mtls.toNodeServerOptions(await mtls.createServerOptions(f.profiles.server!)),
    (socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      socket.once('close', () => sockets.delete(socket));
      const verified = mtls
        .verifyPeer(socket.getPeerCertificate().raw, policy('server'))
        .then(() => {
          socket.on('data', (chunk: Buffer) => socket.write(chunk));
        });
      validations.push(verified);
      void verified.catch(() => socket.destroy());
    },
  );
  server.on('tlsClientError', () => {});
  let port = 0;
  const open = async () => {
    const options = mtls.toNodeClientOptions(
      await mtls.createClientOptions(f.profiles.client!, 'localhost'),
    );
    const client = connect({ ...options, host: '127.0.0.1', port, timeout: 2000 });
    clients.add(client);
    client.on('error', () => {});
    client.once('timeout', () =>
      client.destroy(new Error('Disposable rotation connection timed out')),
    );
    await new Promise<void>((resolve, reject) => {
      client.once('secureConnect', resolve);
      client.once('error', reject);
    });
    await mtls.verifyPeer(client.getPeerCertificate().raw, policy('client'));
    return client;
  };
  try {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    port = address.port;
    const first = await open(),
      previous = new X509Certificate(first.getPeerCertificate().raw).fingerprint256;
    f.materials.set('server', f.materials.get('rotated')!);
    await mtls.reloadCertificates();
    server.setSecureContext(
      mtls.toNodeServerOptions(await mtls.createServerOptions(f.profiles.server!)),
    );
    const connections = await Promise.all([open(), open()]);
    for (const client of connections) {
      assert.equal(
        new X509Certificate(client.getPeerCertificate().raw).fingerprint256,
        new X509Certificate(f.materials.get('rotated')!.cert).fingerprint256,
      );
      assert.equal(client.authorized, true);
      assert.equal(client.alpnProtocol, 'h2');
    }
    assert.notEqual(
      previous,
      new X509Certificate(connections[0]!.getPeerCertificate().raw).fingerprint256,
    );
    assert.equal(new X509Certificate(first.getPeerCertificate().raw).fingerprint256, previous);
    await Promise.all(validations);
    const response = new Promise<Buffer>((resolve, reject) => {
      first.once('data', resolve);
      first.once('error', reject);
    });
    first.write('still-authorized');
    assert.equal((await response).toString(), 'still-authorized');
  } finally {
    f.materials.set('server', original);
    for (const socket of [...clients, ...sockets]) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await app.stop();
  }
});
test('EK-STD-SEC-008 the actual telemetry SDK exports certificate diagnostics without custom labels, drops or private metadata', async () => {
  const bodies: unknown[] = [];
  let totalBytes = 0;
  const receiver = createHttpReceiver((request, response) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    request.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      totalBytes += chunk.length;
      if (bytes > 1048576 || totalBytes > 4194304) request.destroy();
      else chunks.push(chunk);
    });
    request.once('end', () => {
      try {
        bodies.push(JSON.parse(Buffer.concat(chunks).toString()) as unknown);
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end('{}');
      } catch {
        response.writeHead(400);
        response.end();
      }
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const address = receiver.address();
  assert.ok(address && typeof address !== 'string');
  const telemetry = createTelemetry({
    service,
    mode: 'detailed',
    samplingRatio: 1,
    endpoint: 'http://127.0.0.1:' + address.port,
    allowInsecureLoopback: true,
    exportIntervalMs: 1000,
    exportTimeoutMs: 1000,
  });
  const observer: Plugin = {
    id: 'certificate-sdk-observer',
    version: '1.0.0',
    capabilities: new Set(['telemetry']),
    init(context) {
      context.provide(COMPONENTS.telemetry, telemetry);
    },
    close() {},
  };
  const app = await createApplication({ service, plugins: [mtlsPlugin(f.settings), observer] });
  try {
    await app.start();
    const adapter = app.resolve<MtlsService>(MTLS_CAPABILITY);
    assert.ok(await adapter.verifyPeer(der('server'), policy('client')));
    await assert.rejects(
      adapter.verifyPeer(der('client'), policy('client')),
      code('EK_MTLS_INVALID_PEER'),
    );
    await telemetry.flush();
    assert.equal(telemetry.stats().droppedMetrics, 0);
    assert.equal(telemetry.stats().droppedSpans, 0);
    assert.equal(telemetry.stats().exportFailures, 0);
    const objects: Record<string, unknown>[] = [];
    const visit = (value: unknown): void => {
      if (!value || typeof value !== 'object') return;
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      objects.push(value as Record<string, unknown>);
      Object.values(value).forEach(visit);
    };
    bodies.forEach(visit);
    assert.ok(objects.some((value) => value.name === 'mtls.verify_peer'));
    assert.ok(
      objects.some(
        (value) => value.name === 'mtls.verification.duration_ms' && value.unit === 'ms',
      ),
    );
    assert.ok(objects.some((value) => value.name === 'mtls.verification.completed.trusted'));
    const serialized = JSON.stringify(bodies);
    for (const privateValue of [
      'localhost',
      'spiffe',
      identity().issuer,
      identity().certificateFingerprintSha256,
    ])
      assert.equal(serialized.includes(privateValue), false);
  } finally {
    try {
      await app.stop();
      await telemetry.close();
    } finally {
      receiver.closeAllConnections();
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
    }
  }
});
test('EK-STD-SEC-008 actual CRL revocation and provider outage prevent application peer authorization', async () => {
  const { app, mtls } = await start();
  try {
    assert.ok(await mtls.verifyPeer(der('server'), policy('client')));
    f.unavailable(true);
    await assert.rejects(
      mtls.verifyPeer(der('server'), policy('client')),
      code('EK_MTLS_INVALID_PEER'),
    );
    f.unavailable(false);
    await f.revoke('server');
    await assert.rejects(
      mtls.verifyPeer(der('server'), policy('client')),
      code('EK_MTLS_INVALID_PEER'),
    );
    assert.ok(await mtls.verifyPeer(der('client'), policy('server')));
  } finally {
    f.unavailable(false);
    await app.stop();
  }
});

test('EK-STD-SEC-008 internal admission rejects unpreemptible late results and clears discarded material', async () => {
  const runtime = createRuntime(captureSettings(f.settings));
  let cleared = false;
  try {
    await assert.rejects(
      runtime.run(
        { timeoutMs: 5 },
        async () => {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
          return true;
        },
        () => {
          cleared = true;
        },
      ),
      code('EK_TIMEOUT'),
    );
    assert.equal(cleared, true);
  } finally {
    runtime.close();
  }
});
