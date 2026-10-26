// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpReceiver } from 'node:http';
import { createTelemetry } from '@arkenivajs/telemetry';
import { createHash, X509Certificate } from 'node:crypto';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application, OperationOptions, Plugin, Telemetry } from '@arkenivajs/core';
import { COMPONENTS } from '@arkenivajs/core';
import { X509_CAPABILITY, x509Plugin } from '@arkenivajs/security-x509';
import type {
  MtlsTrustProvider,
  VerifiedPeerIdentity,
  X509Info,
  X509PluginSettings,
  X509Service,
} from '@arkenivajs/security-x509';
import fc from 'fast-check';
import { fixture } from '../fixture.js';
import { alternativeNames, fingerprint } from '../../dist/certificate.js';
import { captureSettings, createRuntime } from '../../dist/runtime.js';

const service = { name: 'x509-test', version: '1.0.0', environment: 'test' } as const;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
let f: Awaited<ReturnType<typeof fixture>>;
before(async () => {
  f = await fixture();
});
after(async () => {
  await f?.close();
});
const trust = () => ({
  trustRoots: f.roots,
  expectedHostname: 'localhost',
  requireRevocationCheck: true,
});
async function start(settings = f.settings) {
  const app = await createApplication({ service, plugins: [x509Plugin(settings)] });
  await app.start();
  return { app, x509: app.resolve<X509Service>(X509_CAPABILITY) };
}
function identity(): VerifiedPeerIdentity {
  const certificate = new X509Certificate(f.chain[0]!);
  return {
    dnsSans: ['localhost'],
    uriSans: ['spiffe://fixture/service', 'https://fixture.invalid/path, DNS:forged.invalid'],
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

test('EK-STD-SEC-012 parses exactly one PEM or DER certificate with immutable privacy-sensitive metadata', async () => {
  const { app, x509 } = await start();
  try {
    const info = x509.parse(f.pem),
      pem = x509.parse(f.pem.toString());
    assert.deepEqual(info, pem);
    assert.deepEqual(info, x509.parse(f.chain[0]!));
    assert.equal(info.publicKeyAlgorithm, 'ec');
    assert.deepEqual(info.dnsSans, ['localhost']);
    assert.deepEqual(info.uriSans, [
      'spiffe://fixture/service',
      'https://fixture.invalid/path, DNS:forged.invalid',
    ]);
    assert.ok(
      Object.isFrozen(info) && Object.isFrozen(info.dnsSans) && Object.isFrozen(info.uriSans),
    );
    assert.deepEqual(x509.getFingerprints(info), {
      sha256: createHash('sha256').update(f.chain[0]!).digest('hex'),
      sha512: createHash('sha512').update(f.chain[0]!).digest('hex'),
    });
    assert.deepEqual(x509.getFingerprints({ ...info }), { sha256: info.fingerprintSha256 });
    assert.ok(x509.parse(f.expired).notAfter < new Date().toISOString());
    assert.deepEqual(x509.parse(f.cn).dnsSans, []);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 native TLS validates the complete intermediate chain and both actual CRLs', async () => {
  const { app, x509 } = await start();
  try {
    const before = f.calls();
    for (const expectedHostname of ['localhost', '127.0.0.1']) {
      assert.equal(
        (await x509.inspectChain(f.chain, { ...trust(), expectedHostname })).status,
        'trusted',
      );
    }
    assert.equal(
      (
        await x509.inspectChain([...f.chain, f.roots[0]!], {
          trustRoots: f.roots,
          requireRevocationCheck: false,
        })
      ).status,
      'trusted',
    );
    assert.equal(f.calls() - before, 3);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 chain linkage, exact CA sets, hostname, CN fallback and cycles cannot establish trust', async () => {
  const { app, x509 } = await start();
  try {
    const before = f.calls();
    for (const [chain, policy] of [
      [f.chain, { ...trust(), trustRoots: [f.foreign] }],
      [[f.chain[0]!], trust()],
      [[f.chain[0]!, f.foreign], trust()],
      [[...f.chain, f.chain[0]!], trust()],
      [[f.roots[0]!, f.roots[0]!], trust()],
      [f.chain, { ...trust(), expectedHostname: 'forged.invalid' }],
      [f.chain, { ...trust(), expectedHostname: '127.0.0.2' }],
      [[f.cn, f.chain[1]!], trust()],
    ] as const)
      assert.equal((await x509.inspectChain(chain, policy)).status, 'untrusted');
    assert.equal(f.calls(), before);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 expired and not-yet-valid certificates fail before external verification', async () => {
  const { app, x509 } = await start();
  try {
    const before = f.calls();
    assert.equal((await x509.inspectChain([f.expired, f.chain[1]!], trust())).status, 'expired');
    assert.equal((await x509.inspectChain([f.future, f.chain[1]!], trust())).status, 'untrusted');
    assert.equal(f.calls(), before);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 expiration arithmetic has deterministic explicit instants and rejects invalid dates', async () => {
  const { app, x509 } = await start();
  try {
    const info = x509.parse(f.pem),
      expires = Date.parse(info.notAfter);
    assert.equal(x509.daysUntilExpiry(info, new Date(expires - 2.5 * 86400000).toISOString()), 2);
    assert.equal(x509.daysUntilExpiry(info, new Date(expires + 1).toISOString()), -1);
    assert.equal(x509.daysUntilExpiry(info), Math.floor((expires - Date.now()) / 86400000));
    for (const at of ['invalid', '2026-02-30T00:00:00.000Z', '2026-01-01'])
      assert.throws(() => x509.daysUntilExpiry(info, at), code('EK_X509_PARSE'));
    assert.throws(
      () => x509.getFingerprints({ ...info, fingerprintSha256: 'not-a-digest' }),
      code('EK_X509_PARSE'),
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 malformed, multiple, excessive and shared certificate inputs fail with safe errors', async () => {
  const { app, x509 } = await start();
  try {
    for (const input of [
      Buffer.alloc(0),
      Buffer.alloc(65537),
      Buffer.from('private malformed certificate'),
      f.pem.toString() + f.pem.toString(),
      Buffer.concat([f.chain[0]!, Buffer.from([0])]),
      new Uint8Array(new SharedArrayBuffer(20)),
      undefined,
      {},
      'x'.repeat(65537),
    ])
      assert.throws(
        () => x509.parse(input as Uint8Array),
        (error) => {
          assert.ok(code('EK_X509_PARSE')(error));
          assert.ok(error instanceof KitError);
          assert.equal(error.cause, undefined);
          assert.equal(error.message.includes('private malformed'), false);
          return true;
        },
      );
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 128 }), async (input) => {
        assert.throws(() => x509.parse(input), code('EK_X509_PARSE'));
      }),
      { seed: 50912, numRuns: 100 },
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 quoted SAN commas and escapes never synthesize DNS identities', () => {
  assert.deepEqual(
    alternativeNames('URI:"https://a.invalid/, DNS:evil.invalid", DNS:good.invalid'),
    { dnsSans: ['good.invalid'], uriSans: ['https://a.invalid/, DNS:evil.invalid'] },
  );
  assert.deepEqual(alternativeNames('URI:"https://a.invalid/\\"quoted\\"", IP Address:127.0.0.1'), {
    dnsSans: [],
    uriSans: ['https://a.invalid/"quoted"'],
  });
  for (const input of [
    'URI:"unterminated',
    'URI:"bad\\',
    'DNS:',
    'DNS:"\\n"',
    'URI:'.repeat(17000),
    Array.from({ length: 257 }, () => 'DNS:a').join(', '),
    'DNS:"' + 'x'.repeat(2049) + '"',
    'missing-colon',
    'URI:"a"trailing',
  ])
    assert.throws(() => alternativeNames(input), code('EK_X509_PARSE'));
  assert.equal(fingerprint('AA:'.repeat(31) + 'AA'), 'aa'.repeat(32));
});
test('EK-STD-SEC-012 malformed chain and trust records are rejected without invoking accessors', async () => {
  const { app, x509 } = await start();
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Untrusted accessor');
  };
  try {
    const array = Object.defineProperty([f.chain[0]!], '0', { get: accessor });
    const policy = Object.defineProperty({}, 'trustRoots', { get: accessor, enumerable: true });
    for (const chain of [
      [],
      Array(1),
      array,
      Array(17).fill(f.chain[0]),
      { length: 1 },
      [Buffer.alloc(0)],
    ])
      await assert.rejects(
        x509.inspectChain(chain as Uint8Array[], trust()),
        code('EK_X509_PARSE'),
      );
    for (const input of [
      policy,
      { ...trust(), unexpected: true },
      { ...trust(), requireRevocationCheck: undefined },
      { ...trust(), expectedHostname: '*' },
      { ...trust(), expectedHostname: 'bad\nname' },
      { ...trust(), trustRoots: [f.roots[0]!, f.roots[0]!] },
    ])
      await assert.rejects(
        x509.inspectChain(f.chain, input as ReturnType<typeof trust>),
        code('EK_X509_PARSE'),
      );
    assert.throws(
      () =>
        x509.daysUntilExpiry(Object.defineProperty({}, 'notAfter', { get: accessor }) as X509Info),
      code('EK_X509_PARSE'),
    );
    assert.equal(invoked, 0);
    const proxy = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('Private caller trap');
        },
      },
    );
    assert.throws(
      () => x509.getFingerprints(proxy as X509Info),
      (error) => {
        assert.ok(code('EK_X509_PARSE')(error));
        assert.ok(error instanceof KitError);
        assert.equal(error.cause, undefined);
        assert.equal(error.message.includes('Private caller'), false);
        return true;
      },
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 invalid configuration, unsafe providers and ambiguous trust-store identities fail at construction', () => {
  let invoked = 0;
  const provider = Object.defineProperty({}, 'verifyChainAndRevocation', {
    get() {
      invoked++;
    },
  });
  for (const settings of [
    { ...f.settings, unexpected: true },
    { ...f.settings, trustProvider: provider },
    { ...f.settings, trustProvider: {} },
    { ...f.settings, trustProvider: null },
    { ...f.settings, trustRoots: {} },
    { ...f.settings, trustRoots: { leaf: [f.chain[0]!] } },
    { ...f.settings, trustRoots: { one: f.roots, two: f.roots } },
    { ...f.settings, trustRoots: { one: [...f.roots, ...f.roots] } },
    { ...f.settings, trustRoots: { 'invalid space': f.roots } },
    ...[0, -1, 1.5, NaN, Infinity, 1025].map((maxConcurrent) => ({
      ...f.settings,
      policy: { ...f.settings.policy, maxConcurrent },
    })),
    ...[0, 120001].map((timeoutMs) => ({
      ...f.settings,
      policy: { ...f.settings.policy, timeoutMs },
    })),
    { ...f.settings, policy: { maxConcurrent: 129, timeoutMs: 1 } },
    { ...f.settings, policy: { maxConcurrent: 1, timeoutMs: 1, maxInputBytes: 1 } },
    { ...f.settings, policy: { maxConcurrent: 1, timeoutMs: 1, maxOutputBytes: 1048577 } },
  ])
    assert.throws(() => x509Plugin(settings as X509PluginSettings), code('EK_CONFIG_INVALID'));
  assert.equal(invoked, 0);
});
test('EK-STD-SEC-012 external provider errors and revocation outages remain indeterminate without private diagnostics', async () => {
  const { app, x509 } = await start();
  try {
    f.unavailable(true);
    const result = await x509.inspectChain(f.chain, trust());
    assert.equal(result.status, 'indeterminate');
    assert.equal(JSON.stringify(result).includes('Disposable'), false);
  } finally {
    f.unavailable(false);
    await app.stop();
  }
});
test('EK-STD-SEC-012 trust success must bind exact fingerprint, issuer, validity and every SAN', async () => {
  let returned: unknown = identity();
  const trustProvider: MtlsTrustProvider = {
    async verifyChainAndRevocation() {
      return returned as VerifiedPeerIdentity;
    },
  };
  const { app, x509 } = await start({ ...f.settings, trustProvider });
  try {
    for (const change of [
      { certificateFingerprintSha256: '00'.repeat(32) },
      { issuer: 'different' },
      { notAfter: new Date().toISOString() },
      { dnsSans: ['foreign.invalid'] },
      { uriSans: [] },
    ]) {
      returned = { ...identity(), ...change };
      assert.equal((await x509.inspectChain(f.chain, trust())).status, 'untrusted');
    }
    for (returned of [
      null,
      {},
      { ...identity(), extra: true },
      { ...identity(), dnsSans: [42] },
      { ...identity(), certificateFingerprintSha256: 'bad' },
    ])
      assert.equal((await x509.inspectChain(f.chain, trust())).status, 'indeterminate');
    returned = identity();
    assert.equal((await x509.inspectChain(f.chain, trust())).status, 'trusted');
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 hung trust providers retain slots after timeout and never acknowledge late trust', async () => {
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
  const { app, x509 } = await start({
    ...f.settings,
    trustProvider,
    policy: { maxConcurrent: 1, timeoutMs: 2000 },
  });
  try {
    const result = x509.inspectChain(f.chain, trust(), { timeoutMs: 20 });
    await entered.promise;
    await assert.rejects(result, code('EK_TIMEOUT'));
    assert.equal(providerSignal?.aborted, true);
    await assert.rejects(x509.inspectChain(f.chain, trust()), code('EK_BACKEND_UNAVAILABLE'));
    release.release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal((await x509.inspectChain(f.chain, trust())).status, 'trusted');
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-012 cancellation and shutdown abort the trust backend and close all retained operations', async () => {
  const entered = gate(),
    release = gate();
  const trustProvider: MtlsTrustProvider = {
    async verifyChainAndRevocation(_input, options) {
      entered.release();
      await release.promise;
      assert.equal(options?.signal?.aborted, true);
      return identity();
    },
  };
  const { app, x509 } = await start({ ...f.settings, trustProvider });
  try {
    const controller = new AbortController(),
      result = x509.inspectChain(f.chain, trust(), { signal: controller.signal });
    const rejected = assert.rejects(result, code('EK_ABORTED'));
    await entered.promise;
    controller.abort();
    await rejected;
    const next = x509.inspectChain(f.chain, trust());
    const closed = assert.rejects(
      next,
      (error) => code('EK_ABORTED')(error) || code('EK_RESOURCE_CLOSED')(error),
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    await app.stop();
    await closed;
    await assert.rejects(x509.inspectChain(f.chain, trust()), code('EK_RESOURCE_CLOSED'));
    assert.throws(() => x509.parse(f.pem), code('EK_RESOURCE_CLOSED'));
    assert.throws(
      () => x509.daysUntilExpiry(identity() as unknown as X509Info),
      code('EK_RESOURCE_CLOSED'),
    );
    assert.throws(() => x509.getFingerprints({} as X509Info), code('EK_RESOURCE_CLOSED'));
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-012 invalid request options cannot override time or invoke forged signals', async () => {
  const { app, x509 } = await start();
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Untrusted option');
  };
  try {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      x509.inspectChain(f.chain, trust(), { signal: controller.signal }),
      code('EK_ABORTED'),
    );
    const forged = new AbortController().signal;
    Object.defineProperty(forged, 'aborted', { get: accessor });
    for (const options of [
      { timeoutMs: 0 },
      { timeoutMs: 2001 },
      { signal: {} },
      { signal: forged },
      { now: Date.now() },
      Object.defineProperty({}, 'timeoutMs', { get: accessor, enumerable: true }),
    ])
      await assert.rejects(
        x509.inspectChain(f.chain, trust(), options as OperationOptions),
        code('EK_CONFIG_INVALID'),
      );
    assert.equal(invoked, 0);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 mutable input and settings snapshots cannot change in-flight trust identities', async () => {
  const entered = gate(),
    release = gate(),
    settingsRoot = Buffer.from(f.roots[0]!);
  const trustProvider: MtlsTrustProvider = {
    async verifyChainAndRevocation(input) {
      entered.release();
      await release.promise;
      assert.deepEqual(input.peerDer, f.chain[0]);
      return identity();
    },
  };
  const plugin = x509Plugin({
    ...f.settings,
    trustRoots: { fixture: [settingsRoot] },
    trustProvider,
  });
  settingsRoot.fill(0);
  const app = await createApplication({ service, plugins: [plugin] });
  await app.start();
  try {
    const chain = f.chain.map((value) => Buffer.from(value)),
      roots = f.roots.map((value) => Buffer.from(value));
    const result = app
      .resolve<X509Service>(X509_CAPABILITY)
      .inspectChain(chain, { ...trust(), trustRoots: roots });
    await entered.promise;
    chain.forEach((value) => value.fill(0));
    roots.forEach((value) => value.fill(0));
    release.release();
    assert.equal((await result).status, 'trusted');
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-012 finite input and output budgets prevent oversized parsing and trusted results', async () => {
  const small = await start({
    ...f.settings,
    policy: { maxConcurrent: 1, timeoutMs: 1000, maxOutputBytes: 16 },
  });
  try {
    assert.throws(() => small.x509.parse(f.pem), code('EK_X509_PARSE'));
    await assert.rejects(small.x509.inspectChain(f.chain, trust()), code('EK_X509_PARSE'));
  } finally {
    await small.app.stop();
  }
  const bounded = await start({
    ...f.settings,
    policy: { maxConcurrent: 1, timeoutMs: 1000, maxInputBytes: f.roots[0]!.length },
  });
  try {
    await assert.rejects(bounded.x509.inspectChain(f.chain, trust()), code('EK_X509_PARSE'));
  } finally {
    await bounded.app.stop();
  }
});
test('EK-STD-SEC-012 reused plugin factories have isolated lifecycles and test-only trust cannot enter production', async () => {
  const plugin = x509Plugin(f.settings),
    apps: Application[] = [];
  try {
    for (let index = 0; index < 2; index++) {
      const app = await createApplication({ service, plugins: [plugin] });
      await app.start();
      apps.push(app);
    }
    const first = apps[0]!.resolve<X509Service>(X509_CAPABILITY),
      second = apps[1]!.resolve<X509Service>(X509_CAPABILITY);
    assert.notEqual(first, second);
    await apps[0]!.stop();
    assert.ok(second.parse(f.pem));
  } finally {
    await Promise.all(apps.map((app) => app.stop()));
  }
  for (const environment of ['production', 'development'] as const) {
    const app = await createApplication({
      service: { ...service, environment },
      plugins: [plugin],
    });
    await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
    assert.equal(app.state, 'CLOSED');
    await app.stop();
  }
  await assert.rejects(
    createApplication({ service, plugins: [plugin, plugin] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
});
test('EK-STD-SEC-012 native work cannot return success after its trusted monotonic deadline', async () => {
  const runtime = createRuntime(captureSettings(f.settings));
  try {
    const controller = new AbortController();
    runtime.bootstrap(controller.signal);
    await assert.rejects(
      runtime.run({ timeoutMs: 5 }, async () => {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
        return true;
      }),
      code('EK_TIMEOUT'),
    );
    await assert.rejects(
      runtime.run(undefined, async () => {
        throw new Error('private verifier detail');
      }),
      (error) => {
        assert.ok(code('EK_X509_UNTRUSTED')(error));
        assert.ok(error instanceof KitError);
        assert.equal(error.cause, undefined);
        return true;
      },
    );
  } finally {
    runtime.close();
    runtime.close();
  }
});
test('EK-STD-SEC-012 expired configured roots prevent readiness and bootstrap cancellation is fail-closed', async () => {
  const app = await createApplication({
    service,
    plugins: [x509Plugin({ ...f.settings, trustRoots: { expired: [f.expiredRoot] } })],
  });
  await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
  assert.equal(app.state, 'CLOSED');
  await app.stop();
  const runtime = createRuntime(captureSettings(f.settings)),
    controller = new AbortController();
  controller.abort();
  try {
    assert.throws(() => runtime.bootstrap(controller.signal), code('EK_ABORTED'));
  } finally {
    runtime.close();
  }
});
test('EK-STD-SEC-012 provider methods and usage are captured without runtime getter invocation', () => {
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Unsafe provider getter');
  };
  for (const trustProvider of [
    Object.defineProperty(
      { verifyChainAndRevocation: f.provider.verifyChainAndRevocation },
      'usage',
      { get: accessor },
    ),
    { ...f.provider, usage: 'unknown' },
  ])
    assert.throws(() => x509Plugin({ ...f.settings, trustProvider }), code('EK_CONFIG_INVALID'));
  const policy = Object.defineProperty({}, 'maxConcurrent', { get: accessor, enumerable: true });
  assert.throws(
    () => x509Plugin({ ...f.settings, policy } as X509PluginSettings),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(invoked, 0);
});
test('EK-STD-SEC-012 scoped telemetry records bounded classifications without certificate identities or outcome changes', async () => {
  const events: unknown[] = [];
  let broken = false,
    spans = 0;
  const diagnostic = (...values: unknown[]) => {
    if (broken) throw new Error('Private diagnostic failure');
    events.push(values);
  };
  const telemetry: Telemetry = {
    async measure(_name, work) {
      return work();
    },
    async withSpan(_name, work, options) {
      spans++;
      if (broken) throw new Error('Private tracing failure');
      diagnostic(options);
      return work();
    },
    addCounter: diagnostic,
    recordHistogram: diagnostic,
    setGauge: diagnostic,
    async flush() {},
  };
  const observer: Plugin = {
    id: 'test-telemetry',
    version: '1.0.0',
    capabilities: new Set(['telemetry']),
    init(context) {
      context.provide(COMPONENTS.telemetry, telemetry);
    },
    close() {},
  };
  const app = await createApplication({ service, plugins: [x509Plugin(f.settings), observer] });
  await app.start();
  try {
    const x509 = app.resolve<X509Service>(X509_CAPABILITY);
    assert.equal(
      (await x509.inspectChain(f.chain, { ...trust(), expectedHostname: 'foreign.invalid' }))
        .status,
      'untrusted',
    );
    await assert.rejects(x509.inspectChain([], trust()), code('EK_X509_PARSE'));
    assert.equal(spans, 2);
    const serialized = JSON.stringify(events);
    for (const privateValue of [
      'localhost',
      'spiffe',
      identity().issuer,
      identity().certificateFingerprintSha256,
    ])
      assert.equal(serialized.includes(privateValue), false);
    assert.ok(
      serialized.includes('x509.validation.duration_ms') &&
        serialized.includes('x509.trust_roots.expiring'),
    );
    broken = true;
    const before = f.calls();
    assert.equal((await x509.inspectChain(f.chain, trust())).status, 'trusted');
    assert.equal(
      (await x509.inspectChain(f.chain, { ...trust(), expectedHostname: 'foreign.invalid' }))
        .status,
      'untrusted',
    );
    assert.equal(f.calls(), before + 1);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-012 the actual telemetry SDK exports certificate diagnostics without custom labels, drops or private metadata', async () => {
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
  const app = await createApplication({ service, plugins: [x509Plugin(f.settings), observer] });
  try {
    await app.start();
    const adapter = app.resolve<X509Service>(X509_CAPABILITY);
    assert.equal((await adapter.inspectChain(f.chain, trust())).status, 'trusted');
    assert.equal(
      (await adapter.inspectChain(f.chain, { ...trust(), expectedHostname: 'foreign.invalid' }))
        .status,
      'untrusted',
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
    assert.ok(objects.some((value) => value.name === 'x509.inspect_chain'));
    assert.ok(
      objects.some((value) => value.name === 'x509.validation.duration_ms' && value.unit === 'ms'),
    );
    assert.ok(objects.some((value) => value.name === 'x509.validation.completed.trusted'));
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
test('EK-STD-SEC-012 native CRL rejection after revocation cannot produce trusted validation', async () => {
  const { app, x509 } = await start();
  try {
    assert.equal((await x509.inspectChain(f.chain, trust())).status, 'trusted');
    await f.revoke();
    assert.equal((await x509.inspectChain(f.chain, trust())).status, 'indeterminate');
  } finally {
    await app.stop();
  }
});
