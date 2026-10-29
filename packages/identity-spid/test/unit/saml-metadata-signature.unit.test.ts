// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignedXml } from 'xml-crypto';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import { setImmediate } from 'node:timers/promises';
import { verifySamlMetadataSignature } from '../../dist/saml-metadata-signature.js';
import { FederationSamlSignatures } from '../../dist/saml-signatures.js';
import { verifySamlRegistryDocument } from '../../dist/saml-registry-document.js';
import { FederationSamlRegistry } from '../../dist/saml-registry.js';
import { FederationCall, FederationRuntime } from '../../dist/runtime.js';
import type { FederationProfileV1 } from '../../dist/index.js';

import {
  md,
  protocol,
  enveloped,
  root,
  foreign,
  profile,
  signed,
  registry,
  closeRegistryFixture,
} from '../fixtures/saml-metadata.js';

after(closeRegistryFixture);

test('Registry documents bind current RP and IdP status, root authority and native signing certificates', async () => {
  const f = await registry();
  for (const role of ['idp', 'sp'] as const) {
    const evidence = verifySamlRegistryDocument(f.xml(role), f.status(role), f.profile, role);
    assert.equal(evidence.issuer, role === 'sp' ? f.entity : f.issuer);
    assert.equal(evidence.signerIssuer, 'https://registry.example.test');
    assert.deepEqual(evidence.certificates, [f.first.pem]);
    assert.ok(Object.isFrozen(evidence.certificates));
    assert.ok(Date.parse(evidence.expiresAt) <= Date.now() + 60000);
    assert.equal('trusted' in evidence, false);
    const rotated = verifySamlRegistryDocument(
      f.xml(role, {
        descriptorContent:
          f.descriptor() + f.descriptor(f.second.encoded) + (role === 'sp' ? f.consumer : ''),
      }),
      f.status(role, { signing_certificate_x509: [f.second.encoded, f.first.encoded] }),
      f.profile,
      role,
    );
    assert.deepEqual(rotated.certificates, [f.first.pem, f.second.pem]);
  }
});

test('Missing, disabled, withdrawn, foreign and malformed registry state cannot authorize signed metadata', async () => {
  const f = await registry(),
    xml = f.xml('idp');
  for (const change of [
    { entity_id: f.entity },
    { entity_id: undefined },
    { _deleted: 'Y' },
    { _disabled: 'Y' },
    { _disabled: undefined },
    { _deleted: false },
    { delete_date: undefined },
    { delete_date: '' },
    { delete_date: '2026-01-01' },
    { signing_certificate_x509: [] },
    { signing_certificate_x509: undefined },
    { signing_certificate_x509: [f.first.encoded, f.first.encoded] },
    { signing_certificate_x509: [f.second.encoded] },
    { signing_certificate_x509: [f.ec.encoded] },
    { signing_certificate_x509: [f.weak.encoded] },
    { signing_certificate_x509: ['not-a-certificate'] },
    { signing_certificate_x509: [null] },
    { signing_certificate_x509: ['x'.repeat(16385)] },
    { signing_certificate_x509: ['YWJj'] },
    { signing_certificate_x509: [f.first.encoded + 'AAAA'] },
    { signing_certificate_x509: Array(9).fill(f.first.encoded) },
    Object.fromEntries(Array.from({ length: 65 }, (_, index) => ['extra' + index, 'x'])),
  ])
    assert.throws(
      () => verifySamlRegistryDocument(xml, f.status('idp', change), f.profile, 'idp'),
      { code: 'EK_EID_FEDERATION' },
    );
  for (const status of ['', '{', 'null', '[]', '\ud800', 'x'.repeat(65537), {}])
    assert.throws(() => verifySamlRegistryDocument(xml, status as string, f.profile, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  assert.throws(
    () =>
      verifySamlRegistryDocument(
        f.xml('idp', { key: foreign.privateKey }),
        f.status('idp'),
        f.profile,
        'idp',
      ),
    { code: 'EK_EID_FEDERATION' },
  );
  const wrongAuthority = {
    ...f.profile,
    metadata: {
      ...f.profile.metadata,
      trustAnchors: f.profile.metadata.trustAnchors.map((anchor) => ({
        ...anchor,
        issuer: 'https://foreign.example.test',
      })),
    },
  };
  assert.throws(() => verifySamlRegistryDocument(xml, f.status('idp'), wrongAuthority, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
});

test('Signed metadata must bind exact signing keys, explicit request signatures and the registered POST ACS', async () => {
  const f = await registry();
  for (const content of [
    '',
    f.descriptor(f.ec.encoded),
    f.descriptor() + f.descriptor(),
    f.descriptor().replace('use="signing"', 'use="unknown"'),
    f.descriptor().replace('use="signing"', 'use="encryption"'),
    f.descriptor().replace('</ds:X509Certificate>', '<ds:Other/></ds:X509Certificate>'),
    f.descriptor().replace(f.first.encoded, ''),
    Array(9).fill(f.descriptor()).join(''),
  ])
    assert.throws(
      () =>
        verifySamlRegistryDocument(
          f.xml('idp', { descriptorContent: content }),
          f.status('idp'),
          f.profile,
          'idp',
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  for (const role of ['idp', 'sp'] as const)
    assert.throws(
      () =>
        verifySamlRegistryDocument(
          f.xml(role, { descriptorAttributes: '' }),
          f.status(role),
          f.profile,
          role,
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  for (const consumer of [
    '',
    f.consumer.replace(f.profile.redirectUri, 'https://foreign.example.test/acs'),
    f.consumer.replace('index="0"', 'index="1"'),
    f.consumer.replace('index="0"', 'index="65536"'),
    f.consumer.replace('index="0"', 'index="invalid"'),
    f.consumer.replace('index="0"', ''),
    f.consumer.replace('index="0"', 'index="9007199254740992"'),
    f.consumer.replace('isDefault="true"', 'isDefault="false"'),
    f.consumer.replace('HTTP-POST', 'HTTP-Redirect'),
    f.consumer + f.consumer,
    f.consumer + f.consumer.replace('index="0"', 'index="1"'),
    Array(65).fill(f.consumer).join(''),
  ])
    assert.throws(
      () =>
        verifySamlRegistryDocument(
          f.xml('sp', { descriptorContent: f.descriptor() + consumer }),
          f.status('sp'),
          f.profile,
          'sp',
        ),
      { code: 'EK_EID_FEDERATION' },
    );
});

test('Registry certificates retain native validity and optional metadata expiry never extends refresh policy', async (context) => {
  const f = await registry(),
    configuration = {
      ...f.profile,
      metadata: {
        ...f.profile.metadata,
        trustAnchors: f.profile.metadata.trustAnchors.map((anchor) => ({
          ...anchor,
          expiresAt: new Date(Date.now() + 4 * 86400000).toISOString(),
        })),
      },
    },
    xml = f.xml('idp', { expiry: new Date(Date.now() + 3 * 86400000).toISOString() }),
    certificate = new X509Certificate(f.first.pem);
  let now = Date.now();
  const clock = context.mock.method(Date, 'now', () => now);
  for (const instant of [Date.parse(certificate.validFrom) - 1, Date.parse(certificate.validTo)]) {
    now = instant;
    assert.throws(() => verifySamlRegistryDocument(xml, f.status('idp'), configuration, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  }
  clock.mock.restore();
  const optional = verifySamlRegistryDocument(
    f.xml('idp', { expiry: null, descriptorContent: f.descriptor().replace(' use="signing"', '') }),
    f.status('idp'),
    f.profile,
    'idp',
  );
  assert.equal(optional.validUntil, undefined);
  assert.ok(Date.parse(optional.expiresAt) <= Date.now() + 60000);
  for (const defaultValue of ['', ' isDefault="false"', ' isDefault="0"']) {
    const extra = f.consumer
      .replace('index="0"', 'index="1"')
      .replace(' isDefault="true"', defaultValue)
      .replace(f.profile.redirectUri, 'https://application.example.test/other-acs');
    assert.equal(
      verifySamlRegistryDocument(
        f.xml('sp', { descriptorContent: f.descriptor() + f.consumer + extra }),
        f.status('sp'),
        f.profile,
        'sp',
      ).issuer,
      f.entity,
    );
  }
});

test('The existing native worker verifies registry bindings and rejects signature-only or copied membership evidence', async () => {
  const f = await registry(),
    signatures = new FederationSamlSignatures(f.profile),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  try {
    for (const role of ['idp', 'sp'] as const) {
      const evidence = await runtime.run((call) =>
        signatures.verifyRegistry(call, f.xml(role), f.status(role), role),
      );
      assert.equal(signatures.registryResult(evidence), evidence);
      assert.ok(Object.isFrozen(evidence.certificates));
      assert.throws(() => signatures.registryResult({ ...evidence }), {
        code: 'EK_EID_FEDERATION',
      });
    }
    const signature = await runtime.run((call) => signatures.verify(call, f.xml('idp'), 'idp'));
    assert.throws(() => signatures.registryResult(signature), { code: 'EK_EID_FEDERATION' });
    await assert.rejects(
      () =>
        runtime.run((call) =>
          signatures.verifyRegistry(call, f.xml('idp'), f.status('idp', { _disabled: 'Y' }), 'idp'),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await runtime.close();
  }
});

test('Registry composition refreshes both exact sources and never falls back after withdrawal', async () => {
  const f = await registry(),
    paths: string[] = [],
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  let disabled = false;
  const transport = {
      async samlMetadata(endpoint: string) {
        paths.push(endpoint);
        return f.xml(endpoint.endsWith('/sp') ? 'sp' : 'idp');
      },
      async samlRegistryStatus(endpoint: string) {
        paths.push(endpoint);
        return f.status(
          endpoint.endsWith('/sp-status') ? 'sp' : 'idp',
          disabled ? { _disabled: 'Y' } : {},
        );
      },
    },
    verifier = new FederationSamlRegistry(f.profile, transport),
    foreignOwner = new FederationSamlRegistry(f.profile, transport);
  try {
    const evidence = await runtime.run((call) => verifier.verify(call, f.issuer, 'idp'));
    assert.equal(verifier.result(evidence), evidence);
    assert.throws(() => verifier.result({ ...evidence }), { code: 'EK_EID_FEDERATION' });
    assert.throws(() => foreignOwner.result(evidence), { code: 'EK_EID_FEDERATION' });
    disabled = true;
    await assert.rejects(() => runtime.run((call) => verifier.verify(call, f.issuer, 'idp')), {
      code: 'EK_EID_FEDERATION',
    });
    assert.deepEqual(paths, [
      'https://registry.example.test/idp',
      'https://registry.example.test/idp-status',
      'https://registry.example.test/idp',
      'https://registry.example.test/idp-status',
    ]);
    const before = paths.length;
    for (const [entity, role] of [
      [f.issuer, 'sp'],
      [f.entity, 'idp'],
      ['https://foreign.example.test', 'idp'],
    ] as const)
      await assert.rejects(() => runtime.run((call) => verifier.verify(call, entity, role)), {
        code: 'EK_EID_FEDERATION',
      });
    assert.equal(paths.length, before);
  } finally {
    await runtime.close();
  }
});

test('Registry expiry, invalid roles and failed sources cannot create reusable membership evidence', async (context) => {
  const f = await registry(),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  let now = Date.now(),
    failed = false,
    advanced = false,
    reads = 0;
  context.mock.method(Date, 'now', () => now);
  const transport = {
      async samlMetadata() {
        reads++;
        if (failed) throw new Error('Private registry transport diagnostic');
        return f.xml('idp');
      },
      async samlRegistryStatus() {
        reads++;
        if (advanced) now += 2000;
        return f.status('idp');
      },
    },
    verifier = new FederationSamlRegistry(f.profile, transport),
    signatures = new FederationSamlSignatures(f.profile);
  try {
    const evidence = await runtime.run((call) => verifier.verify(call, f.issuer, 'idp'));
    now = Date.parse(evidence.expiresAt);
    assert.throws(() => verifier.result(evidence), { code: 'EK_EID_FEDERATION' });
    assert.throws(() => verifier.result(null), { code: 'EK_EID_FEDERATION' });
    now = Date.now() - 61000;
    failed = true;
    await assert.rejects(() => runtime.run((call) => verifier.verify(call, f.issuer, 'idp')), {
      code: 'EK_EID_FEDERATION',
    });
    failed = false;
    advanced = true;
    const short = new FederationSamlRegistry(
      { ...f.profile, metadata: { ...f.profile.metadata, refreshIntervalSeconds: 1 } },
      transport,
    );
    await assert.rejects(() => runtime.run((call) => short.verify(call, f.issuer, 'idp')), {
      code: 'EK_EID_FEDERATION',
    });
    const before = reads;
    await assert.rejects(
      () => runtime.run((call) => verifier.verify(call, f.issuer, 'unknown' as never)),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(reads, before);
    for (const status of [undefined, null, '', '\ud800', 'x'.repeat(65537)])
      await assert.rejects(
        () =>
          runtime.run((call) =>
            signatures.verifyRegistry(call, f.xml('idp'), status as string, 'idp'),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    await assert.rejects(
      () =>
        runtime.run((call) =>
          signatures.verifyRegistry(call, f.xml('idp'), f.status('idp'), 'unknown' as never),
        ),
      { code: 'EK_EID_PROFILE' },
    );
    const missing = { ...f.profile, samlRegistration: { signingCertificateRef: 'certificate' } };
    assert.throws(() => new FederationSamlRegistry(missing, transport), { code: 'EK_EID_PROFILE' });
  } finally {
    await runtime.close();
  }
});

test('The actual metadata worker entry returns native signature results and fixed failure messages', async () => {
  for (const accepted of [true, false]) {
    const worker = new Worker(new URL('../../dist/saml-signature-worker.js', import.meta.url), {
      workerData: {
        xml: signed(accepted ? {} : { key: foreign.privateKey }),
        profile: profile(),
        role: 'idp',
      },
      env: {
        NODE_ENV: 'production',
        ...(process.env.NODE_V8_COVERAGE ? { NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE } : {}),
      },
      stdout: true,
      stderr: true,
    });
    worker.stdout.resume();
    worker.stderr.resume();
    try {
      const result = once(worker, 'message'),
        exited = once(worker, 'exit');
      const [value] = await result;
      if (accepted) {
        assert.equal(value.ok, true);
        assert.equal(value.result.issuer, profile().expectedIssuers[0]);
        assert.equal(value.result.verifiedXml.includes('SignatureValue'), false);
      } else assert.deepEqual(value, { ok: false });
      assert.equal((await exited)[0], 0);
    } finally {
      await worker.terminate();
    }
  }
});

test('The actual registry worker entry preserves both current-state success and fixed rejection messages', async () => {
  const f = await registry();
  for (const accepted of [true, false]) {
    const worker = new Worker(new URL('../../dist/saml-signature-worker.js', import.meta.url), {
      workerData: {
        xml: f.xml('idp'),
        profile: f.profile,
        role: 'idp',
        status: f.status('idp', accepted ? {} : { _deleted: 'Y' }),
      },
      env: {
        NODE_ENV: 'production',
        ...(process.env.NODE_V8_COVERAGE ? { NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE } : {}),
      },
      stdout: true,
      stderr: true,
    });
    worker.stdout.resume();
    worker.stderr.resume();
    try {
      const received = once(worker, 'message'),
        exited = once(worker, 'exit'),
        [value] = await received;
      if (accepted) {
        assert.equal(value.ok, true);
        assert.equal(value.result.issuer, f.issuer);
        assert.deepEqual(value.result.certificates, [f.first.pem]);
      } else assert.deepEqual(value, { ok: false });
      assert.equal((await exited)[0], 0);
    } finally {
      await worker.terminate();
    }
  }
});

test('Observed withdrawal invalidates old receipts and prevents earlier concurrent work from restoring them', async () => {
  const f = await registry(),
    runtime = new FederationRuntime({ maxConcurrent: 2, timeoutMs: 10000 });
  let reads = 0,
    release!: () => void,
    entered!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    reached = new Promise<void>((resolve) => {
      entered = resolve;
    });
  const verifier = new FederationSamlRegistry(f.profile, {
    async samlMetadata() {
      return f.xml('idp');
    },
    async samlRegistryStatus() {
      const selected = ++reads;
      if (selected === 2) {
        entered();
        await held;
      }
      return f.status('idp', selected === 3 ? { _disabled: 'Y' } : {});
    },
  });
  try {
    const old = await runtime.run((call) => verifier.verify(call, f.issuer, 'idp'));
    const earlier = runtime.run((call) => verifier.verify(call, f.issuer, 'idp')),
      rejected = assert.rejects(earlier, { code: 'EK_EID_FEDERATION' });
    await reached;
    await assert.rejects(() => runtime.run((call) => verifier.verify(call, f.issuer, 'idp')), {
      code: 'EK_EID_FEDERATION',
    });
    assert.throws(() => verifier.result(old), { code: 'EK_EID_FEDERATION' });
    release();
    await rejected;
    const fresh = await runtime.run((call) => verifier.verify(call, f.issuer, 'idp'));
    assert.equal(verifier.result(fresh), fresh);
    assert.throws(() => verifier.result(old), { code: 'EK_EID_FEDERATION' });
  } finally {
    release();
    await runtime.close();
  }
});

test('Owned native metadata workers verify real signatures and reject copied, foreign or expired evidence', async (context) => {
  const configuration = profile(),
    verifier = new FederationSamlSignatures(configuration),
    foreignOwner = new FederationSamlSignatures(configuration),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  try {
    const idp = await runtime.run((call) => verifier.verify(call, signed(), 'idp')),
      sp = await runtime.run((call) => verifier.verify(call, signed({ role: 'sp' }), 'sp')),
      noExpiry = await runtime.run((call) =>
        verifier.verify(call, signed({ expiry: null }), 'idp'),
      );
    assert.equal(verifier.result(idp), idp);
    assert.equal(verifier.result(sp).issuer, configuration.entityId);
    assert.equal(verifier.result(noExpiry).validUntil, undefined);
    assert.ok(Object.isFrozen(idp));
    assert.equal('trusted' in idp, false);
    let traps = 0;
    for (const candidate of [
      null,
      {},
      { ...idp },
      new Proxy(idp, {
        get() {
          traps++;
          throw new Error('Evidence getters must remain unread');
        },
      }),
    ])
      assert.throws(() => verifier.result(candidate), { code: 'EK_EID_FEDERATION' });
    assert.equal(traps, 0);
    const forged = { ...idp };
    Object.defineProperty(verifier, 'owned', { value: new WeakSet([forged]) });
    assert.throws(() => verifier.result(forged), { code: 'EK_EID_FEDERATION' });
    assert.throws(() => foreignOwner.result(idp), { code: 'EK_EID_FEDERATION' });
    let now = Date.now();
    context.mock.method(Date, 'now', () => now);
    now = Date.parse(idp.validUntil!);
    assert.throws(() => verifier.result(idp), { code: 'EK_EID_FEDERATION' });
    assert.equal(verifier.result(noExpiry), noExpiry);
    now = Date.parse(noExpiry.trustAnchorExpiresAt);
    assert.throws(() => verifier.result(noExpiry), { code: 'EK_EID_FEDERATION' });
  } finally {
    await runtime.close();
  }
});

test('Native metadata verification rejects malformed inputs before creating workers and preserves readiness', async (context) => {
  const verifier = new FederationSamlSignatures(profile()),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  let workers = 0,
    hooks = 0;
  const once = Worker.prototype.once;
  context.mock.method(
    Worker.prototype,
    'once',
    function (this: Worker, ...args: Parameters<Worker['once']>) {
      workers++;
      return Reflect.apply(once, this, args);
    },
  );
  try {
    for (const xml of [
      undefined,
      null,
      {},
      '',
      '\ud800',
      'x'.repeat(65537),
      {
        toString() {
          hooks++;
          return signed();
        },
      },
    ])
      await assert.rejects(
        () => runtime.run((call) => verifier.verify(call, xml as string, 'idp')),
        {
          code: 'EK_EID_FEDERATION',
        },
      );
    for (const role of [
      'foreign',
      {
        [Symbol.toPrimitive]() {
          hooks++;
          return 'idp';
        },
      },
    ])
      await assert.rejects(
        () => runtime.run((call) => verifier.verify(call, signed(), role as never)),
        {
          code: 'EK_EID_PROFILE',
        },
      );
    assert.equal(workers, 0);
    assert.equal(hooks, 0);
    const stopped = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 1000 }, () => false);
    try {
      await assert.rejects(() => stopped.run((call) => verifier.verify(call, signed(), 'idp')), {
        code: 'EK_LIFECYCLE_STATE',
      });
      assert.equal(workers, 0);
    } finally {
      await stopped.close();
    }
    const oidc: Record<string, unknown> = {
      ...profile(),
      protocol: 'oidc-federation',
      clientId: profile().entityId,
    };
    delete oidc.samlRegistration;
    assert.throws(() => new FederationSamlSignatures(oidc as unknown as FederationProfileV1), {
      code: 'EK_EID_PROFILE',
    });
    assert.throws(
      () => new FederationSamlSignatures({ ...profile(), protocol: 'oidc-federation' }),
      {
        code: 'EK_EID_PROFILE',
      },
    );
  } finally {
    await runtime.close();
  }
});

test('Native worker signature failures never return evidence or raw protocol diagnostics', async () => {
  const verifier = new FederationSamlSignatures(profile()),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  try {
    for (const xml of [
      signed({ key: foreign.privateKey }),
      signed().replace('protocolSupportEnumeration=', 'altered="true" protocolSupportEnumeration='),
      '<!DOCTYPE x><x/>',
    ])
      await assert.rejects(
        () => runtime.run((call) => verifier.verify(call, xml, 'idp')),
        (error: unknown) => {
          assert.equal((error as { code: string }).code, 'EK_EID_FEDERATION');
          assert.equal((error as Error).message, 'The federation trust policy was not satisfied');
          return true;
        },
      );
    assert.equal(runtime.stats().active, 0);
  } finally {
    await runtime.close();
  }
});

test('Cancellation at the native step boundary and during listener installation cannot start unowned work', async (context) => {
  const verifier = new FederationSamlSignatures(profile()),
    call = new FederationCall(10000, [], () => {});
  const injected = context.mock.method(
    call,
    'step',
    async <T>(work: (options: { signal: AbortSignal; timeoutMs: number }) => Promise<T>) =>
      work({ signal: AbortSignal.abort(), timeoutMs: 10000 }),
  );
  try {
    await assert.rejects(() => verifier.verify(call, signed(), 'idp'), { code: 'EK_ABORTED' });
  } finally {
    injected.mock.restore();
    call.finish();
  }
  const runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 }),
    stop = new AbortController(),
    once = Worker.prototype.once;
  let aborted = 0;
  context.mock.method(
    Worker.prototype,
    'once',
    function (this: Worker, event: string, listener: (...args: never[]) => void) {
      const result = Reflect.apply(once, this, [event, listener]);
      if (event === 'message') {
        aborted++;
        stop.abort();
      }
      return result;
    },
  );
  try {
    await assert.rejects(
      () =>
        runtime.run((active) => verifier.verify(active, signed(), 'idp'), { signal: stop.signal }),
      {
        code: 'EK_ABORTED',
      },
    );
    await runtime.close();
    assert.equal(runtime.stats().active, 0);
    assert.equal(aborted, 1);
  } finally {
    await runtime.close();
  }
});

test('Aborted native verification retains shared capacity until actual worker termination settles', async (context) => {
  const verifier = new FederationSamlSignatures(profile()),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 }),
    stop = new AbortController(),
    terminate = Worker.prototype.terminate;
  let release!: () => void, entered!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    terminating = new Promise<void>((resolve) => {
      entered = resolve;
    });
  context.mock.method(Worker.prototype, 'terminate', async function (this: Worker) {
    entered();
    await held;
    return Reflect.apply(terminate, this, []);
  });
  try {
    const pending = runtime.run((call) => verifier.verify(call, signed(), 'idp'), {
      signal: stop.signal,
    });
    const rejected = assert.rejects(pending, { code: 'EK_ABORTED' });
    await setImmediate();
    stop.abort();
    await rejected;
    await terminating;
    assert.equal(runtime.stats().active, 1);
    await assert.rejects(() => runtime.run(async () => 'not-admitted'), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
    const closed = runtime.close();
    assert.equal(runtime.stats().active, 1);
    release();
    await closed;
    assert.equal(runtime.stats().active, 0);
  } finally {
    release();
    await runtime.close();
  }
});

test('Native worker deadlines terminate physical verification and reject expired results after cleanup', async (context) => {
  const verifier = new FederationSamlSignatures(profile()),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 });
  try {
    await assert.rejects(
      () => runtime.run((call) => verifier.verify(call, signed(), 'idp'), { timeoutMs: 1 }),
      {
        code: 'EK_TIMEOUT',
      },
    );
    await runtime.close();
    assert.equal(runtime.stats().active, 0);
    const next = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 }),
      terminate = Worker.prototype.terminate,
      configuration = profile(),
      expiry = Date.now() + 60000,
      xml = signed({ expiry: new Date(expiry).toISOString() });
    let now = Date.now();
    context.mock.method(Date, 'now', () => now);
    context.mock.method(Worker.prototype, 'terminate', async function (this: Worker) {
      const result = await Reflect.apply(terminate, this, []);
      now = expiry;
      return result;
    });
    try {
      await assert.rejects(
        () =>
          next.run((call) => new FederationSamlSignatures(configuration).verify(call, xml, 'idp')),
        {
          code: 'EK_EID_FEDERATION',
        },
      );
    } finally {
      await next.close();
    }
  } finally {
    await runtime.close();
  }
});

test('Native worker errors, premature exit and cleanup failure fail closed without leaking native causes', async (context) => {
  const verifier = new FederationSamlSignatures(profile()),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 }),
    once = Worker.prototype.once;
  let mode: 'error' | 'exit' = 'error';
  const injected = context.mock.method(
    Worker.prototype,
    'once',
    function (this: Worker, event: string, listener: (...args: never[]) => void) {
      const result = Reflect.apply(once, this, [event, listener]);
      if (event === 'message')
        queueMicrotask(() =>
          this.emit(mode, mode === 'error' ? new Error('Private native diagnostic') : 1),
        );
      return result;
    },
  );
  try {
    for (mode of ['error', 'exit'] as const)
      await assert.rejects(() => runtime.run((call) => verifier.verify(call, signed(), 'idp')), {
        code: 'EK_EID_FEDERATION',
        message: 'The federation trust policy was not satisfied',
      });
    injected.mock.restore();
    const terminate = Worker.prototype.terminate;
    context.mock.method(Worker.prototype, 'terminate', async function (this: Worker) {
      await Reflect.apply(terminate, this, []);
      throw new Error('Private cleanup diagnostic');
    });
    await assert.rejects(() => runtime.run((call) => verifier.verify(call, signed(), 'idp')), {
      code: 'EK_BACKEND_UNAVAILABLE',
      message: 'The federation operation capacity is unavailable',
    });
  } finally {
    await runtime.close();
  }
});

test('Native SAML metadata signatures bind issuer, role and verified reference bytes without granting current membership', () => {
  for (const role of ['idp', 'sp'] as const) {
    const result = verifySamlMetadataSignature(signed({ role }), profile(), role);
    assert.equal(
      result.issuer,
      role === 'idp' ? 'https://idp.example.test' : 'https://application.example.test',
    );
    assert.equal(result.signerKid, 'root-pin');
    assert.equal(result.role, role);
    assert.ok(result.validUntil);
    assert.ok(result.verifiedXml.includes('EntityDescriptor'));
    assert.equal(result.verifiedXml.includes('SignatureValue'), false);
    assert.equal('trusted' in result, false);
    assert.ok(Object.isFrozen(result));
  }
  const withoutExpiry = verifySamlMetadataSignature(signed({ expiry: null }), profile(), 'idp');
  assert.equal(
    withoutExpiry.validUntil,
    undefined,
    'An absent metadata expiry is not replaced with a fabricated freshness guarantee',
  );
});

test('Only current explicitly pinned RSA roots verify; embedded identity claims and wrong signing keys cannot authorize metadata', () => {
  const xml = signed(),
    p = profile(),
    pin = p.metadata.trustAnchors[0]!;
  const rollover = {
    ...p,
    metadata: {
      ...p.metadata,
      trustAnchors: [
        {
          ...pin,
          kid: 'other-pin',
          publicKeyPem: foreign.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        },
        pin,
      ],
    },
  };
  assert.equal(verifySamlMetadataSignature(xml, rollover, 'idp').signerKid, 'root-pin');
  for (const input of [
    signed({ key: foreign.privateKey }),
    xml.replace('protocolSupportEnumeration=', 'altered="true" protocolSupportEnumeration='),
  ])
    assert.throws(() => verifySamlMetadataSignature(input, p, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  const withdrawn = {
    ...rollover,
    metadata: {
      ...rollover.metadata,
      trustAnchors: rollover.metadata.trustAnchors.map((item) =>
        item.kid === 'root-pin'
          ? { ...item, expiresAt: new Date(Date.now() - 1).toISOString() }
          : item,
      ),
    },
  };
  assert.throws(() => verifySamlMetadataSignature(xml, withdrawn, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
  const notYetActive = {
      ...rollover,
      metadata: {
        ...rollover.metadata,
        trustAnchors: rollover.metadata.trustAnchors.map((item) =>
          item.kid === 'root-pin'
            ? { ...item, validFrom: new Date(Date.now() + 60000).toISOString() }
            : item,
        ),
      },
    },
    ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      .publicKey.export({ format: 'pem', type: 'spki' })
      .toString(),
    wrongFamily = {
      ...p,
      metadata: { ...p.metadata, trustAnchors: [{ ...pin, publicKeyPem: ec }] },
    };
  for (const configured of [notYetActive, wrongFamily])
    assert.throws(() => verifySamlMetadataSignature(xml, configured, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
});

test('Unknown metadata roles cannot select another parser or execute coercion hooks', () => {
  let calls = 0;
  for (const role of [
    'provider',
    {
      [Symbol.toPrimitive]() {
        calls++;
        return 'idp';
      },
    },
  ])
    assert.throws(() => verifySamlMetadataSignature(signed(), profile(), role as never), {
      code: 'EK_EID_PROFILE',
    });
  assert.equal(calls, 0);
});

test('Pinned X.509 roots and native RSA SHA512 preserve independently bounded root validity', async (context) => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-metadata-root-')),
    keyPath = join(directory, 'key.pem'),
    certPath = join(directory, 'certificate.pem');
  try {
    await writeFile(keyPath, root.privateKey.export({ format: 'pem', type: 'pkcs8' }), {
      mode: 0o600,
    });
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-key',
        keyPath,
        '-out',
        certPath,
        '-days',
        '1',
        '-subj',
        '/CN=Pinned Metadata Fixture',
      ],
      { timeout: 10000 },
    );
    const p = profile(),
      cert = await readFile(certPath, 'utf8'),
      configured = {
        ...p,
        metadata: {
          ...p.metadata,
          trustAnchors: [{ ...p.metadata.trustAnchors[0]!, publicKeyPem: cert }],
        },
      },
      result = verifySamlMetadataSignature(
        signed({
          algorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          digest: 'http://www.w3.org/2001/04/xmlenc#sha512',
        }),
        configured,
        'idp',
      );
    assert.equal(result.signerKid, 'root-pin');
    assert.ok(Date.parse(result.trustAnchorExpiresAt) > Date.now());
    assert.ok(
      Date.parse(result.trustAnchorExpiresAt) <=
        Date.parse(configured.metadata.trustAnchors[0]!.expiresAt),
    );
    const certificate = new X509Certificate(cert),
      expiry = Date.parse(certificate.validTo),
      wide = {
        ...configured,
        metadata: {
          ...configured.metadata,
          trustAnchors: [
            {
              ...configured.metadata.trustAnchors[0]!,
              expiresAt: new Date(expiry + 3600000).toISOString(),
            },
          ],
        },
      },
      document = signed({ expiry: new Date(expiry + 7200000).toISOString() });
    for (const now of [Date.parse(certificate.validFrom) - 1, expiry + 1]) {
      context.mock.method(Date, 'now', () => now);
      assert.throws(() => verifySamlMetadataSignature(document, wide, 'idp'), {
        code: 'EK_EID_FEDERATION',
      });
      context.mock.restoreAll();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('A root expiring during actual native signature verification cannot produce reusable evidence', (context) => {
  const p = profile(),
    expiry = Date.now() + 10000,
    configuration = {
      ...p,
      metadata: {
        ...p.metadata,
        trustAnchors: [
          { ...p.metadata.trustAnchors[0]!, expiresAt: new Date(expiry).toISOString() },
        ],
      },
    },
    xml = signed({ expiry: new Date(expiry + 3600000).toISOString() }),
    native = SignedXml.prototype.checkSignature;
  let now = Date.now(),
    verified = 0;
  context.mock.method(Date, 'now', () => now);
  context.mock.method(
    SignedXml.prototype,
    'checkSignature',
    function (this: SignedXml, input: string) {
      const result = Reflect.apply(native, this, [input]);
      assert.equal(result, true, 'The signature itself must remain natively valid');
      verified++;
      now = expiry + 1;
      return result;
    },
  );
  assert.throws(() => verifySamlMetadataSignature(xml, configuration, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
  assert.equal(verified, 1);
});

test('Metadata expiring during actual native verification cannot authorize a fresh result', (context) => {
  const configuration = profile(),
    expiry = Date.now() + 10000,
    xml = signed({ expiry: new Date(expiry).toISOString() }),
    native = SignedXml.prototype.checkSignature;
  let now = Date.now(),
    verified = 0;
  context.mock.method(Date, 'now', () => now);
  context.mock.method(
    SignedXml.prototype,
    'checkSignature',
    function (this: SignedXml, input: string) {
      const result = Reflect.apply(native, this, [input]);
      assert.equal(result, true);
      verified++;
      now = expiry + 1;
      return result;
    },
  );
  assert.throws(() => verifySamlMetadataSignature(xml, configuration, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
  assert.equal(verified, 1);
});

test('Native verification cannot authorize missing or differently bound authenticated reference evidence', (context) => {
  const xml = signed(),
    configuration = profile(),
    native = SignedXml.prototype.getSignedReferences;
  let substitute: 'missing' | 'identity' | 'id' = 'missing',
    calls = 0;
  context.mock.method(SignedXml.prototype, 'getSignedReferences', function (this: SignedXml) {
    const references = Reflect.apply(native, this, []) as string[];
    assert.equal(
      references.length,
      1,
      'The actual signature must authenticate exactly one reference',
    );
    calls++;
    if (substitute === 'missing') return [];
    return [
      references[0]!.replace(
        substitute === 'identity' ? 'https://idp.example.test' : 'metadata_root',
        substitute === 'identity' ? 'https://foreign.example.test' : 'different_root',
      ),
    ];
  });
  for (substitute of ['missing', 'identity', 'id'] as const)
    assert.throws(() => verifySamlMetadataSignature(xml, configuration, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  assert.equal(calls, 3);
});

test('Valid signatures cannot bypass expiry, issuer, role, ID, algorithm and wrapping policy', () => {
  const p = profile();
  for (const xml of [
    signed({ entity: 'https://foreign.example.test' }),
    signed({ role: 'sp' }),
    signed({ expiry: new Date(Date.now() - 1).toISOString() }),
    signed({ expiry: '2026-02-30T00:00:00Z' }),
    signed({ expiry: '' }),
    signed({ expiry: '2999-12-31T00:00:00' }),
    signed({ algorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' }),
    signed({ digest: 'http://www.w3.org/2000/09/xmldsig#sha1' }),
    signed({ extra: `<md:SPSSODescriptor protocolSupportEnumeration="${protocol}"/>` }),
    signed({ extra: '<md:Extensions><other ID="metadata_root"/></md:Extensions>' }),
    signed({ extra: '<md:Extensions><?unsafe data?></md:Extensions>' }),
    '<wrapper>' + signed() + '</wrapper>',
    `<md:EntitiesDescriptor xmlns:md="${md}">` + signed() + '</md:EntitiesDescriptor>',
    '<?unsafe data?>' + signed(),
  ])
    assert.throws(() => verifySamlMetadataSignature(xml, p, 'idp'), { code: 'EK_EID_FEDERATION' });
});

test('External references, malformed XML, DTDs and bounded parser limits fail closed before any resource discovery', () => {
  const xml = signed(),
    p = profile();
  for (const value of [
    '',
    null,
    xml + '\0',
    'not XML',
    '\ud800' + xml,
    verifySamlMetadataSignature(xml, p, 'idp').verifiedXml,
    '<!DOCTYPE a [<!ENTITY b SYSTEM "file:///private-material">]>' + xml,
    xml.replace('URI="#metadata_root"', 'URI="https://unapproved.example.test/material"'),
    xml.replace('URI="#metadata_root"', 'URI="#another-node"'),
    xml.replace('ID="metadata_root"', 'ID="invalid id"'),
    xml.replace('ID="metadata_root"', 'Id="metadata_root"'),
    xml.replace(
      'protocolSupportEnumeration="' + protocol + '"',
      'protocolSupportEnumeration="unapproved"',
    ),
    xml.replace(enveloped, 'http://www.w3.org/TR/1999/REC-xslt-19991116'),
    'x'.repeat(65537),
    signed({
      extra: '<md:Extensions>' + '<x>'.repeat(34) + '</x>'.repeat(34) + '</md:Extensions>',
    }),
    signed({ extra: '<md:Extensions>' + '<x/>'.repeat(8193) + '</md:Extensions>' }),
    signed({
      extra:
        '<md:Extensions><x ' +
        Array.from({ length: 33 }, (_, index) => 'a' + index + '="x"').join(' ') +
        '/></md:Extensions>',
    }),
    signed({ extra: `<md:IDPSSODescriptor protocolSupportEnumeration="${protocol}"/>` }),
  ])
    assert.throws(() => verifySamlMetadataSignature(value as string, p, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  assert.throws(() =>
    verifySamlMetadataSignature(
      xml,
      {
        ...p,
        protocol: 'oidc-federation',
        clientId: p.entityId,
        samlRegistration: undefined,
      } as never,
      'idp',
    ),
  );
});
