// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { verify, X509Certificate } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { samlLoginFixture } from '../fixtures/saml-login.js';
import { closeRegistryFixture } from '../fixtures/saml-metadata.js';
import { FederationSamlLogin } from '../../dist/saml-login.js';
import { FederationCall, FederationRuntime } from '../../dist/runtime.js';
import { FederationTransactions } from '../../dist/transactions.js';
import { FederationSamlRegistry } from '../../dist/saml-registry.js';
import { withFederationSaml } from '../../dist/saml-native.js';
import { parseSamlMetadataXml } from '../../dist/saml-metadata-signature.js';

after(closeRegistryFixture);
function request(redirect: string, certificate: string) {
  const target = new URL(redirect),
    signature = target.searchParams.get('Signature')!,
    signed = target.search
      .slice(1)
      .split('&')
      .filter((part) => !part.startsWith('Signature='))
      .join('&');
  assert.equal(
    verify(
      'RSA-SHA256',
      Buffer.from(signed),
      new X509Certificate(certificate).publicKey,
      Buffer.from(signature, 'base64'),
    ),
    true,
  );
  const xml = inflateRawSync(
    Buffer.from(target.searchParams.get('SAMLRequest')!, 'base64'),
  ).toString();
  return { target, xml, root: parseSamlMetadataXml(xml, 65536).documentElement };
}

test('Native login preserves omitted hints and bounded defaults without accepting incomplete protocol settings', async () => {
  const f = await samlLoginFixture();
  try {
    const settings = { ...f.settings, policy: { maxConcurrent: 8, timeoutMs: 10000 } },
      login = new FederationSamlLogin(
        settings,
        f.document.profile.profileId,
        f.transport,
        f.crypto,
      ),
      result = await f.runtime.run((call) =>
        login.begin(call, {
          issuer: f.input.issuer,
          assurance: f.input.assurance,
          returnPath: '/',
        }),
      ),
      state = await f.runtime.run((call) =>
        f.transactions.consume(call, result.transactionId, f.input.issuer),
      );
    assert.equal(Object.hasOwn(state, 'tenantHint'), false);
    request(result.redirectUrl, f.document.first.pem);
    const { samlRegistration, ...withoutRegistration } = f.document.profile;
    void samlRegistration;
    for (const profile of [
      withoutRegistration,
      { ...f.document.profile, protocol: 'oidc-federation' as const },
    ])
      assert.throws(
        () =>
          new FederationSamlLogin(
            { ...f.settings, profiles: [profile] },
            profile.profileId,
            f.transport,
            f.crypto,
          ),
        { code: 'EK_EID_PROFILE' },
      );
  } finally {
    await f.close();
  }
});

test('An unexpected binding after real native signing is rejected before protected login delivery', async (context) => {
  const f = await samlLoginFixture(),
    step = FederationCall.prototype.step;
  let changed = 0;
  context.mock.method(FederationCall.prototype, 'step', async function <
    T,
  >(this: FederationCall, work: Parameters<FederationCall['step']>[0]): Promise<T> {
    const result = await Reflect.apply(step, this, [work]);
    if (
      result &&
      typeof result === 'object' &&
      'binding' in result &&
      result.binding === 'redirect' &&
      'redirectUrl' in result &&
      typeof result.redirectUrl === 'string'
    ) {
      request(result.redirectUrl, f.document.first.pem);
      changed++;
      return { ...result, binding: 'post' } as T;
    }
    return result as T;
  });
  try {
    await assert.rejects(() => f.runtime.run((call) => f.login.begin(call, f.input)), {
      code: 'EK_EID_PROFILE',
    });
    assert.equal(changed, 1);
    assert.equal(
      [...f.rows.keys()].some((key) => JSON.parse(key)[0] === 'arkenivajs.spid.authorization.v1'),
      false,
    );
  } finally {
    await f.close();
  }
});

test('A trust snapshot expiring after actual encrypted persistence cannot produce a login result', async (context) => {
  const f = await samlLoginFixture(),
    create = FederationTransactions.prototype.create;
  let now = Date.now(),
    persisted = 0;
  context.mock.method(Date, 'now', () => now);
  context.mock.method(
    FederationTransactions.prototype,
    'create',
    async function (
      this: FederationTransactions,
      ...args: Parameters<FederationTransactions['create']>
    ) {
      const result = await Reflect.apply(create, this, args);
      persisted++;
      now += 120000;
      return result;
    },
  );
  try {
    await assert.rejects(() => f.runtime.run((call) => f.login.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(persisted, 1);
  } finally {
    await f.close();
  }
});

test('Native composition cannot reuse RP and IdP receipts with another role, registration or assurance policy', async () => {
  const f = await samlLoginFixture(),
    registry = new FederationSamlRegistry(f.document.profile, f.transport);
  try {
    await f.runtime.run(async (call) => {
      const rp = await registry.verify(call, f.document.entity, 'sp'),
        idp = await registry.verify(call, f.document.issuer, 'idp');
      const { samlRegistration, ...withoutRegistration } = f.document.profile;
      void samlRegistration;
      for (const [profile, first, second] of [
        [withoutRegistration, rp, idp],
        [f.document.profile, idp, rp],
        [{ ...f.document.profile, entityId: 'https://foreign.example.test' }, rp, idp],
        [f.document.profile, rp, rp],
        [{ ...f.document.profile, expectedIssuers: ['https://foreign.example.test'] }, rp, idp],
        [{ ...f.document.profile, allowedAssurance: ['spid-l3' as const] }, rp, idp],
      ] as const)
        await assert.rejects(
          () =>
            withFederationSaml(
              call,
              f.settings,
              profile,
              registry,
              first,
              second,
              'spid-l2',
              async () => 'not-admitted',
            ),
          { code: 'EK_EID_FEDERATION' },
        );
    });
    assert.equal(f.references.length, 0);
  } finally {
    await f.close();
  }
});

test('RP and IdP metadata share one cumulative operation budget before native login admission', async () => {
  const f = await samlLoginFixture();
  try {
    const documents = [
        f.document.xml('sp'),
        f.document.status('sp'),
        f.document.xml('idp'),
        f.document.status('idp'),
      ],
      maxBytes = documents.reduce((sum, value) => sum + Buffer.byteLength(value), 0) - 1,
      profile = { ...f.document.profile, metadata: { ...f.document.profile.metadata, maxBytes } },
      registry = new FederationSamlRegistry(profile, f.transport);
    await assert.rejects(
      () =>
        f.runtime.run(async (call) => {
          await registry.verify(call, f.document.entity, 'sp');
          await registry.verify(call, f.document.issuer, 'idp');
        }),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(f.references.length, 0);
    const malformed = new FederationSamlRegistry(f.document.profile, {
      ...f.transport,
      async samlMetadata() {
        return {} as string;
      },
    });
    await assert.rejects(
      () => f.runtime.run((call) => malformed.verify(call, f.document.entity, 'sp')),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});

test('Native SPID login signs the Redirect request and encrypts its exact correlation and private context', async () => {
  const f = await samlLoginFixture();
  try {
    const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
      wire = request(login.redirectUrl, f.document.first.pem),
      id = wire.root.getAttribute('ID')!;
    assert.match(login.transactionId, /^[a-f0-9]{64}$/u);
    assert.equal(wire.target.origin + wire.target.pathname, 'https://idp.example.test/login');
    assert.equal(wire.target.searchParams.get('RelayState'), id);
    assert.equal(wire.root.getAttribute('ForceAuthn'), 'true');
    assert.ok(wire.xml.includes('https://www.spid.gov.it/SpidL2'));
    assert.ok(wire.xml.includes('NameQualifier="' + f.document.entity + '"'));
    assert.equal(wire.xml.includes('AllowCreate'), false);
    const raw = JSON.stringify([...f.rows]);
    for (const value of [login.transactionId, f.input.returnPath, f.input.tenantHint])
      assert.equal(raw.includes(value), false);
    const privateRows = [...f.rows].filter(
      ([key]) => JSON.parse(key)[0] === 'arkenivajs.spid.authorization.v1',
    );
    assert.equal(privateRows.length, 1);
    assert.equal(JSON.stringify(privateRows).includes(id), false);
    assert.equal(wire.xml.includes(f.input.returnPath), false);
    const native = [...f.rows.values()].find((row) => row.kind === 'login')!;
    assert.equal(native.returnPath, '/');
    const protectedState = await f.runtime.run((call) =>
      f.transactions.consume(call, login.transactionId, f.document.issuer),
    );
    assert.equal(protectedState.samlRequestId, id);
    assert.equal(protectedState.returnPath, f.input.returnPath);
    assert.equal(protectedState.tenantHint, f.input.tenantHint);
    assert.ok(Date.parse(login.expiresAt) <= Date.parse(protectedState.expiresAt));
    assert.equal(f.runtime.stats().active, 0);
  } finally {
    await f.close();
  }
});

test('Registered certificate rotation succeeds while a matching but unregistered key pair fails before redirect delivery', async () => {
  for (const registered of [true, false]) {
    const f = await samlLoginFixture();
    try {
      f.state.rotateAfterBootstrap = true;
      f.state.registeredBoth = registered;
      if (registered) {
        const login = await f.runtime.run((call) => f.login.begin(call, f.input));
        request(login.redirectUrl, f.document.second.pem);
        assert.ok(f.state.certificateReads >= 2);
      } else {
        await assert.rejects(() => f.runtime.run((call) => f.login.begin(call, f.input)));
        assert.equal(
          [...f.rows.keys()].some(
            (key) => JSON.parse(key)[0] === 'arkenivajs.spid.authorization.v1',
          ),
          false,
        );
      }
    } finally {
      await f.close();
    }
  }
});

test('RP and IdP withdrawal deny login before signing keys or one-use login state are created', async () => {
  for (const role of ['revokedRp', 'revokedIdp'] as const) {
    const f = await samlLoginFixture();
    try {
      f.state[role] = true;
      await assert.rejects(() => f.runtime.run((call) => f.login.begin(call, f.input)), {
        code: 'EK_EID_FEDERATION',
      });
      assert.equal(f.references.length, 0);
      assert.equal(f.rows.size, 0);
    } finally {
      await f.close();
    }
  }
});

test('Native login rejects malformed inputs and executable context before metadata or credential work', async () => {
  const f = await samlLoginFixture();
  let hooks = 0;
  try {
    for (const input of [
      null,
      { ...f.input, assurance: 'cie-l2' },
      { ...f.input, issuer: 'https://foreign.example.test' },
      { ...f.input, returnPath: '//foreign.example.test' },
      {
        ...f.input,
        get tenantHint() {
          hooks++;
          throw new Error('Executable pre-session context');
        },
      },
    ])
      await assert.rejects(() => f.runtime.run((call) => f.login.begin(call, input as never)));
    assert.equal(hooks, 0);
    assert.equal(f.paths.length, 0);
    assert.equal(f.references.length, 0);
    assert.throws(
      () => new FederationSamlLogin(f.settings, 'missing-profile', f.transport, f.crypto),
      { code: 'EK_EID_PROFILE' },
    );
    const limited = new FederationSamlLogin(
      { ...f.settings, policy: { ...f.settings.policy, maxInputBytes: 1 } },
      f.document.profile.profileId,
      f.transport,
      f.crypto,
    );
    await assert.rejects(() => f.runtime.run((call) => limited.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.equal(f.paths.length, 0);
  } finally {
    await f.close();
  }
});

test('Provider and ambiguous protected-state persistence failures cannot deliver a signed login result', async () => {
  const f = await samlLoginFixture();
  try {
    f.state.unavailable = true;
    await assert.rejects(
      () => f.runtime.run((call) => f.login.begin(call, f.input)),
      (error: unknown) => {
        assert.equal(JSON.stringify(error).includes('fixture secret provider'), false);
        return true;
      },
    );
    f.state.unavailable = false;
    const settings = {
        ...f.settings,
        stateStore: {
          ...f.settings.stateStore,
          store: {
            ...f.settings.stateStore.store,
            async compareAndSet(
              ...args: Parameters<typeof f.settings.stateStore.store.compareAndSet>
            ) {
              const result = await f.settings.stateStore.store.compareAndSet(...args);
              if (args[0] === 'arkenivajs.spid.authorization.v1')
                throw new Error('The protected write acknowledgement was lost');
              return result;
            },
          },
        },
      },
      login = new FederationSamlLogin(
        settings,
        f.document.profile.profileId,
        f.transport,
        f.crypto,
      );
    await assert.rejects(() => f.runtime.run((call) => login.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
    assert.ok(
      [...f.rows.keys()].some((key) => JSON.parse(key)[0] === 'arkenivajs.spid.authorization.v1'),
    );
    assert.equal(JSON.stringify([...f.rows]).includes(f.input.tenantHint), false);
  } finally {
    await f.close();
  }
});

test('An aborted native login retains global capacity until an ignoring secret provider physically settles', async () => {
  const f = await samlLoginFixture(),
    runtime = new FederationRuntime({ maxConcurrent: 1, timeoutMs: 10000 }),
    stop = new AbortController();
  let entered!: () => void, release!: () => void;
  const reached = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    held = new Promise<void>((resolve) => {
      release = resolve;
    });
  const settings = {
      ...f.settings,
      secretProvider: {
        async get(...args: Parameters<typeof f.settings.secretProvider.get>) {
          if (args[0] === f.document.profile.signingKeyRef) {
            entered();
            await held;
          }
          return f.settings.secretProvider.get(...args);
        },
      },
    },
    login = new FederationSamlLogin(settings, f.document.profile.profileId, f.transport, f.crypto);
  try {
    const pending = runtime.run((call) => login.begin(call, f.input), { signal: stop.signal }),
      rejected = assert.rejects(pending, { code: 'EK_ABORTED' });
    await reached;
    stop.abort();
    await rejected;
    assert.equal(runtime.stats().active, 1);
    await assert.rejects(() => runtime.run(async () => 'not-admitted'), {
      code: 'EK_BACKEND_UNAVAILABLE',
    });
    release();
    await runtime.close();
    assert.equal(runtime.stats().active, 0);
  } finally {
    release();
    await runtime.close();
    await f.close();
  }
});

test('Malformed external certificate bytes and executable material cannot pass native signing admission', async () => {
  const f = await samlLoginFixture();
  let hooks = 0;
  try {
    const proxy = new Proxy(Buffer.from(f.document.first.pem), {
        get() {
          hooks++;
          throw new Error('Executable certificate bytes');
        },
      }),
      values = [
        'not-bytes',
        new Uint8Array(0),
        new Uint8Array(32769),
        new Uint8Array(new SharedArrayBuffer(32)),
        proxy,
        {
          get bytes() {
            hooks++;
            throw new Error('Executable certificate material');
          },
        },
      ];
    for (const value of values) {
      const settings = {
          ...f.settings,
          secretProvider: {
            async get(...args: Parameters<typeof f.settings.secretProvider.get>) {
              if (args[0] !== f.document.profile.samlRegistration!.signingCertificateRef)
                return f.settings.secretProvider.get(...args);
              return (
                value === values[values.length - 1]
                  ? value
                  : { bytes: value, keyVersion: 'fixture' }
              ) as never;
            },
          },
        },
        login = new FederationSamlLogin(
          settings,
          f.document.profile.profileId,
          f.transport,
          f.crypto,
        );
      await assert.rejects(() => f.runtime.run((call) => login.begin(call, f.input)));
    }
    assert.equal(hooks, 0);
    assert.equal(
      [...f.rows.keys()].some((key) => JSON.parse(key)[0] === 'arkenivajs.spid.authorization.v1'),
      false,
    );
    const production = new FederationSamlLogin(
      { ...f.settings, environment: 'production' },
      f.document.profile.profileId,
      f.transport,
      f.crypto,
    );
    const before = f.references.length;
    await assert.rejects(() => f.runtime.run((call) => production.begin(call, f.input)), {
      code: 'EK_EID_PROFILE',
    });
    assert.equal(f.references.length, before);
  } finally {
    await f.close();
  }
});

test('Native login honors output bounds and certificate snapshots never read shadowed byte properties', async () => {
  const f = await samlLoginFixture();
  let hooks = 0;
  try {
    const settings = {
        ...f.settings,
        secretProvider: {
          async get(...args: Parameters<typeof f.settings.secretProvider.get>) {
            const value = await f.settings.secretProvider.get(...args);
            if (args[0] === f.document.profile.samlRegistration!.signingCertificateRef)
              for (const key of ['byteLength', 'buffer', Symbol.iterator])
                Object.defineProperty(value.bytes, key, {
                  get() {
                    hooks++;
                    throw new Error('Shadowed byte properties must remain unread');
                  },
                });
            return { ...value, expiresAt: new Date(Date.now() + 3600000).toISOString() };
          },
        },
      },
      login = new FederationSamlLogin(
        settings,
        f.document.profile.profileId,
        f.transport,
        f.crypto,
      );
    const accepted = await f.runtime.run((call) => login.begin(call, f.input));
    request(accepted.redirectUrl, f.document.first.pem);
    assert.equal(hooks, 0);
    const limited = new FederationSamlLogin(
      { ...f.settings, policy: { ...f.settings.policy, maxOutputBytes: 1 } },
      f.document.profile.profileId,
      f.transport,
      f.crypto,
    );
    await assert.rejects(() => f.runtime.run((call) => limited.begin(call, f.input)), {
      code: 'EK_EID_FEDERATION',
    });
  } finally {
    await f.close();
  }
});
