import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, COMPONENTS, KitError, APPLICATION_SIGNAL } from '@arkenivajs/core';
import { PREPARE_PLUGIN, ACTIVATE_PLUGIN, DRAIN_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';

const service = { name: 'composition-test', version: '1.0.0', environment: 'test' as const };
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;

test('EK-CORE-001 resource-free facades exist before startup and listeners activate after all resources', async () => {
  const events: string[] = [];
  const endpoint: ComposablePlugin = {
    id: 'endpoint',
    version: '1.0.0',
    capabilities: new Set(['api']),
    [PREPARE_PLUGIN](context) {
      assert.ok(Object.isFrozen(context));
      assert.ok(Object.isFrozen(context.options));
      events.push('prepare');
      return new Map([[COMPONENTS.api, { registrations: [] as string[], state: context.state }]]);
    },
    init(context) {
      events.push('endpoint.init');
      assert.equal(
        context.require<{ state: () => string }>(COMPONENTS.api).state(),
        'INITIALIZING',
      );
    },
    [ACTIVATE_PLUGIN]() {
      events.push('endpoint.activate');
    },
    close() {
      events.push('endpoint.close');
    },
  };
  const resource: ComposablePlugin = {
    id: 'resource',
    version: '1.0.0',
    capabilities: new Set(),
    dependencies: ['endpoint'],
    init(context) {
      events.push('resource.init');
      context.require<{ registrations: string[] }>(COMPONENTS.api).registrations.push('/example');
    },
    [ACTIVATE_PLUGIN]() {
      events.push('resource.activate');
    },
    close() {
      events.push('resource.close');
    },
  };
  const app = await createApplication({ service, plugins: [endpoint, resource] });
  const facade = app.api as unknown as { registrations: string[]; state: () => string };
  assert.equal(facade.state(), 'CREATED');
  assert.deepEqual(events, ['prepare']);
  await app.start();
  assert.deepEqual(facade.registrations, ['/example']);
  assert.deepEqual(events, [
    'prepare',
    'endpoint.init',
    'resource.init',
    'resource.activate',
    'endpoint.activate',
  ]);
  assert.equal(facade.state(), 'READY');
  await app.stop();
  assert.deepEqual(events.slice(-2), ['resource.close', 'endpoint.close']);
});

test('EK-CORE-002 prepared facades remain isolated when the same plugin factory is reused', async () => {
  const plugin: ComposablePlugin = {
    id: 'endpoint',
    version: '1.0.0',
    capabilities: new Set(['api']),
    [PREPARE_PLUGIN]() {
      return new Map([[COMPONENTS.api, {}]]);
    },
    init() {},
    close() {},
  };
  const first = await createApplication({ service, plugins: [plugin] });
  const second = await createApplication({ service, plugins: [plugin] });
  assert.notEqual(first.api, second.api);
  await first.stop();
  await second.stop();
});

test('EK-CORE-001 activation failures and cancellation roll back initialized resources exactly once', async () => {
  for (const cancel of [false, true]) {
    let closed = 0,
      initialized!: () => void;
    const activation = new Promise<void>((resolve) => {
      initialized = resolve;
    });
    const plugin: ComposablePlugin = {
      id: 'endpoint',
      version: '1.0.0',
      capabilities: new Set(['api']),
      [PREPARE_PLUGIN]() {
        return new Map([[COMPONENTS.api, {}]]);
      },
      init() {},
      [ACTIVATE_PLUGIN](context) {
        initialized();
        if (!cancel) throw new Error('fake-activation');
        return new Promise<void>((_resolve, reject) =>
          context
            .require<AbortSignal>(APPLICATION_SIGNAL)
            .addEventListener('abort', () => reject(new Error('cancelled')), { once: true }),
        );
      },
      close() {
        closed++;
      },
    };
    const app = await createApplication({ service, plugins: [plugin] });
    const starting = app.start();
    const rejected = assert.rejects(starting, code(cancel ? 'EK_ABORTED' : 'EK_PLUGIN_FAILED'));
    await activation;
    if (cancel) await app.stop();
    await rejected;
    assert.equal(app.state, 'CLOSED');
    assert.equal(closed, 1);
    await app.stop();
    assert.equal(closed, 1);
  }
});

test('EK-CORE-002 malformed composition hooks and undeclared prepared components reject', async () => {
  const base = {
    id: 'endpoint',
    version: '1.0.0',
    capabilities: new Set(['api']),
    init() {},
    close() {},
  };
  for (const plugin of [
    { ...base, [PREPARE_PLUGIN]: 1 },
    { ...base, [ACTIVATE_PLUGIN]: 1 },
    { ...base, [DRAIN_PLUGIN]: 1 },
    { ...base, [PREPARE_PLUGIN]: () => null },
    { ...base, [PREPARE_PLUGIN]: () => new Map([[COMPONENTS.logger, {}]]) },
    { ...base, [PREPARE_PLUGIN]: () => new Map([[COMPONENTS.api, null]]) },
  ])
    await assert.rejects(
      createApplication({ service, plugins: [plugin as never] }),
      (error) => error instanceof KitError,
    );
  const repeated: ComposablePlugin = {
    ...base,
    [PREPARE_PLUGIN]: () =>
      [
        [COMPONENTS.api, {}],
        [COMPONENTS.api, {}],
      ] as unknown as ReadonlyMap<symbol, unknown>,
  };
  await assert.rejects(
    createApplication({ service, plugins: [repeated] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
});

test('EK-CORE-001 inbound drain precedes reverse cleanup and failures do not skip close', async () => {
  for (const fail of [false, true]) {
    const events: string[] = [];
    const listener: ComposablePlugin = {
      id: 'listener',
      version: '1.0.0',
      capabilities: new Set(),
      init() {},
      [DRAIN_PLUGIN]() {
        events.push('drain');
        if (fail) throw new Error('drain failed');
      },
      close() {
        events.push('listener.close');
      },
    };
    const resource: ComposablePlugin = {
      id: 'resource',
      version: '1.0.0',
      capabilities: new Set(),
      init() {},
      close() {
        events.push('resource.close');
      },
    };
    const app = await createApplication({ service, plugins: [listener, resource] });
    await app.start();
    if (fail) await assert.rejects(app.stop(), code('EK_PLUGIN_FAILED'));
    else await app.stop();
    assert.deepEqual(events, ['drain', 'resource.close', 'listener.close']);
    assert.equal(app.state, 'CLOSED');
  }
});

test('MFA-AUTH-001 executable assurance policy is immutable wiring, outside configuration snapshots and reloads', async () => {
  const resolver = () => 'mfa' as const;
  let observed = false;
  const plugin: ComposablePlugin = {
    id: 'policy',
    version: '1.0.0',
    capabilities: new Set(['auth']),
    init(context) {
      observed = true;
      assert.equal(context.options.security!.assuranceResolver, resolver);
      assert.ok(Object.isFrozen(context.options.security));
    },
    close() {},
  };
  const security = {
    issuer: 'https://issuer.invalid',
    audience: 'api',
    assuranceResolver: resolver,
  };
  const app = await createApplication({ service, security, plugins: [plugin] });
  security.assuranceResolver = () => 'single-factor' as never;
  try {
    assert.deepEqual(app.config.get('security'), {
      issuer: 'https://issuer.invalid',
      audience: 'api',
    });
    assert.ok(!JSON.stringify(app.config.snapshot()).includes('assuranceResolver'));
    await assert.rejects(
      app.config.reload({ security: { assuranceResolver: () => 'mfa' } }),
      code('EK_CONFIG_RELOAD_REJECTED'),
    );
    await app.start();
    assert.equal(observed, true);
  } finally {
    await app.stop();
  }
  let accessed = false;
  const accessor = Object.defineProperty(
    { issuer: 'https://issuer.invalid', audience: 'api' },
    'assuranceResolver',
    {
      enumerable: true,
      get() {
        accessed = true;
        return resolver;
      },
    },
  );
  for (const input of [accessor, { ...security, assuranceResolver: 'mfa' }])
    await assert.rejects(
      createApplication({ service, security: input as never, plugins: [plugin] }),
      code('EK_MFA_POLICY'),
    );
  assert.equal(accessed, false);
  await assert.rejects(
    createApplication({
      service,
      security: { ...security, other: resolver } as never,
      plugins: [plugin],
    }),
    code('EK_CONFIG_INVALID'),
  );
});
