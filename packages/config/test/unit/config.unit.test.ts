// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createConfig, configPlugin } from '@arkenivajs/config';
import { createApplication, KitError } from '@arkenivajs/core';

const schema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    count: { type: 'integer', minimum: 0, maximum: 100 },
    enabled: { type: 'boolean' },
    nullable: { type: ['string', 'null'] },
    nested: {
      type: 'object',
      additionalProperties: false,
      properties: { value: { type: 'number' }, password: { type: 'string' } },
    },
    token: { type: 'string' },
    custom: { type: 'string' },
  },
};
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
const setup = { schema, workspace: process.cwd(), environment: {} };

test('EK-CONF-001 committed overrides and reloads emit metadata without keys or values', async () => {
  const events: unknown[] = [];
  const config = await createConfig<{ count: number; custom: string }>({
    ...setup,
    defaults: { count: 1, custom: 'fake-private-default' },
    yamlText: 'count: 2\ncustom: fake-private-yaml',
    environment: { ARKENIVAJS_COUNT: '3' },
    environmentFields: { ARKENIVAJS_COUNT: { path: 'count', type: 'integer' } },
    runtime: { count: 4 },
    dynamicPaths: ['count'],
    onDiagnostic(event) {
      assert.ok(Object.isFrozen(event));
      events.push(event);
    },
  });
  assert.deepEqual(events, [
    { event: 'configuration.override.applied', source: 'yaml', keyCount: 2 },
    { event: 'configuration.override.applied', source: 'environment', keyCount: 1 },
    { event: 'configuration.override.applied', source: 'runtime', keyCount: 1 },
  ]);
  await config.reload({ count: 5 });
  assert.deepEqual(events.at(-1), {
    event: 'configuration.reload.applied',
    source: 'reload',
    keyCount: 1,
  });
  const count = events.length;
  await assert.rejects(config.reload({ count: -1 }), code('EK_CONFIG_RELOAD_REJECTED'));
  await assert.rejects(
    createConfig({
      ...setup,
      defaults: { count: 1 },
      runtime: { count: -1 },
      onDiagnostic(event) {
        events.push(event);
      },
    }),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(events.length, count);
  assert.ok(!JSON.stringify(events).includes('fake-private'));
  assert.ok(!JSON.stringify(events).includes('custom'));
});

test('EK-CONF-001 precedence is defaults then YAML then explicit env then runtime', async () => {
  const c = await createConfig<Record<string, unknown>>({
    ...setup,
    defaults: { count: 1, enabled: false },
    yamlText: 'count: 2\nenabled: true',
    environment: { ARKENIVAJS_COUNT: '3' },
    environmentFields: { ARKENIVAJS_COUNT: { path: 'count', type: 'integer' } },
    runtime: { count: 4 },
  });
  assert.equal(c.get('count'), 4);
  assert.equal(c.require('enabled'), true);
  assert.equal(c.has('count'), true);
  assert.equal(c.get('absent' as 'count'), undefined);
  assert.equal(c.has('absent' as 'count'), false);
  assert.throws(() => c.require('absent' as 'count'), code('EK_CONFIG_MISSING'));
});

test('EK-CONF-001 null is present but cannot satisfy require', async () => {
  const c = await createConfig<Record<string, unknown>>({ ...setup, runtime: { nullable: null } });
  assert.equal(c.has('nullable'), true);
  assert.equal(c.get('nullable'), null);
  assert.throws(() => c.require('nullable'), code('EK_CONFIG_MISSING'));
});

test('EK-CONF-001 secrets are environment-only and snapshots redact recursively', async () => {
  const c = await createConfig<Record<string, unknown>>({
    ...setup,
    secretPaths: ['custom'],
    environment: {
      ARKENIVAJS_TOKEN: 'fake-token',
      ARKENIVAJS_PASSWORD: 'fake-password',
      ARKENIVAJS_CUSTOM: 'fake-custom',
    },
    environmentFields: {
      ARKENIVAJS_TOKEN: { path: 'token', type: 'string' },
      ARKENIVAJS_PASSWORD: { path: 'nested.password', type: 'string' },
      ARKENIVAJS_CUSTOM: { path: 'custom', type: 'string' },
    },
  });
  assert.equal(c.get('token'), 'fake-token');
  assert.ok(!JSON.stringify(c.snapshot()).includes('fake-'));
  assert.ok(Object.isFrozen(c.snapshot()));
  assert.ok(Object.isFrozen(c.snapshot().nested));
  for (const layer of ['defaults', 'runtime'] as const)
    await assert.rejects(
      createConfig({ ...setup, [layer]: { token: 'fake-token' } }),
      code('EK_CONFIG_INVALID'),
    );
  await assert.rejects(
    createConfig({ ...setup, yamlText: 'nested:\n  password: fake-password' }),
    code('EK_CONFIG_INVALID'),
  );
});

test('EK-CONF-001 malformed YAML, aliases, duplicate keys and unknown keys reject', async () => {
  for (const yamlText of [
    '[invalid',
    'count: 1\ncount: 2',
    'null',
    '[]',
    'count: wrong',
    'unknown: true',
    'nested: &data {value: 1}\ncustom: *data',
    'custom: !unknown value',
  ])
    await assert.rejects(createConfig({ ...setup, yamlText }), code('EK_CONFIG_INVALID'));
  await assert.rejects(
    createConfig({ ...setup, yamlText: 'x'.repeat(1_048_577) }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    createConfig({ ...setup, yamlText: '{}', yamlFile: 'config.yaml' }),
    code('EK_CONFIG_INVALID'),
  );
});

test('EK-CONF-001 environment parsing rejects coercion and mapping conflicts', async () => {
  for (const [type, bad] of [
    ['integer', '1garbage'],
    ['integer', '1.1'],
    ['integer', '9007199254740993'],
    ['number', 'NaN'],
    ['number', '1e999'],
    ['boolean', 'TRUE'],
    ['json', '{bad'],
  ] as const) {
    await assert.rejects(
      createConfig({
        ...setup,
        environment: { ARKENIVAJS_VALUE: bad },
        environmentFields: { ARKENIVAJS_VALUE: { path: 'count', type } },
      }),
      code('EK_CONFIG_INVALID'),
    );
  }
  await assert.rejects(
    createConfig({ ...setup, environment: { ARKENIVAJS_UNKNOWN: 'value' } }),
    code('EK_CONFIG_INVALID'),
  );
  for (const path of ['__proto__.value', 'nested.constructor', 'count..invalid'])
    await assert.rejects(
      createConfig({
        ...setup,
        environment: { ARKENIVAJS_VALUE: '1' },
        environmentFields: { ARKENIVAJS_VALUE: { path, type: 'integer' } },
      }),
      code('EK_CONFIG_INVALID'),
    );
  await assert.rejects(
    createConfig({
      ...setup,
      environment: { ARKENIVAJS_A: '1', ARKENIVAJS_B: '2' },
      environmentFields: {
        ARKENIVAJS_A: { path: 'count', type: 'integer' },
        ARKENIVAJS_B: { path: 'count', type: 'integer' },
      },
    }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    createConfig({
      ...setup,
      environment: { ARKENIVAJS_A: '1', ARKENIVAJS_B: '2' },
      environmentFields: {
        ARKENIVAJS_A: { path: 'count', type: 'integer' },
        ARKENIVAJS_B: { path: 'count.value', type: 'integer' },
      },
    }),
    code('EK_CONFIG_INVALID'),
  );
  const c = await createConfig<Record<string, unknown>>({
    ...setup,
    environment: {
      OTHER: 'ignored',
      ARKENIVAJS_SKIP: undefined,
      ARKENIVAJS_BOOL: 'false',
      ARKENIVAJS_JSON: '{"value":1.5}',
    },
    environmentFields: {
      ARKENIVAJS_BOOL: { path: 'enabled', type: 'boolean' },
      ARKENIVAJS_JSON: { path: 'nested', type: 'json' },
    },
  });
  assert.equal(c.get('enabled'), false);
  assert.deepEqual(c.get('nested'), { value: 1.5 });
  const number = await createConfig({
    ...setup,
    environment: { ARKENIVAJS_NUMBER: '1.5' },
    environmentFields: { ARKENIVAJS_NUMBER: { path: 'nested.value', type: 'number' } },
  });
  assert.deepEqual(number.get('nested'), { value: 1.5 });
});

test('EK-CONF-001 files are confined to approved workspace including symlinks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-config-'));
  try {
    const workspace = join(root, 'workspace');
    const { mkdir } = await import('node:fs/promises');
    await mkdir(workspace);
    await writeFile(join(workspace, 'valid.yaml'), 'count: 7');
    await writeFile(join(root, 'outside.yaml'), 'count: 8');
    await symlink(join(root, 'outside.yaml'), join(workspace, 'escape.yaml'));
    const c = await createConfig<Record<string, unknown>>({
      ...setup,
      workspace,
      yamlFile: 'valid.yaml',
    });
    assert.equal(c.get('count'), 7);
    for (const yamlFile of ['../outside.yaml', 'escape.yaml', 'absent.yaml'])
      await assert.rejects(
        createConfig({ ...setup, workspace, yamlFile }),
        code('EK_CONFIG_INVALID'),
      );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('EK-CONF-001 config plugin exposes the validated store without implicit globals', async () => {
  const config = await createConfig<Record<string, unknown>>({ ...setup, runtime: { count: 42 } });
  const app = await createApplication({
    service: { name: 'config-test', version: '1.0.0', environment: 'test' },
    plugins: [configPlugin(config)],
  });
  await app.start();
  assert.equal(app.config.get('count'), 42);
  await app.stop();
});

test('EK-CONF-001 malformed runtime layers and whitespace numeric values reject', async () => {
  for (const runtime of [null, [], 'value', 1, false])
    await assert.rejects(
      createConfig({ ...setup, runtime: runtime as never }),
      code('EK_CONFIG_INVALID'),
    );
  await assert.rejects(
    createConfig({
      ...setup,
      environment: { ARKENIVAJS_COUNT: '1\n' },
      environmentFields: { ARKENIVAJS_COUNT: { path: 'count', type: 'integer' } },
    }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    createConfig({
      ...setup,
      environment: { ARKENIVAJS_COUNT: 1 as never },
      environmentFields: { ARKENIVAJS_COUNT: { path: 'count', type: 'integer' } },
    }),
    code('EK_CONFIG_INVALID'),
  );
});

test('EK-CONF-001 secret providers resolve before use and respect explicit environment precedence', async () => {
  const seen: string[] = [];
  const c = await createConfig<Record<string, unknown>>({
    ...setup,
    secrets: { custom: 'service/custom', token: 'service/token' },
    environment: { ARKENIVAJS_TOKEN: 'fake-env-token' },
    environmentFields: { ARKENIVAJS_TOKEN: { path: 'token', type: 'string' } },
    secretProvider: async (reference) => {
      seen.push(reference);
      return 'fake-provider-secret';
    },
  });
  assert.deepEqual(seen, ['service/custom']);
  assert.equal(c.get('token'), 'fake-env-token');
  assert.equal(c.get('custom'), 'fake-provider-secret');
  assert.ok(!JSON.stringify(c.snapshot()).includes('fake-'));
  await assert.rejects(
    createConfig({ ...setup, secrets: { custom: 'service/custom' } }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    createConfig({
      ...setup,
      secrets: { custom: 'service/custom' },
      secretProvider: async () => '',
    }),
    code('EK_CONFIG_MISSING'),
  );
  await assert.rejects(
    createConfig({
      ...setup,
      secrets: { custom: 'service/custom' },
      runtime: { custom: 'inline-secret' },
      secretProvider: async () => 'fake-secret',
    }),
    code('EK_CONFIG_INVALID'),
  );
  await assert.rejects(
    createConfig({
      ...setup,
      secrets: { '__proto__.token': 'invalid' },
      secretProvider: async () => 'fake-secret',
    }),
    code('EK_CONFIG_INVALID'),
  );
});

test('EK-CONF-001 configuration loading honors cancellation and secret-provider deadlines', async () => {
  await assert.rejects(createConfig({ ...setup, signal: AbortSignal.abort() }), code('EK_ABORTED'));
  await assert.rejects(
    createConfig({
      ...setup,
      timeoutMs: 5,
      secrets: { token: 'service/token' },
      secretProvider: () => new Promise<string>(() => {}),
    }),
    code('EK_TIMEOUT'),
  );
  const c = await createConfig({ schema, workspace: process.cwd(), runtime: { count: 1 } });
  assert.equal(c.get('count'), 1);
});
