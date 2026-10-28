// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, mkdir, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ServiceDefinition } from '@grpc/grpc-js';
import { loadDescriptor } from '../../dist/descriptor.js';

const signal = () => new AbortController().signal;
const writeAsset = (path: string, value: string | Uint8Array) =>
  writeFile(path, value, { mode: 0o600 });
test('Actual native protobuf descriptors preserve bytes, int64 text, presence and streaming modes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-fidelity-'));
  const path = join(directory, 'echo.proto');
  await writeAsset(
    path,
    await readFile(fileURLToPath(new URL('../../test/fixtures/echo.proto', import.meta.url))),
  );
  let definition;
  try {
    definition = await loadDescriptor(path, 3000, signal());
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
  const service = definition['fixture.Echo'] as ServiceDefinition,
    bounce = service.Bounce!;
  const result = bounce.requestDeserialize(
    bounce.requestSerialize({
      value: 'echo',
      sequence: '9223372036854775807',
      payload: Buffer.from([0, 255, 1]),
    }),
  ) as Record<string, unknown>;
  assert.equal(result.sequence, '9223372036854775807');
  assert.deepEqual(result.payload, Buffer.from([0, 255, 1]));
  assert.deepEqual(bounce.requestDeserialize(bounce.requestSerialize({})), {});
  assert.equal(service.Watch!.responseStream, true);
  assert.equal(service.Exchange!.requestStream, true);
  assert.equal(service.Exchange!.responseStream, true);
});

test('Offline native protobuf compilation captures relative imports without later file access', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-import-'));
  try {
    await mkdir(join(directory, 'types'));
    await writeAsset(
      join(directory, 'service.proto'),
      'syntax="proto3"; package fixture; import "types/message.proto"; service Echo { rpc Bounce(Message) returns(Message); }',
    );
    await writeAsset(
      join(directory, 'types/message.proto'),
      'syntax="proto3"; package fixture; message Message { string value=1; }',
    );
    const definition = await loadDescriptor(join(directory, 'service.proto'), 3000, signal());
    await rm(directory, { recursive: true, force: true });
    const method = (definition['fixture.Echo'] as ServiceDefinition).Bounce!;
    assert.deepEqual(method.responseDeserialize(method.responseSerialize({ value: 'captured' })), {
      value: 'captured',
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

for (const [name, source] of [
  ['invalid syntax', 'syntax="proto3"; message {'],
  ['remote import', 'syntax="proto3"; import "https://example.invalid/evil.proto";'],
  ['parent escape', 'syntax="proto3"; import "../outside.proto";'],
  ['absolute import', 'syntax="proto3"; import "/etc/passwd";'],
  ['cyclic import', 'syntax="proto3"; import "service.proto";'],
  ['missing weak import', 'syntax="proto3"; import weak "missing.proto";'],
  ['prototype field', 'syntax="proto3"; message Unsafe { string constructor=1; }'],
  [
    'native method collision',
    'syntax="proto3"; message Empty {} service Unsafe { rpc Close(Empty) returns(Empty); }',
  ],
] as const) {
  test(`Offline native protobuf compilation rejects ${name}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-invalid-'));
    try {
      await writeAsset(join(directory, 'service.proto'), source);
      await assert.rejects(loadDescriptor(join(directory, 'service.proto'), 3000, signal()), {
        code: 'EK_CONFIG_INVALID',
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
test('Descriptor assets reject symlinks, writable files, oversized assets and invalid UTF-8', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-assets-'));
  try {
    const target = join(directory, 'service.proto'),
      link = join(directory, 'link.proto');
    await writeAsset(target, 'syntax="proto3"; message Valid { string value=1; }');
    await symlink(target, link);
    await assert.rejects(loadDescriptor(link, 3000, signal()));
    await chmod(target, 0o666);
    await assert.rejects(loadDescriptor(target, 3000, signal()));
    await chmod(target, 0o600);
    await writeAsset(target, Buffer.alloc(1048577, 32));
    await assert.rejects(loadDescriptor(target, 3000, signal()));
    await writeAsset(target, Buffer.from([255, 254]));
    await assert.rejects(loadDescriptor(target, 3000, signal()));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
test('Invalid timeouts and pre-aborted descriptor loads fail before opening assets', async () => {
  for (const timeout of [0, -1, 0.5, NaN, Infinity, 60001])
    await assert.rejects(loadDescriptor('/missing.proto', timeout, signal()), {
      code: 'EK_CONFIG_INVALID',
    });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(loadDescriptor('/missing.proto', 3000, controller.signal), {
    code: 'EK_ABORTED',
  });
});
