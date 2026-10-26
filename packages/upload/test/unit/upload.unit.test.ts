// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { fixture, policy, body, send } from './fixture.js';
import { uploadPlugin } from '../../dist/index.js';
import type { UploadPluginSettings, UploadPolicy } from '../../dist/index.js';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { Writable } from 'node:stream';

const file = {
  name: 'document',
  filename: 'report.pdf',
  type: 'application/pdf',
  value: Buffer.from('%PDF-disposable'),
};

test('POST and PUT preserve native field/file order and report actual bytes under verified tenant identity', async (t) => {
  for (const method of ['POST', 'PUT'] as const) {
    const f = await fixture({ method });
    t.after(f.close);
    const input = body([
      { name: 'note', value: 'bounded text' },
      file,
      { ...file, name: 'second' },
    ]);
    const result = await send(f.origin, input, await f.token('tenant-a'), method);
    assert.equal(result.status, 200, result.body);
    assert.deepEqual(JSON.parse(result.body), {
      files: 2,
      bytes: file.value.length * 2,
      order: ['field:note', 'file:document', 'file:second'],
      tenant: 'tenant-a',
    });
    assert.equal(f.stats().observedBytes, input.length);
    assert.equal(f.stats().successfulRequests, 1);
    assert.equal(f.stats().activeRequests, 0);
    assert.ok(!f.logs().includes('bounded text'));
    assert.ok(!f.logs().includes('%PDF-disposable'));
    assert.ok(!f.logs().includes('report.pdf'));
  }
});

test('Authentication and exact scopes are checked before the application handler or multipart parser consumes a file', async (t) => {
  const f = await fixture();
  t.after(f.close);
  for (const [token, expected] of [
    [undefined, 401],
    ['Bearer invalid', 401],
    [await f.token('tenant-a', 'documents:read'), 403],
  ] as const) {
    const result = await send(f.origin, body([file]), token);
    assert.equal(result.status, expected, result.body);
    assert.equal(f.calls(), 0);
  }
  assert.equal(f.stats().observedBytes, 0);
  assert.equal(f.stats().rejectedRequests, 3);
});

test('Every wire, file, field and count limit is enforced on real multipart input', async (t) => {
  const cases: readonly [Partial<UploadPolicy>, ReturnType<typeof body>][] = [
    [{ maxRequestBytes: 150 }, body([file])],
    [{ maxFileBytes: 4 }, body([file])],
    [{ maxFieldBytes: 3 }, body([{ name: 'note', value: 'too long' }])],
    [{ maxFiles: 1 }, body([file, file])],
    [
      { maxFields: 1 },
      body([
        { name: 'a', value: 'x' },
        { name: 'b', value: 'y' },
      ]),
    ],
    [{ maxParts: 1 }, body([{ name: 'a', value: 'x' }, file])],
  ];
  for (const [change, input] of cases) {
    const f = await fixture({ policy: { ...policy, ...change } });
    t.after(f.close);
    const result = await send(f.origin, input, await f.token());
    assert.equal(result.status, 413, JSON.stringify({ change, result }));
    assert.match(result.body, /EK_UPLOAD_LIMIT/);
    assert.equal(f.stats().successfulRequests, 0);
  }
});

test('Declared MIME is an allowlist assertion and hostile display filenames or malformed endings cannot succeed', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const token = await f.token();
  const badType = await send(f.origin, body([{ ...file, type: 'text/html' }]), token);
  assert.equal(badType.status, 415, badType.body);
  for (const filename of ['../private.pdf', 'C:\\private.pdf', '..']) {
    const result = await send(f.origin, body([{ ...file, filename }]), token);
    assert.equal(result.status, 400, result.body);
    assert.ok(!result.body.includes(filename));
  }
  const incomplete = await send(f.origin, body([file], false), token);
  assert.equal(incomplete.status, 400, incomplete.body);
  const wrongType = await fetch(f.origin + '/uploads', {
    method: 'POST',
    headers: { authorization: token, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(wrongType.status, 415);
  await wrongType.arrayBuffer();
});

test('Explicit discard consumes one file and permits the next part without implicit storage', async (t) => {
  const f = await fixture({
    async handler(request) {
      let files = 0;
      for await (const part of request.parts)
        if (part.kind === 'file') {
          await part.discard();
          files++;
        }
      return { files, bytes: 0, order: [] };
    },
  });
  t.after(f.close);
  const result = await send(f.origin, body([file, file]), await f.token());
  assert.equal(result.status, 200, result.body);
  assert.equal(JSON.parse(result.body).files, 2);
});

test('Unconsumed, partially consumed, repeated and swallowed-invalid streams never receive a success acknowledgement', async (t) => {
  for (const mode of ['unused', 'skip', 'partial', 'twice', 'caught']) {
    const f = await fixture({
      async handler(request) {
        if (mode !== 'unused')
          for await (const part of request.parts) {
            if (part.kind !== 'file') continue;
            if (mode === 'skip') continue;
            if (mode === 'partial') {
              for await (const chunk of part.stream) {
                void chunk;
                break;
              }
              break;
            }
            await part.discard();
            if (mode === 'twice') await part.discard();
            if (mode === 'caught')
              try {
                await part.discard();
              } catch {
                /* The scope must remain failed. */
              }
          }
        return { files: 0, bytes: 0, order: [] };
      },
    });
    t.after(f.close);
    const result = await send(f.origin, body([file, file]), await f.token());
    assert.equal(result.status, 400, JSON.stringify({ mode, result }));
    assert.equal(f.stats().successfulRequests, 0);
  }
});

test('Slow chunked files remain streaming and concurrent tenant requests never exchange context', async (t) => {
  const f = await fixture({
    policy: { ...policy, maxRequestBytes: 5000000, maxFileBytes: 3000000 },
  });
  t.after(f.close);
  async function* streamed() {
    yield body([{ ...file, value: Buffer.alloc(0) }], false).subarray(0, -2);
    for (let index = 0; index < 128; index++) {
      yield Buffer.alloc(16384, 65);
      if (index % 16 === 0) await delay(1);
    }
    yield Buffer.from('\r\n--arkeniva-upload-fixture--\r\n');
  }
  const result = await Promise.all([
    send(f.origin, streamed(), await f.token('tenant-a')),
    send(f.origin, body([file]), await f.token('tenant-b')),
  ]);
  assert.deepEqual(
    result.map((r) => r.status),
    [200, 200],
    JSON.stringify(result),
  );
  assert.equal(JSON.parse(result[0]!.body).bytes, 2097152);
  assert.deepEqual(
    result.map((r) => JSON.parse(r.body).tenant),
    ['tenant-a', 'tenant-b'],
  );
  assert.equal(f.stats().activeRequests, 0);
});

test('Configuration rejects unknown properties, accessors, unsafe names, schemas and unbounded policies before startup', () => {
  const make = (change: object) => ({
    routes: [
      {
        path: '/uploads',
        method: 'POST',
        policy,
        auth: { required: true },
        responseSchema: { type: 'object' },
        handler: () => ({}),
        ...change,
      },
    ],
  });
  for (const change of [
    { path: '/livez' },
    { path: '/../uploads' },
    { method: 'GET' },
    { policy: { ...policy, maxFileBytes: 0 } },
    { policy: { ...policy, maxParts: Infinity } },
    { policy: { ...policy, maxFiles: 1.5 } },
    { policy: { ...policy, allowedMediaTypes: ['*/*'] } },
    { auth: { required: false } },
    { auth: { required: false, reason: 'reviewed', scopes: ['admin'] } },
    { responseSchema: { type: 'unknown-type' } },
    { unexpected: true },
  ])
    assert.throws(() => uploadPlugin(make(change) as UploadPluginSettings), {
      code: 'EK_UPLOAD_CONFIG',
    });
  let read = false;
  assert.throws(
    () =>
      uploadPlugin({
        get routes() {
          read = true;
          return [];
        },
      }),
    { code: 'EK_UPLOAD_CONFIG' },
  );
  assert.equal(read, false);
});

test('Protected uploads require an actual authentication provider and route collisions fail before listener activation', async () => {
  const sink = new Writable({
    write(_chunk, _encoding, done) {
      done();
    },
  });
  const route = {
    path: '/uploads',
    method: 'POST' as const,
    policy,
    auth: { required: true as const },
    responseSchema: { type: 'object' },
    handler: () => ({}),
  };
  const missing = await createApplication({
    service: { name: 'upload-missing-auth', version: '1.0.0', environment: 'test' },
    plugins: [loggingPlugin({ destination: sink }), apiPlugin(), uploadPlugin({ routes: [route] })],
  });
  try {
    await assert.rejects(missing.start());
  } finally {
    await missing.stop();
  }
  assert.throws(() => uploadPlugin({ routes: [route, route] }), { code: 'EK_UPLOAD_CONFIG' });
  const duplicate = await createApplication({
    service: { name: 'upload-route-collision', version: '1.0.0', environment: 'test' },
    plugins: [
      loggingPlugin({ destination: sink }),
      apiPlugin(),
      uploadPlugin({
        routes: [
          {
            ...route,
            auth: { required: false, reason: 'The owned test fixture has no protected data' },
          },
        ],
      }),
    ],
  });
  duplicate.api.post('/uploads', {
    auth: { required: false },
    schema: { response: { type: 'object' } },
    handler: () => ({}),
  });
  try {
    await assert.rejects(duplicate.start());
  } finally {
    await duplicate.stop();
    sink.destroy();
  }
});

test('An explicitly reviewed public upload has no manufactured identity and must still consume every file', async (t) => {
  const f = await fixture({
    auth: { required: false, reason: 'The owned disposable fixture accepts no persistent data' },
    async handler(input) {
      assert.equal(input.context.auth, undefined);
      for await (const part of input.parts)
        if (part.kind === 'file') await part.discard({ timeoutMs: 1000 });
      return { files: 1, bytes: 0, order: [] };
    },
  });
  t.after(f.close);
  const result = await send(f.origin, body([file]));
  assert.equal(result.status, 200, result.body);
});
