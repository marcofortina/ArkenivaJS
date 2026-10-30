// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, Server, Metadata } from '@grpc/grpc-js';
import { fixture } from '../fixture.js';
import { within } from '@arkenivajs/core/support';
import { connect } from 'node:http2';
import { once } from 'node:events';

test(
  'Dependency initialization can register authenticated services before listener activation',
  { timeout: 30000 },
  async () => {
    const source = await fixture({ imperative: true });
    try {
      const client = source.service.client('Echo');
      const result = await client.unary<{ value: string }>(
        'Bounce',
        { value: 'imperative' },
        { metadata: { authorization: await source.bearer() } },
      );
      assert.equal(result.value, 'imperative');
      const before = source.calls();
      await assert.rejects(client.unary('Bounce', {}), { code: 'EK_GRPC_AUTH' });
      assert.equal(source.calls(), before);
    } finally {
      await source.close();
    }
  },
);

test(
  'Managed gRPC uses actual signed tenant assertions, native unary, streaming and bidi RPCs',
  { timeout: 30000 },
  async (t) => {
    const source = await fixture();
    try {
      const client = source.service.client('Echo'),
        metadata = { authorization: await source.bearer() };
      await t.test('Unary protobuf preserves bytes and exact int64 values', async () => {
        const result = await client.unary<Record<string, unknown>>(
          'Bounce',
          {
            value: 'native-unary',
            sequence: '9223372036854775807',
            payload: Buffer.from([0, 255]),
          },
          { metadata },
        );
        assert.equal(result.value, 'native-unary');
        assert.equal(result.sequence, '9223372036854775807');
        assert.deepEqual(result.payload, Buffer.from([0, 255]));
        assert.ok(source.tenants().length > 0);
        assert.ok(source.tenants().every((tenant) => source.auth.isVerifiedTenant(tenant)));
      });
      await t.test('Server streaming preserves order and native protobuf values', async () => {
        const values: string[] = [];
        for await (const value of client.serverStream<{ sequence: string }>(
          'Watch',
          { value: 'stream' },
          { metadata },
        ))
          values.push(value.sequence);
        assert.deepEqual(values, ['0', '1', '2']);
      });
      await t.test(
        'Native access returns actual instances and supports protected bidirectional streaming',
        async () => {
          const native = client.native();
          assert.ok(native instanceof Client);
          assert.ok(source.serverService.nativeServer() instanceof Server);
          const headers = new Metadata();
          headers.set('authorization', metadata.authorization);
          const method = source.definition.Exchange!,
            stream = native.makeBidiStreamRequest(
              method.path,
              method.requestSerialize,
              method.responseDeserialize,
              headers,
              { deadline: Date.now() + 3000 },
            );
          const result: unknown[] = [];
          const completed = new Promise<void>((resolve, reject) => {
            stream.on('data', (value) => result.push(value));
            stream.once('end', resolve);
            stream.once('error', reject);
          });
          stream.write({ value: 'native-bidi', sequence: '-9223372036854775808' });
          stream.end();
          await completed;
          assert.deepEqual(result, [{ value: 'native-bidi', sequence: '-9223372036854775808' }]);
        },
      );
      await t.test(
        'Forged or missing identity and naked tenant metadata never reach handlers',
        async () => {
          const before = source.calls();
          for (const input of [
            {},
            { authorization: 'Bearer unsigned.payload.signature' },
            { ...metadata, 'x-tenant-id': 'tenant-B' },
            { authorization: await source.bearer('tenant-B') },
          ])
            await assert.rejects(client.unary('Bounce', {}, { metadata: input }), {
              code: 'EK_GRPC_AUTH',
            });
          assert.equal(source.calls(), before);
        },
      );
      await t.test(
        'Authority failures fail closed even on an established verified TLS connection',
        async () => {
          const before = source.calls();
          source.deny(true);
          await assert.rejects(client.unary('Bounce', {}, { metadata }), { code: 'EK_GRPC_AUTH' });
          source.deny(false);
          assert.equal(source.calls(), before);
        },
      );
      await t.test('Deadline cancellation reaches the real server handler', async () => {
        const pending = client.unary('Bounce', { value: 'hold' }, { metadata, timeoutMs: 500 });
        await within(() => source.held(), { timeoutMs: 1000 });
        await assert.rejects(pending, { code: 'EK_GRPC_DEADLINE' });
        await within(() => source.cancellation(), { timeoutMs: 1000 });
        assert.ok(source.cancelled() > 0);
      });
      await t.test(
        'Authority output cannot substitute issuers or manually reconstructed tenant objects',
        async () => {
          const before = source.calls();
          try {
            for (const substitution of ['issuer', 'tenant'] as const) {
              source.substitute(substitution);
              await assert.rejects(client.unary('Bounce', {}, { metadata }), {
                code: 'EK_GRPC_AUTH',
              });
            }
          } finally {
            source.substitute('none');
          }
          assert.equal(source.calls(), before);
        },
      );
      await t.test(
        'Invalid durations, unsafe fields and oversized messages fail before submission',
        async () => {
          const before = source.calls();
          for (const timeoutMs of [0, -1, 0.1, NaN, Infinity])
            await assert.rejects(client.unary('Bounce', {}, { metadata, timeoutMs }), {
              code: 'EK_CONFIG_INVALID',
            });
          for (const input of [
            { unknown: true },
            { sequence: '9223372036854775808' },
            { sequence: 9007199254740992 },
            { value: 1 },
            { payload: 'base64' },
            { value: 'x'.repeat(4097) },
          ])
            await assert.rejects(client.unary('Bounce', input, { metadata }));
          assert.equal(source.calls(), before);
        },
      );
      await t.test(
        'Post-listen registration is rejected through both public and native access',
        () => {
          assert.throws(
            () =>
              source.serverService.registerService(
                'Echo',
                {},
                {
                  requireAuthentication: true,
                  methodAllowlist: ['Bounce'],
                  maxInboundBytes: 1,
                  maxOutboundBytes: 1,
                  concurrencyLimit: 1,
                },
              ),
            { code: 'EK_LIFECYCLE_STATE' },
          );
          assert.throws(
            () => (source.serverService.nativeServer() as Server).addService(source.definition, {}),
            { code: 'EK_LIFECYCLE_STATE' },
          );
        },
      );
      await t.test(
        'Timed-out uncooperative handlers retain physical concurrency reservations',
        async () => {
          const attempts = [1, 2].map(() =>
            client.unary('Bounce', { value: 'blocked' }, { metadata, timeoutMs: 300 }).then(
              () => {
                throw new Error('The blocked request unexpectedly completed');
              },
              (error) => {
                assert.equal(error.code, 'EK_GRPC_DEADLINE');
              },
            ),
          );
          try {
            await within(() => source.blocked(), { timeoutMs: 1500 });
            await Promise.all(attempts);
            const before = source.calls();
            await assert.rejects(client.unary('Bounce', {}, { metadata }), {
              code: 'EK_GRPC_STATUS',
            });
            const otherStream = client.serverStream('Watch', {}, { metadata });
            const otherMethod = otherStream[Symbol.asyncIterator]();
            await assert.rejects(otherMethod.next(), { code: 'EK_GRPC_STATUS' });
            assert.equal(source.calls(), before);
          } finally {
            source.unblock();
            await Promise.allSettled(attempts);
          }
          await within(() => source.unblocked(), { timeoutMs: 1000 });
          assert.deepEqual(Object.keys(await client.unary<object>('Bounce', {}, { metadata })), []);
        },
      );
      await t.test('Native calls share the bounded client reservation pool', async () => {
        const native = client.native() as Client,
          headers = new Metadata(),
          method = source.definition.Exchange!;
        headers.set('authorization', metadata.authorization);
        const streams = Array.from({ length: 4 }, () =>
          native.makeBidiStreamRequest(
            method.path,
            method.requestSerialize,
            method.responseDeserialize,
            headers,
            { deadline: Date.now() + 3000 },
          ),
        );
        const settled = streams.map((stream) => {
          stream.on('error', () => undefined);
          return new Promise<void>((resolve) => stream.once('status', () => resolve()));
        });
        try {
          assert.throws(
            () =>
              native.makeBidiStreamRequest(
                method.path,
                method.requestSerialize,
                method.responseDeserialize,
                headers,
              ),
            { code: 'EK_BACKEND_UNAVAILABLE' },
          );
        } finally {
          for (const stream of streams) stream.cancel();
          await Promise.all(settled);
        }
      });
      await t.test(
        'A closed native channel cannot escape public resource-closed errors',
        async () => {
          (client.native() as Client).close();
          await assert.rejects(client.unary('Bounce', {}, { metadata }), {
            code: 'EK_RESOURCE_CLOSED',
          });
          assert.throws(() => client.native(), { code: 'EK_RESOURCE_CLOSED' });
        },
      );
    } finally {
      await source.close();
    }
  },
);

test(
  'Native HTTP/2 ping bursts preserve transport bounds and cannot invoke RPC handlers',
  { timeout: 30000 },
  async () => {
    const source = await fixture(),
      material = source.pki.materials.get('client')!;
    const session = connect(source.endpoint, {
      ca: material.ca.map((value) => Buffer.from(value)),
      cert: Buffer.from(material.cert),
      key: Buffer.from(material.key),
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxOutstandingPings: 64,
    });
    session.on('error', () => undefined);
    try {
      const [settings] = await within(() => once(session, 'remoteSettings'), { timeoutMs: 3000 });
      assert.equal(settings.maxConcurrentStreams, 4);
      assert.equal(settings.maxHeaderListSize, 16384);
      await within(
        () =>
          Promise.all(
            Array.from(
              { length: 64 },
              () =>
                new Promise<void>((resolve) => {
                  try {
                    session.ping(() => resolve());
                  } catch {
                    resolve();
                  }
                }),
            ),
          ),
        { timeoutMs: 3000 },
      );
      assert.equal(source.calls(), 0);
      session.destroy();
      const client = source.service.client('Echo');
      const result = await client.unary<{ value: string }>(
        'Bounce',
        { value: 'healthy-after-pings' },
        { metadata: { authorization: await source.bearer() } },
      );
      assert.equal(result.value, 'healthy-after-pings');
    } finally {
      session.destroy();
      await source.close();
    }
  },
);

test(
  'Established gRPC channels recheck actual client revocation for each RPC',
  { timeout: 30000 },
  async () => {
    const source = await fixture();
    try {
      const client = source.service.client('Echo'),
        metadata = { authorization: await source.bearer() };
      await client.unary('Bounce', { value: 'established' }, { metadata });
      const before = source.calls();
      await source.pki.revoke('client');
      await assert.rejects(client.unary('Bounce', {}, { metadata }), { code: 'EK_GRPC_AUTH' });
      assert.equal(source.calls(), before);
    } finally {
      await source.close();
    }
  },
);

test(
  'gRPC method selection, native deadlines and stream authentication failures cannot reach a handler',
  { timeout: 30000 },
  async () => {
    const source = await fixture();
    try {
      const client = source.service.client('Echo'),
        metadata = { authorization: await source.bearer() },
        before = source.calls();
      for (const method of ['Missing', 'Watch', 'Exchange', '__proto__'])
        await assert.rejects(client.unary(method, {}, { metadata }), {
          code: 'EK_UNSUPPORTED_CAPABILITY',
        });
      for (const method of ['Missing', 'Bounce', 'Exchange'])
        await assert.rejects(
          client.serverStream(method, {}, { metadata })[Symbol.asyncIterator]().next(),
          { code: 'EK_UNSUPPORTED_CAPABILITY' },
        );
      const signal = AbortSignal.abort();
      await assert.rejects(client.unary('Bounce', {}, { metadata, signal }), {
        code: 'EK_ABORTED',
      });
      await assert.rejects(
        client.serverStream('Watch', {}, { metadata, signal })[Symbol.asyncIterator]().next(),
        { code: 'EK_ABORTED' },
      );
      assert.equal(source.service.client('Echo'), client);
      assert.throws(() => source.service.client('Missing'), { code: 'EK_CONFIG_INVALID' });
      const native = client.native() as Client,
        codec = source.definition.Bounce!;
      assert.throws(
        () =>
          native.makeUnaryRequest(
            '/foreign.Service/Unknown',
            codec.requestSerialize,
            codec.responseDeserialize,
            {},
            new Metadata(),
            { deadline: new Date(Date.now() + 1000) },
            () => undefined,
          ),
        { code: 'EK_CONFIG_INVALID' },
      );
      assert.throws(
        () =>
          native.makeUnaryRequest(
            codec.path,
            codec.requestSerialize,
            codec.responseDeserialize,
            {},
            new Metadata(),
            { deadline: new Date(NaN) },
            () => undefined,
          ),
        { code: 'EK_CONFIG_INVALID' },
      );
      const rejectedStream = client.serverStream(
        'Watch',
        {},
        { metadata: { authorization: 'Bearer invalid' } },
      );
      await assert.rejects(rejectedStream[Symbol.asyncIterator]().next(), { code: 'EK_GRPC_AUTH' });
      assert.equal(source.calls(), before);
      const result = await client.unary<{ value: string }>(
        'Bounce',
        { value: 'healthy-after-denial' },
        { metadata },
      );
      assert.equal(result.value, 'healthy-after-denial');
    } finally {
      await source.close();
    }
  },
);

test(
  'Explicit cancellation reaches an actual unary handler and native stream abandonment leaves the channel reusable',
  { timeout: 30000 },
  async () => {
    const source = await fixture();
    try {
      const client = source.service.client('Echo'),
        metadata = { authorization: await source.bearer() },
        controller = new AbortController();
      const pending = client.unary(
        'Bounce',
        { value: 'hold' },
        { metadata, signal: controller.signal },
      );
      await within(() => source.held(), { timeoutMs: 1000 });
      controller.abort();
      await assert.rejects(pending, { code: 'EK_ABORTED' });
      await within(() => source.cancellation(), { timeoutMs: 1000 });
      const iterator = client.serverStream('Watch', {}, { metadata })[Symbol.asyncIterator]();
      assert.equal((await iterator.next()).done, false);
      await iterator.return?.();
      assert.equal(
        (await client.unary<{ value: string }>('Bounce', { value: 'recovered' }, { metadata }))
          .value,
        'recovered',
      );
      await Promise.all([source.client.stop(), source.server.stop()]);
      assert.throws(() => source.service.client('Echo'), { code: 'EK_RESOURCE_CLOSED' });
      assert.throws(() => source.serverService.nativeServer(), { code: 'EK_RESOURCE_CLOSED' });
      assert.throws(() => client.native(), { code: 'EK_RESOURCE_CLOSED' });
      await assert.rejects(client.unary('Bounce', {}, { metadata }), {
        code: 'EK_RESOURCE_CLOSED',
      });
      await assert.rejects(
        client.serverStream('Watch', {}, { metadata })[Symbol.asyncIterator]().next(),
        { code: 'EK_RESOURCE_CLOSED' },
      );
    } finally {
      await source.close();
    }
  },
);

test(
  'Actual gRPC handler failures and malformed stream output remain sanitized and release admission',
  { timeout: 30000 },
  async () => {
    const source = await fixture();
    try {
      const client = source.service.client('Echo'),
        metadata = { authorization: await source.bearer() };
      for (const value of ['handler-throw', 'wrong-result'])
        await assert.rejects(client.unary('Bounce', { value }, { metadata }), {
          code: 'EK_GRPC_STATUS',
        });
      for (const value of ['wrong-stream', 'oversized-stream', 'stream-throw']) {
        const values: unknown[] = [];
        await assert.rejects(
          async () => {
            for await (const row of client.serverStream('Watch', { value }, { metadata }))
              values.push(row);
          },
          { code: 'EK_GRPC_STATUS' },
        );
        assert.equal(values.length, value === 'stream-throw' ? 1 : 0);
      }
      assert.equal(
        (
          await client.unary<{ value: string }>(
            'Bounce',
            { value: 'healthy-after-handler-failures' },
            { metadata },
          )
        ).value,
        'healthy-after-handler-failures',
      );
    } finally {
      await source.close();
    }
  },
);
