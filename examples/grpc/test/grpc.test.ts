// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, Server } from '@grpc/grpc-js';
import { runGrpcExample } from '../dist/main.js';
import { createFixture } from '../dist/fixture.js';

test(
  'Packed public gRPC consumers exchange exact protobuf values over real mTLS',
  { timeout: 30000 },
  async () => {
    assert.deepEqual(await runGrpcExample(), {
      value: 'native-protobuf',
      exactInteger: '9223372036854775807',
      sequence: ['0', '1', '2'],
    });
  },
);
test(
  'Public gRPC capabilities preserve native identity and reject forged tenant assertions',
  { timeout: 30000 },
  async () => {
    const fixture = await createFixture();
    try {
      const client = fixture.service.client('Echo');
      assert.ok(client.native() instanceof Client);
      assert.ok(fixture.serverService.nativeServer() instanceof Server);
      assert.equal(JSON.stringify(client), '{}');
      const before = fixture.calls();
      await assert.rejects(
        client.unary(
          'Bounce',
          {},
          { metadata: { authorization: 'Bearer unsigned.fixture.assertion' } },
        ),
        { code: 'EK_GRPC_AUTH' },
      );
      await assert.rejects(
        client.unary(
          'Bounce',
          {},
          { metadata: { authorization: await fixture.bearer('tenant-B') } },
        ),
        { code: 'EK_GRPC_AUTH' },
      );
      assert.equal(fixture.calls(), before);
      await fixture.client.stop();
      await assert.rejects(client.unary('Bounce', {}), { code: 'EK_RESOURCE_CLOSED' });
    } finally {
      await fixture.close();
    }
  },
);
