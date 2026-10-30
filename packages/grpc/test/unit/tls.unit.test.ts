// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import {
  Server,
  makeGenericClientConstructor,
  Client,
  Metadata,
  CallCredentials,
} from '@grpc/grpc-js';
import type { ServiceDefinition, ServerUnaryCall, sendUnaryData } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { createApplication } from '@arkenivajs/core';
import { mtlsPlugin, MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import type { MtlsService } from '@arkenivajs/security-mtls';
import { fixture } from '../../../security-mtls/dist-test/fixture.js';
import { clientCredentials, serverCredentials } from '../../dist/tls.js';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
test(
  'Actual native gRPC waits for asynchronous TLS trust before sending a protobuf request',
  { timeout: 30000 },
  async () => {
    const pki = await fixture(),
      app = await createApplication({
        service: {
          name: 'grpc-tls',
          version: '1.0.0',
          environment: 'test',
        },
        plugins: [mtlsPlugin(pki.settings)],
      });
    const server = new Server({
      'grpc.max_receive_message_length': 4096,
      'grpc.max_send_message_length': 4096,
    });
    let client: Client | undefined,
      received = 0;
    try {
      await app.start();
      const mtls = app.resolve<MtlsService>(MTLS_CAPABILITY),
        ready = gate(),
        permitted = gate();
      const packageDefinition = loadSync(
        fileURLToPath(new URL('../../test/fixtures/echo.proto', import.meta.url)),
        {
          keepCase: true,
          longs: String,
          enums: String,
          bytes: Buffer,
          defaults: false,
          oneofs: true,
        },
      );
      const service = packageDefinition['fixture.Echo'] as ServiceDefinition;
      server.addService(service, {
        bounce(
          call: ServerUnaryCall<{ value: string }, { value: string }>,
          callback: sendUnaryData<{ value: string }>,
        ) {
          assert.equal(call.getAuthContext().transportSecurityType, 'ssl');
          assert.ok(call.getAuthContext().sslPeerCertificate?.raw.length);
          assert.equal(call.metadata.get('x-owned-fixture')[0], 'verified');
          received++;
          callback(null, call.request);
        },
      });
      const secured = await serverCredentials(mtls, pki.profiles.server!, { timeoutMs: 3000 });
      const port = await new Promise<number>((resolve, reject) => {
        server.bindAsync('127.0.0.1:0', secured, (error, port) =>
          error ? reject(error) : resolve(port),
        );
      });
      const guarded: MtlsService = {
        ...mtls,
        async verifyPeer(...parameters) {
          ready.release();
          await permitted.promise;
          return mtls.verifyPeer(...parameters);
        },
      };
      const Native = makeGenericClientConstructor(service, 'fixture.Echo');
      const transport = await clientCredentials(guarded, pki.profiles.client!, 'localhost', {
        timeoutMs: 3000,
      });
      assert.equal(transport._isSecure(), true);
      assert.equal(transport._equals(transport), true);
      assert.equal(
        transport._equals(
          await clientCredentials(mtls, pki.profiles.client!, 'localhost', { timeoutMs: 3000 }),
        ),
        false,
      );
      assert.equal(secured._equals(secured), true);
      assert.equal(
        secured._equals(await serverCredentials(mtls, pki.profiles.server!, { timeoutMs: 3000 })),
        false,
      );
      const composed = transport.compose(
        CallCredentials.createFromMetadataGenerator((_options, callback) => {
          const headers = new Metadata();
          headers.set('x-owned-fixture', 'verified');
          callback(null, headers);
        }),
      );
      assert.equal(composed._isSecure(), true);
      client = new Native('localhost:' + port, composed);
      assert.ok(client instanceof Client);
      const active = client;
      const response = new Promise<{ value: string }>((resolve, reject) => {
        active.makeUnaryRequest(
          '/fixture.Echo/Bounce',
          service.Bounce!.requestSerialize,
          service.Bounce!.responseDeserialize,
          { value: 'actual-protobuf' },
          { deadline: Date.now() + 5000 },
          (error, value?: { value: string }) =>
            error
              ? reject(error)
              : value
                ? resolve(value)
                : reject(new Error('The native gRPC response is missing')),
        );
      });
      await ready.promise;
      assert.equal(received, 0);
      permitted.release();
      assert.equal((await response).value, 'actual-protobuf');
      assert.equal(received, 1);
    } finally {
      client?.close();
      server.forceShutdown();
      await app.stop();
      await pki.close();
    }
  },
);

for (const condition of ['revoked-server', 'unavailable-verifier'] as const) {
  test(
    `Actual native gRPC rejects ${condition} before delivering an RPC`,
    { timeout: 30000 },
    async () => {
      const pki = await fixture(),
        app = await createApplication({
          service: { name: 'grpc-rejected-tls', version: '1.0.0', environment: 'test' },
          plugins: [mtlsPlugin(pki.settings)],
        }),
        server = new Server();
      let client: Client | undefined,
        received = 0;
      try {
        await app.start();
        const mtls = app.resolve<MtlsService>(MTLS_CAPABILITY),
          definition = loadSync(
            fileURLToPath(new URL('../../test/fixtures/echo.proto', import.meta.url)),
          ),
          service = definition['fixture.Echo'] as ServiceDefinition,
          credentials = await serverCredentials(mtls, pki.profiles.server!, { timeoutMs: 3000 }),
          clientTls = await clientCredentials(mtls, pki.profiles.client!, 'localhost', {
            timeoutMs: 3000,
          });
        server.addService(service, {
          bounce(call: ServerUnaryCall<unknown, unknown>, callback: sendUnaryData<unknown>) {
            received++;
            callback(null, call.request);
          },
        });
        const port = await new Promise<number>((resolve, reject) => {
          server.bindAsync('127.0.0.1:0', credentials, (error, port) =>
            error ? reject(error) : resolve(port),
          );
        });
        if (condition === 'revoked-server') await pki.revoke('server');
        else pki.unavailable(true);
        const Native = makeGenericClientConstructor(service, 'fixture.Echo');
        client = new Native('localhost:' + port, clientTls);
        const active = client;
        await assert.rejects(
          new Promise((resolve, reject) => {
            active.makeUnaryRequest(
              '/fixture.Echo/Bounce',
              service.Bounce!.requestSerialize,
              service.Bounce!.responseDeserialize,
              { value: 'must-not-arrive' },
              { deadline: Date.now() + 1500 },
              (error, result) => (error ? reject(error) : resolve(result)),
            );
          }),
        );
        assert.equal(received, 0);
        assert.ok(pki.verifications() > 0);
      } finally {
        client?.close();
        server.forceShutdown();
        await app.stop();
        await pki.close();
      }
    },
  );
}
