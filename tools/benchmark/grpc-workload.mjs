// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createSecureContext } from 'node:tls';
import { Client, ChannelCredentials, Metadata, loadPackageDefinition } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';

export function grpcConnection(fixture) {
  assert.match(fixture.endpoint, /^localhost:[1-9][0-9]{0,4}$/);
  assert.ok(Number(fixture.endpoint.split(':')[1]) <= 65535);
  assert.ok(fixture.descriptorFile?.startsWith('/'));
  const bridge = new URL(fixture.bridgeUrl);
  assert.equal(bridge.protocol, 'http:');
  assert.equal(bridge.hostname, '127.0.0.1');
  assert.ok(bridge.port && !bridge.username && !bridge.password && !bridge.search && !bridge.hash);
  assert.equal(bridge.pathname, '/verify');
  const material = JSON.parse(fixture.material);
  return {
    ca: material.ca.map((value) => Buffer.from(value, 'base64')),
    cert: Buffer.from(material.cert, 'base64'),
    key: Buffer.from(material.key, 'base64'),
    minVersion: 'TLSv1.3',
    ALPNProtocols: ['h2'],
  };
}

export function grpcSettings(fixture) {
  grpcConnection(fixture);
  const profile = JSON.parse(fixture.profile);
  return {
    services: [
      {
        name: 'Echo',
        descriptorFile: fixture.descriptorFile,
        endpoint: fixture.endpoint,
        allowedMethods: ['Bounce', 'Watch'],
        maxMessageBytes: 4096,
      },
    ],
    handlers: {},
    tlsProfiles: { client: profile },
    authority: {
      async require() {
        throw new Error('The gRPC comparison never grants application authority');
      },
    },
    policy: { maxConcurrent: 2, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 4096 },
  };
}

export function grpcMtlsSettings(fixture) {
  const material = grpcConnection(fixture),
    profile = JSON.parse(fixture.profile);
  return {
    profiles: { client: profile },
    reloadMode: 'explicit',
    policy: { maxConcurrent: 2, timeoutMs: 3000 },
    credentialProvider: {
      usage: 'test-only',
      async load(requested) {
        assert.deepEqual(requested, profile);
        return material;
      },
    },
    trustProvider: {
      usage: 'test-only',
      async verifyChainAndRevocation(input, options) {
        const response = await globalThis.fetch(fixture.bridgeUrl, {
          method: 'POST',
          headers: {
            authorization: 'Bearer ' + fixture.bearer,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            peerDer: Buffer.from(input.peerDer).toString('base64'),
            policy: input.policy,
          }),
          signal: options?.signal ?? AbortSignal.timeout(2000),
          redirect: 'error',
        });
        assert.equal(response.status, 200);
        return response.json();
      },
    },
  };
}

/** Direct grpc-js retains native protobuf and stream behavior; it omits the wrapper's CRL/policy stage. */
export function nativeGrpc(fixture) {
  const material = grpcConnection(fixture),
    definition = loadPackageDefinition(
      loadSync(fixture.descriptorFile, { longs: String, bytes: Buffer, keepCase: true }),
    );
  const credentials = ChannelCredentials.createFromSecureContext(createSecureContext(material), {
    rejectUnauthorized: true,
  });
  const native = new definition.fixture.Echo(fixture.endpoint, credentials, {
    'grpc.max_receive_message_length': 4096,
    'grpc.max_send_message_length': 4096,
    'grpc.enable_retries': 0,
  });
  return {
    client(name) {
      assert.equal(name, 'Echo');
      return {
        native: () => native,
        unary(method, input) {
          assert.equal(method, 'Bounce');
          return new Promise((done, reject) =>
            native.Bounce(input, new Metadata(), { deadline: Date.now() + 3000 }, (cause, value) =>
              cause ? reject(cause) : done(value),
            ),
          );
        },
        serverStream(method, input) {
          assert.equal(method, 'Watch');
          return native.Watch(input, new Metadata(), { deadline: Date.now() + 3000 });
        },
      };
    },
    close() {
      native.close();
      for (const ca of material.ca) ca.fill(0);
      material.cert.fill(0);
      material.key.fill(0);
    },
  };
}

export async function verifyGrpc(service, fixture) {
  const client = service.client('Echo');
  assert.ok(client.native() instanceof Client);
  const payload = Buffer.from([0, 255, 128, 7]);
  const input = { value: fixture.marker + '-unary', sequence: '9223372036854775807', payload };
  const result = await client.unary('Bounce', input);
  assert.equal(result.value, input.value);
  assert.equal(result.sequence, input.sequence);
  assert.deepEqual(Buffer.from(result.payload), payload);
  const messages = [];
  for await (const value of client.serverStream('Watch', {
    ...input,
    value: fixture.marker + '-stream',
  })) {
    assert.equal(value.value, fixture.marker + '-stream');
    assert.deepEqual(Buffer.from(value.payload), payload);
    messages.push(value.sequence);
  }
  assert.deepEqual(messages, ['1', '2', '3']);
  return {
    nativeClientIdentityVerified: true,
    actualUnaryVerified: true,
    exactInt64StringPreserved: true,
    binaryPayloadPreserved: true,
    actualOrderedStreamMessages: 3,
  };
}
