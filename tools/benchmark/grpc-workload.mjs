// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createSecureContext } from 'node:tls';
import { Client, ChannelCredentials, Metadata, loadPackageDefinition } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { createHash, randomUUID } from 'node:crypto';

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
  let closed = false;
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
      if (closed) return;
      closed = true;
      native.close();
      for (const ca of material.ca) ca.fill(0);
      material.cert.fill(0);
      material.key.fill(0);
    },
  };
}

const observations = new WeakMap();
export const grpcCorpusPayload = () => Buffer.from([0, 255, 128, 7]);

/** Application fixture receipts are not authentication, idempotency or distributed authority. */
export function grpcUnaryReceipt(fixture, input, result) {
  assert.deepEqual(Object.keys(input).sort(), ['payload', 'sequence', 'value']);
  assert.deepEqual(Object.keys(result).sort(), ['payload', 'sequence', 'value']);
  assert.equal(typeof input.value, 'string');
  assert.equal(input.sequence, '9223372036854775807');
  assert.deepEqual(Buffer.from(input.payload), grpcCorpusPayload());
  assert.equal(result.value, input.value);
  assert.equal(result.sequence, input.sequence);
  assert.deepEqual(Buffer.from(result.payload), grpcCorpusPayload());
  const prefix = fixture.marker + '-unary';
  let receipt = 'verification';
  if (input.value !== prefix) {
    receipt = input.value.slice(prefix.length + 1);
    assert.equal(input.value, prefix + '-' + receipt);
    assert.match(receipt, /^[a-f0-9-]{36}$/);
  }
  return {
    receipt,
    sequence: result.sequence,
    payloadHex: Buffer.from(result.payload).toString('hex'),
  };
}

export function grpcReceiptDigest(rows) {
  assert.ok(Array.isArray(rows) && rows.length <= 512);
  const digest = createHash('sha256').update('arkenivajs.grpc.benchmark.receipts.v1\n');
  for (const row of rows) {
    assert.ok(row.receipt === 'verification' || /^[a-f0-9-]{36}$/.test(row.receipt));
    assert.equal(row.sequence, '9223372036854775807');
    assert.equal(row.payloadHex, '00ff8007');
    digest.update(JSON.stringify([row.receipt, row.sequence, row.payloadHex]) + '\n');
  }
  return digest.digest('hex');
}

function captureUnary(state, fixture, input, result) {
  const receipt = grpcUnaryReceipt(fixture, input, result);
  assert.ok(state.receipts.length < 128, 'The owned gRPC receipt capacity is exceeded');
  assert.equal(state.seen.has(receipt.receipt), false);
  state.seen.add(receipt.receipt);
  state.receipts.push(receipt);
}

export async function verifyGrpc(service, fixture) {
  const client = service.client('Echo');
  assert.ok(client.native() instanceof Client);
  const payload = grpcCorpusPayload();
  const input = { value: fixture.marker + '-unary', sequence: '9223372036854775807', payload };
  const result = await client.unary('Bounce', input);
  const state = {
    client,
    receipts: [],
    seen: new Set(),
    verificationUnaryCalls: 0,
    verificationStreams: 0,
    verificationStreamMessages: 0,
    callbacks: 0,
    completed: 0,
    active: 0,
    peakActive: 0,
    serviceClosed: false,
  };
  captureUnary(state, fixture, input, result);
  state.verificationUnaryCalls++;
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
  state.verificationStreams++;
  state.verificationStreamMessages += messages.length;
  observations.set(service, state);
  return {
    nativeClientIdentityVerified: true,
    actualUnaryVerified: true,
    exactInt64StringPreserved: true,
    binaryPayloadPreserved: true,
    actualOrderedStreamMessages: 3,
  };
}

/** One request carries a fresh fixture-only correlation in an unchanged protobuf string field. */
export function grpcWorkload(service, fixture) {
  const state = observations.get(service);
  assert.ok(state, 'gRPC corpus verification must precede workload execution');
  return {
    'mutual-tls-unary-bounce': async () => {
      assert.equal(state.active, 0);
      assert.equal(state.serviceClosed, false);
      state.callbacks++;
      state.active++;
      state.peakActive = Math.max(state.peakActive, state.active);
      try {
        const input = {
          value: fixture.marker + '-unary-' + randomUUID(),
          sequence: '9223372036854775807',
          payload: grpcCorpusPayload(),
        };
        captureUnary(state, fixture, input, await state.client.unary('Bounce', input));
        state.completed++;
        return true;
      } finally {
        state.active--;
      }
    },
  };
}

export async function grpcObservations(service, { measure, records }) {
  const state = observations.get(service);
  assert.ok(state, 'gRPC corpus verification must precede completion');
  await service.close();
  state.serviceClosed = true;
  assert.equal(state.callbacks, state.completed);
  assert.equal(state.active, 0);
  assert.ok(state.peakActive <= 1);
  if (measure) {
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'mutual-tls-unary-bounce');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
    assert.equal(state.callbacks, record.sampleCount + record.warmupIterations);
  } else assert.equal(records.length, 0);
  const totalUnaryCalls = state.verificationUnaryCalls + state.completed;
  assert.equal(state.receipts.length, totalUnaryCalls);
  assert.equal(state.seen.size, totalUnaryCalls);
  const receiptDigest = grpcReceiptDigest(state.receipts);
  state.receipts.length = 0;
  state.seen.clear();
  return {
    actualUnaryCallbacks: state.callbacks,
    successfulUnaryEchoes: state.completed,
    verificationUnaryCalls: state.verificationUnaryCalls,
    totalUnaryCalls,
    verificationStreams: state.verificationStreams,
    verificationStreamMessages: state.verificationStreamMessages,
    receiptDigest,
    activeCallbacks: state.active,
    peakConcurrentCallbacks: state.peakActive,
    retainedReceipts: state.receipts.length,
    serviceClosed: state.serviceClosed,
  };
}

export function requireGrpcProcessTreeResource(resource) {
  assert.ok(
    resource,
    'gRPC sampling requires complete descriptor/client process resource accounting',
  );
  assert.equal(resource.scope, 'whole-supervised-lifecycle');
  assert.equal(resource.allChildrenWaited, true);
  assert.equal(resource.remainingOwnedProcesses, 0);
  assert.equal(resource.pythonObserverIncluded, false);
  assert.equal(resource.externalServerResourcesIncluded, false);
  assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
  assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
  assert.equal(resource.rssReadQuality.inaccessibleReads, 0);
  assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
  assert.ok(
    Number.isSafeInteger(resource.samplingRounds) &&
      resource.samplingRounds > 0 &&
      resource.samplingRounds <= 10000,
  );
  for (const key of [
    'elapsedMs',
    'userCpuSeconds',
    'systemCpuSeconds',
    'maxSamplingGapMs',
    'largestSingleProcessRssBytes',
    'sampledSummedRssPeakBytes',
    'sampledLargestSingleRssBytes',
  ])
    assert.ok(Number.isFinite(resource[key]) && resource[key] >= 0);
}
