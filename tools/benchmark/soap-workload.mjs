// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Agent } from 'node:https';
import { readFile } from 'node:fs/promises';
import { createClientAsync, HttpClient, Client } from 'soap';
import axios from 'axios';
import { createHash } from 'node:crypto';

export function soapConnection(fixture) {
  try {
    const url = new URL(fixture.endpoint);
    assert.equal(url.protocol, 'https:');
    assert.equal(url.hostname, '127.0.0.1');
    assert.ok(url.port && !url.username && !url.password && !url.search && !url.hash);
    assert.equal(url.pathname, '/soap');
    assert.ok(fixture.certificateFile?.startsWith('/') && fixture.wsdlFile?.startsWith('/'));
    return url;
  } catch {
    throw new Error(
      'The owned SOAP comparison requires a fixed verified-HTTPS loopback endpoint and local WSDL',
    );
  }
}

export function soapSettings(fixture) {
  soapConnection(fixture);
  return {
    services: [
      {
        id: 'comparison.v1',
        wsdlFile: fixture.wsdlFile,
        endpoint: fixture.endpoint,
        allowedOperations: ['ReadStock'],
        protocol: '1.1',
        trustedCaRef: 'owned-comparison-ca',
        maxResponseBytes: 4096,
      },
    ],
    secretProvider: {
      async get(reference) {
        assert.equal(reference, 'owned-comparison-ca');
        return { bytes: await readFile(fixture.certificateFile), keyVersion: 'v1' };
      },
    },
    policy: { maxConcurrent: 1, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 4096 },
  };
}

/** Native node-soap and Axios own actual WSDL decoding, serialization and verified HTTPS. */
export async function nativeSoap(fixture, wrongName = false) {
  soapConnection(fixture);
  const agent = new Agent({
    ca: await readFile(fixture.certificateFile),
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    maxSockets: 1,
    keepAlive: false,
    ...(wrongName ? { servername: 'wrong.invalid' } : {}),
  });
  const leases = new Set();
  return {
    async createClient(id) {
      assert.equal(id, 'comparison.v1');
      const request = axios.create({
        httpsAgent: agent,
        proxy: false,
        maxRedirects: 0,
        timeout: 3000,
        maxContentLength: 4096,
        maxBodyLength: 4096,
      });
      const client = await createClientAsync(fixture.wsdlFile, {
        endpoint: fixture.endpoint,
        disableCache: true,
        httpClient: new HttpClient({ request }),
      });
      assert.ok(client instanceof Client);
      assert.deepEqual(Object.keys(client.describe().InventoryService.InventoryPort), [
        'ReadStock',
      ]);
      let response;
      client.on('response', (_body, value, correlationId) => {
        response = { value, correlationId };
      });
      const lease = {
        native: () => client,
        describe: () => ({ serviceId: id, operations: ['ReadStock'], protocol: '1.1' }),
        async call(operation, input) {
          assert.equal(operation, 'ReadStock');
          response = undefined;
          const [data] = await client.ReadStockAsync(input);
          assert.ok(response?.value);
          return {
            data,
            status: response.value.status,
            headers: response.value.headers,
            correlationId: response.correlationId,
          };
        },
        async close() {
          client.removeAllListeners();
          leases.delete(lease);
        },
      };
      leases.add(lease);
      return lease;
    },
    async close() {
      try {
        for (const lease of [...leases]) await lease.close();
      } finally {
        agent.destroy();
      }
    },
  };
}

const observations = new WeakMap();

/** Aggregate private fixture receipts, never individual correlation IDs in public evidence. */
export function soapReceiptDigest(rows) {
  assert.ok(Array.isArray(rows) && rows.length <= 512);
  const digest = createHash('sha256').update('arkenivajs.soap.benchmark.receipts.v1\n');
  for (const row of rows) {
    assert.match(row.receipt, /^[a-f0-9-]{36}$/);
    assert.ok(row.index === 0 || row.index === 1);
    assert.equal(row.quantity, 12);
    digest.update(JSON.stringify([row.receipt, row.index, row.quantity]) + '\n');
  }
  return digest.digest('hex');
}

export function verifySoapResult(result) {
  assert.equal(result.status, 200);
  assert.deepEqual({ ...result.data }, { quantity: 12 });
  assert.equal(typeof result.correlationId, 'string');
  assert.ok(result.correlationId.length > 0 && result.correlationId.length <= 128);
  assert.ok(!/[\r\n]/.test(result.correlationId));
  const receipt = result.headers['x-owned-soap-receipt'];
  assert.match(receipt, /^[a-f0-9-]{36}$/);
  return receipt;
}

function captureResult(state, result, index) {
  const receipt = verifySoapResult(result);
  assert.ok(state.receipts.length < 128, 'The owned SOAP receipt capacity is exceeded');
  assert.equal(state.localCorrelations.has(result.correlationId), false);
  assert.equal(state.serverReceipts.has(receipt), false);
  state.localCorrelations.add(result.correlationId);
  state.serverReceipts.add(receipt);
  state.receipts.push({ receipt, index, quantity: result.data.quantity });
  state.inputs[index]++;
}

export async function verifySoap(service, fixture) {
  const client = await service.createClient('comparison.v1');
  try {
    assert.ok(client.native() instanceof Client);
    const description = client.describe();
    assert.equal(description.protocol, '1.1');
    assert.deepEqual([...description.operations], ['ReadStock']);
    const state = {
      receipts: [],
      localCorrelations: new Set(),
      serverReceipts: new Set(),
      inputs: [0, 0],
      verificationCalls: 0,
      callbacks: 0,
      completed: 0,
      active: 0,
      peakActive: 0,
      lease: undefined,
    };
    observations.set(service, state);
    const correlations = [];
    for (let index = 0; index < 2; index++) {
      const result = await client.call('ReadStock', { sku: fixture.marker + '-' + index });
      captureResult(state, result, index);
      state.verificationCalls++;
      correlations.push(result.correlationId);
    }
    assert.notEqual(correlations[0], correlations[1]);
    return {
      actualHttpsCallsVerified: 2,
      nativeClientIdentityVerified: true,
      approvedOperationVerified: true,
      actualHttpStatusVerified: true,
      distinctCorrelationIdsVerified: true,
    };
  } finally {
    await client.close();
  }
}

/** Reuse one owned lease while each callback performs an actual verified HTTPS exchange. */
export function soapWorkload(service, fixture) {
  const state = observations.get(service);
  assert.ok(state, 'SOAP corpus verification must precede workload execution');
  return {
    'read-stock-verified-https': async () => {
      assert.equal(state.active, 0);
      state.callbacks++;
      state.active++;
      state.peakActive = Math.max(state.peakActive, state.active);
      try {
        // Lease setup occurs during the first warmup callback, not the retained samples.
        state.lease ??= service.createClient('comparison.v1');
        const client = await state.lease,
          index = (state.callbacks - 1) % 2;
        captureResult(
          state,
          await client.call('ReadStock', { sku: fixture.marker + '-' + index }),
          index,
        );
        state.completed++;
        return true;
      } finally {
        state.active--;
      }
    },
  };
}

export async function soapObservations(service, { measure, records }) {
  const state = observations.get(service);
  assert.ok(state, 'SOAP corpus verification must precede completion');
  if (state.lease) {
    await (await state.lease).close();
    state.lease = undefined;
  }
  assert.equal(state.callbacks, state.completed);
  assert.equal(state.active, 0);
  assert.ok(state.peakActive <= 1);
  if (measure) {
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'read-stock-verified-https');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
    assert.equal(state.callbacks, record.sampleCount + record.warmupIterations);
  } else assert.equal(records.length, 0);
  const totalCalls = state.verificationCalls + state.completed;
  assert.equal(state.receipts.length, totalCalls);
  assert.equal(state.localCorrelations.size, totalCalls);
  assert.equal(state.serverReceipts.size, totalCalls);
  const receiptDigest = soapReceiptDigest(state.receipts);
  state.receipts.length = 0;
  state.localCorrelations.clear();
  state.serverReceipts.clear();
  return {
    actualCallCallbacks: state.callbacks,
    successfulDecodedCalls: state.completed,
    verificationCalls: state.verificationCalls,
    totalCalls,
    inputCounts: [...state.inputs],
    distinctLocalCorrelations: totalCalls,
    distinctServerReceipts: totalCalls,
    receiptDigest,
    activeCallbacks: state.active,
    peakConcurrentCallbacks: state.peakActive,
    retainedReceipts: state.receipts.length,
    ownedWorkloadLeases: Number(!!state.lease),
  };
}

export function requireSoapProcessTreeResource(resource) {
  assert.ok(resource, 'SOAP sampling requires complete parser process resource accounting');
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
