// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Agent } from 'node:https';
import { readFile } from 'node:fs/promises';
import { createClientAsync, HttpClient, Client } from 'soap';
import axios from 'axios';

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

export async function verifySoap(service, fixture) {
  const client = await service.createClient('comparison.v1');
  try {
    assert.ok(client.native() instanceof Client);
    const description = client.describe();
    assert.equal(description.protocol, '1.1');
    assert.deepEqual([...description.operations], ['ReadStock']);
    const correlations = [];
    for (let index = 0; index < 2; index++) {
      const result = await client.call('ReadStock', { sku: fixture.marker + '-' + index });
      assert.equal(result.status, 200);
      assert.deepEqual({ ...result.data }, { quantity: 12 });
      assert.equal(typeof result.correlationId, 'string');
      assert.ok(result.correlationId.length > 0);
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
