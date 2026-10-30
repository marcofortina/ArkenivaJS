// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import { apiPlugin } from '@arkenivajs/api';
import { createScimService, scimPlugin, SCIM_CAPABILITY } from '@arkenivajs/security-scim';
import { startScimFixture } from '../scim-fixture.mjs';
import { grantScim, nativeScim, rememberScimOwner, scimSettings } from '../scim-workload.mjs';
import {
  scimIterations,
  scimWarmupIterations,
  scimMaximumRetainedReads,
} from '../scim-workload.mjs';

test(
  'Actual SCIM providers reject forged tenant authority, foreign records and outages without changing resource versions',
  { timeout: 30000 },
  async () => {
    const authority = await startScimFixture();
    let app;
    try {
      const denied = await globalThis.fetch(authority.fixture.bridgeUrl + '/grant', {
        method: 'POST',
        headers: { authorization: 'Bearer invalid' },
      });
      assert.equal(denied.status, 400);
      await denied.arrayBuffer();
      assert.deepEqual(authority.observations(), { handedOut: 0, providerCalls: 0 });
      const fixture = structuredClone(authority.fixture);
      await grantScim(fixture);
      const settings = scimSettings(fixture);
      const options = (environment) => ({
        service: { name: 'scim-comparison-test', version: '1.0.0', environment },
        http: { host: '127.0.0.1', port: 0 },
        security: { issuer: fixture.issuer, audience: fixture.audience, algorithms: ['RS256'] },
        logging: { level: 'silent' },
        plugins: [
          loggingPlugin(),
          securityPlugin({
            allowInsecureLoopback: true,
            jwksUrl: fixture.issuer + '/keys',
            authorizeTenant: (_identity, tenant) => tenant === fixture.grant.tenant,
          }),
          apiPlugin({ dependencies: ['security'] }),
          scimPlugin(settings),
        ],
      });
      app = await createApplication(options('test'));
      rememberScimOwner(app);
      await app.start();
      const service = app.resolve(SCIM_CAPABILITY),
        identity = await app.auth.verifyBearer('Bearer ' + fixture.grant.token),
        tenant = app.auth.tenantFrom(identity);
      const body = {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: fixture.marker,
        externalId: fixture.grant.externalId,
        active: true,
      };
      const request = (method, path, contents, headers = {}, auth = tenant) =>
        service.handle({
          method,
          path,
          body: contents,
          auth,
          headers: {
            authorization: 'Bearer ' + fixture.grant.token,
            'content-type': 'application/scim+json',
            ...headers,
          },
        });
      const created = await request('POST', '/Users', body);
      assert.equal(created.status, 201);
      const path = '/Users/' + created.body.id,
        before = authority.observations().providerCalls;
      for (const forged of [undefined, { ...tenant }, { ...tenant, tenantId: 'foreign' }]) {
        const response = await service.handle({
          method: 'GET',
          path,
          body: undefined,
          auth: forged,
          headers: { authorization: 'Bearer ' + fixture.grant.token },
        });
        assert.equal(response.status, 403);
      }
      for (const authorization of [undefined, 'Bearer invalid'])
        assert.equal((await request('GET', path, undefined, { authorization })).status, 401);
      assert.equal(authority.observations().providerCalls, before);

      const foreign = structuredClone(authority.fixture),
        native = await nativeScim(foreign),
        foreignIdentity = await native.auth().verifyBearer('Bearer ' + foreign.grant.token);
      const foreignResource = await native.handle({
        method: 'POST',
        path: '/Users',
        body: { ...body, externalId: foreign.grant.externalId },
        auth: native.auth().tenantFrom(foreignIdentity),
        headers: { authorization: 'Bearer ' + foreign.grant.token },
      });
      assert.equal(foreignResource.status, 201);
      const foreignRead = await request('GET', '/Users/' + foreignResource.body.id);
      assert.equal(foreignRead.status, 403);
      assert.ok(!JSON.stringify(foreignRead).includes(foreignResource.body.id));

      authority.unavailable(true);
      const failed = await request(
        'PATCH',
        path,
        {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{ op: 'replace', path: 'active', value: false }],
        },
        { 'if-match': created.headers.etag },
      );
      assert.equal(failed.status, 503);
      authority.unavailable(false);
      const recovered = await request('GET', path);
      assert.equal(recovered.status, 200);
      assert.equal(recovered.body.active, true);
      assert.equal(recovered.headers.etag, '"1"');
      assert.throws(
        () =>
          createScimService({
            environment: 'production',
            auth: app.auth,
            authority: settings.authority,
          }),
        { code: 'EK_CONFIG_INVALID' },
      );
      const production = createScimService({
        environment: 'production',
        auth: app.auth,
        authority: {
          async require() {
            throw new Error('Provisioning is denied');
          },
        },
      });
      assert.throws(() => production.registerUsers(settings.users), { code: 'EK_CONFIG_INVALID' });
      assert.throws(() => production.registerGroups(settings.groups), {
        code: 'EK_CONFIG_INVALID',
      });
    } finally {
      try {
        await app?.stop();
      } finally {
        await authority.close();
      }
    }
  },
);

test(
  'Verified and sampled SCIM profiles preserve actual SQL ownership, read bodies and ETags',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-scim-harness-'));
    const script = fileURLToPath(new URL('../scim.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const measured = mode === '--smoke',
          output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 150000,
          maxBuffer: 1048576,
        });
        const encoded = await readFile(join(output, 'report.json'), 'utf8'),
          report = JSON.parse(encoded);
        assert.equal(report.measured, measured);
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.doesNotMatch(encoded, /owned-scim-private-user|scim-[a-f0-9]{24}|127\.0\.0\.1/);
        const protocolText = await readFile(join(output, 'protocol-observation.json'), 'utf8'),
          protocol = JSON.parse(protocolText);
        assert.equal(protocol.actualDeletedResources, 4);
        assert.equal(protocol.independentTenantOwners, 4);
        assert.equal(protocol.durableVersionPerResource, 4);
        assert.equal(protocol.releaseGate, false);
        assert.doesNotMatch(protocolText, /owned-scim-private-user|scim-[a-f0-9]{24}|127\.0\.0\.1/);
        if (measured) {
          const reads = report.records.reduce((sum, row) => sum + row.completion.checkedReads, 0);
          assert.equal(reads, 4 * (scimIterations + scimWarmupIterations));
          assert.equal(protocol.independentlyObservedSampleReads, reads);
          assert.equal(protocol.actualLiveReadResources, 4);
          assert.equal(protocol.unchangedReadResourceVersion, 1);
          assert.equal(protocol.unchangedReadBodyAndOwnership, true);
          assert.equal(protocol.parentProviderResources, null);
          assert.equal(protocol.postgresServerResources, null);
        } else
          assert.deepEqual(protocol, {
            actualDeletedResources: 4,
            independentTenantOwners: 4,
            durableVersionPerResource: 4,
            releaseGate: false,
          });
        for (const row of report.records) {
          assert.deepEqual(row.verification, {
            actualDurableCrudVerified: true,
            idempotentCreateRetries: 2,
            atomicEtagWinners: 1,
            exactNativePatchAndPagination: true,
            deletedResourceNotReturned: true,
          });
          assert.equal(row.completion.sampledReads, measured ? scimIterations : 0);
          assert.equal(row.completion.warmupReads, measured ? scimWarmupIterations : 0);
          assert.equal(
            row.completion.checkedReads,
            row.completion.sampledReads + row.completion.warmupReads,
          );
          if (measured) {
            assert.equal(row.records.length, 1);
            const record = row.records[0];
            assert.equal(record.operation, 'getUser');
            assert.equal(record.sampleCount, scimIterations);
            assert.equal(record.warmupIterations, scimWarmupIterations);
            assert.equal(record.rawLatency.unit, 'milliseconds');
            assert.equal(record.rawLatency.values.length, record.sampleCount);
            assert.ok(
              record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0),
            );
            assert.ok(record.throughputOpsPerSecond > 0);
            assert.ok(row.resource.elapsedMs > 0);
            assert.equal(row.completion.unchangedBodyAndEtag, true);
            assert.equal(row.completion.activeCallbacks, 0);
            assert.equal(
              row.completion.peakRetainedResponses,
              scimIterations + scimWarmupIterations,
            );
            assert.equal(row.completion.maximumRetainedResponses, scimMaximumRetainedReads);
          } else {
            assert.deepEqual(row.records, []);
            assert.equal(row.resource, null);
          }
          assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
          if (row.quality) assert.ok(row.quality.metricSeries > 0);
        }
      }
      const unsupported = join(directory, 'unsupported');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--full', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
