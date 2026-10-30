// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect } from 'node:http2';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { VerifiedTenantContext } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { scimPlugin, SCIM_CAPABILITY } from '../../dist/index.js';
import type { ScimRecord, ScimService } from '../../dist/index.js';
import { fixture } from '../fixture.js';
import { tlsFixture } from '../tls-fixture.js';

for (const mode of ['http', 'https', 'http2'] as const)
  test(
    `Actual ${mode} SCIM endpoints enforce bearer and tenant policy before native provisioning`,
    { timeout: 15000 },
    async () => {
      const f = await fixture(),
        tls = mode === 'http' ? undefined : await tlsFixture(),
        reservation = createServer();
      await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
      const address = reservation.address();
      assert.ok(address && typeof address === 'object');
      await new Promise<void>((resolve) => reservation.close(() => resolve()));
      const sink = new Writable({
        write(_chunk, _encoding, done) {
          done();
        },
      });
      let app: Awaited<ReturnType<typeof createApplication>> | undefined;
      const users = f.provider('Users'),
        originalList = users.list;
      let held: { entered(): void; release: Promise<void>; aborted(): void } | undefined;
      users.list = async (...args) => {
        if (held) {
          const selected = held;
          args[2]?.signal?.addEventListener('abort', selected.aborted, { once: true });
          selected.entered();
          await selected.release;
        }
        return originalList(...args);
      };
      const authority = {
        async require(
          _action: string,
          hint: { issuer: string; subject: string } | undefined,
          context: { tenant?: VerifiedTenantContext },
        ) {
          const auth = app!.auth,
            tenant = context.tenant;
          if (
            !auth ||
            !hint ||
            !tenant ||
            auth.tenantFrom(tenant.identity) !== tenant ||
            hint.issuer !== tenant.identity.issuer ||
            hint.subject !== tenant.identity.subject
          )
            throw new Error('The actual application rejected the provisioning session');
          return { ...hint, tenant };
        },
      };
      try {
        app = await createApplication({
          service: { name: 'scim-http-fixture', version: '1.0.0', environment: 'test' },
          http: {
            host: '127.0.0.1',
            port: address.port,
            ...(tls ? { protocol: 'https' as const, tls: tls.files, http2: mode === 'http2' } : {}),
          },
          security: { issuer: f.issuer, audience: 'api://scim-fixture', algorithms: ['ES256'] },
          plugins: [
            loggingPlugin({ destination: sink }),
            securityPlugin({ allowInsecureLoopback: true }),
            apiPlugin({ dependencies: ['security'] }),
            scimPlugin({
              users,
              groups: f.provider('Groups'),
              authority,
              capabilities: { patch: true, bulk: false, filter: true, sort: true, etag: true },
              maxPageSize: 10,
              maxFilterDepth: 8,
              maxRequestBytes: 16384,
              maxConcurrent: mode === 'http' ? 1 : 4,
            }),
          ],
        });
        await app.start();
        const origin = (app.api as ManagedApiServer).address()!;
        type Result = {
          status: number;
          body: string;
          headers: Record<string, string | string[] | undefined>;
        };
        const exchange = async (
          method: string,
          path: string,
          body?: unknown,
          tenant = 'tenant-a',
          extra: Record<string, string> = {},
          anonymous = false,
          raw?: string | Buffer,
        ): Promise<Result> => {
          const source = await f.request(method as 'GET', path, body, tenant),
            headers = {
              ...(!anonymous ? { authorization: source.headers.authorization! } : {}),
              ...(body === undefined ? {} : { 'content-type': 'application/scim+json' }),
              ...extra,
            },
            payload = raw ?? (body === undefined ? undefined : JSON.stringify(body));
          if (mode === 'http2') {
            return new Promise<Result>((resolve, reject) => {
              const client = connect(origin, { ca: tls!.ca, rejectUnauthorized: true });
              client.once('error', reject);
              const stream = client.request({ ':method': method, ':path': path, ...headers }),
                chunks: Buffer[] = [];
              let responseHeaders: Record<string, string | string[] | undefined> = {},
                status = 0;
              stream.on('response', (incoming) => {
                status = Number(incoming[':status']);
                responseHeaders = Object.fromEntries(
                  Object.entries(incoming).filter((entry) => !entry[0].startsWith(':')),
                ) as typeof responseHeaders;
              });
              stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
              stream.once('error', (error) => {
                client.destroy();
                reject(error);
              });
              stream.once('end', () => {
                client.close();
                resolve({
                  status,
                  headers: responseHeaders,
                  body: Buffer.concat(chunks).toString('utf8'),
                });
              });
              stream.end(payload);
            });
          }
          return new Promise<Result>((resolve, reject) => {
            const outgoing = (mode === 'http' ? httpRequest : httpsRequest)(
              origin + path,
              {
                method,
                headers,
                ...(tls ? { ca: tls.ca, rejectUnauthorized: true } : {}),
                agent: false,
              },
              (incoming) => {
                const chunks: Buffer[] = [];
                incoming.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
                incoming.once('error', reject);
                incoming.once('end', () =>
                  resolve({
                    status: incoming.statusCode!,
                    headers: incoming.headers,
                    body: Buffer.concat(chunks).toString('utf8'),
                  }),
                );
              },
            );
            outgoing.once('error', reject);
            outgoing.end(payload);
          });
        };
        assert.equal(
          (await exchange('GET', '/scim/v2/Users', undefined, 'tenant-a', {}, true)).status,
          401,
        );
        const discovery = await exchange('GET', '/scim/v2/ServiceProviderConfig');
        assert.equal(discovery.status, 200, discovery.body);
        for (const raw of ['{"schemas":', Buffer.from([0xff, 0xfe])]) {
          for (const contentType of ['application/scim+json', 'application/json']) {
            const invalid = await exchange(
              'POST',
              '/scim/v2/Users',
              {},
              'tenant-a',
              { 'content-type': contentType },
              false,
              raw,
            );
            assert.equal(invalid.status, 400, invalid.body);
            assert.equal(
              JSON.parse(invalid.body).schemas[0],
              'urn:ietf:params:scim:api:messages:2.0:Error',
            );
          }
        }
        assert.equal(
          (
            await exchange('POST', '/scim/v2/Users', {}, 'tenant-a', {
              'content-type': 'text/plain',
            })
          ).status,
          415,
        );
        const body = {
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
            userName: 'https-fixture-user',
            externalId: 'https-external',
          },
          created = await exchange('POST', '/scim/v2/Users', body);
        assert.equal(created.status, 201, created.body);
        assert.equal(
          created.headers['content-type']?.toString().split(';')[0],
          'application/scim+json',
        );
        const record = JSON.parse(created.body) as ScimRecord,
          location = '/scim/v2/Users/' + record.id;
        assert.equal(created.headers.location, location);
        assert.equal((await exchange('GET', location, undefined, 'tenant-b')).status, 403);
        const changed = await exchange(
          'PATCH',
          location,
          {
            schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            Operations: [{ op: 'replace', path: 'active', value: false }],
          },
          'tenant-a',
          { 'if-match': created.headers.etag as string },
        );
        assert.equal(changed.status, 200, changed.body);
        assert.equal((JSON.parse(changed.body) as ScimRecord).active, false);
        assert.equal(
          (
            await exchange(
              'PATCH',
              location,
              {
                schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                Operations: [{ op: 'replace', path: 'active', value: true }],
              },
              'tenant-a',
              { 'if-match': created.headers.etag as string },
            )
          ).status,
          412,
        );
        assert.equal(
          (
            await exchange('POST', '/scim/v2/Groups', {
              schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
              displayName: 'Owned group',
              members: [{ value: 'privileged-account' }],
            })
          ).status,
          403,
        );
        assert.equal(
          (await exchange('POST', '/scim/v2/Users', { ...body, excess: 'x'.repeat(16385) })).status,
          413,
        );
        assert.equal((await exchange('DELETE', location)).status, 204);
        assert.equal((await exchange('GET', location)).status, 404);
        if (tls && mode === 'https')
          await assert.rejects(
            new Promise<void>((resolve, reject) => {
              const request = httpsRequest(
                origin + '/scim/v2/Users',
                {
                  ca: tls.ca,
                  rejectUnauthorized: true,
                  servername: 'foreign.invalid',
                  agent: false,
                },
                () => resolve(),
              );
              request.once('error', reject);
              request.end();
            }),
            { code: 'ERR_TLS_CERT_ALTNAME_INVALID' },
          );
        if (mode === 'http') {
          let entered!: () => void, release!: () => void, aborted!: () => void;
          const started = new Promise<void>((resolve) => {
              entered = resolve;
            }),
            stopped = new Promise<void>((resolve) => {
              aborted = resolve;
            }),
            pending = new Promise<void>((resolve) => {
              release = resolve;
            });
          held = { entered, release: pending, aborted };
          const source = await f.request('GET', '/Users'),
            client = httpRequest(origin + '/scim/v2/Users', {
              headers: { authorization: source.headers.authorization! },
              agent: false,
            });
          client.on('error', () => {});
          client.end();
          try {
            await within(() => started, { timeoutMs: 3000 });
            assert.equal((await exchange('GET', '/scim/v2/Users')).status, 503);
            client.destroy();
            // Abort must arrive well before the transport's five-second operation deadline.
            await within(() => stopped, { timeoutMs: 1000 });
            assert.equal((await exchange('GET', '/scim/v2/Users')).status, 503);
          } finally {
            held = undefined;
            release();
            client.destroy();
          }
          await new Promise<void>((resolve) => setImmediate(resolve));
          assert.equal((await exchange('GET', '/scim/v2/Users')).status, 200);
        }
        const service = app.resolve<ScimService>(SCIM_CAPABILITY);
        assert.throws(() => service.registerUsers(f.provider('Users')), {
          code: 'EK_LIFECYCLE_STATE',
        });
        await app.stop();
        await assert.rejects(service.handle(await f.request('GET', '/Users')), {
          code: 'EK_RESOURCE_CLOSED',
        });
      } finally {
        await app?.stop();
        sink.destroy();
        await f.close();
        await tls?.close();
      }
    },
  );
