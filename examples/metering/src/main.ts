import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application, MeteringEvent } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { httpPlugin } from '@arkenivajs/http';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { meteringPlugin, parseMeteringEvent } from '@arkenivajs/metering';

/** Real signed assertions and private JSONL records; all listeners/files are disposable. */
export async function runMeteringExample(): Promise<
  Readonly<{ statuses: Readonly<Record<string, number>>; events: readonly MeteringEvent[] }>
> {
  const workspace = await mkdtemp(join(tmpdir(), 'arkeniva-metering-guide-'));
  let issuerResource: ReturnType<typeof createServer> | undefined;
  let upstreamResource: ReturnType<typeof createServer> | undefined;
  const sink = new Writable({
    write(_chunk, _encoding, done) {
      done();
    },
  });
  let app: Application | undefined;
  let result: Awaited<ReturnType<typeof runMeteringExample>> | undefined;
  let failed = false,
    primary: unknown;
  try {
    const pair = await generateKeyPair('RS256');
    const key = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'meter-example',
      alg: 'RS256',
      use: 'sig',
    };
    const issuer = createServer((request, reply) => {
      reply.setHeader('content-type', 'application/json');
      reply.end(
        JSON.stringify(
          request.url === '/keys'
            ? { keys: [key] }
            : { issuer: authority, jwks_uri: authority + '/keys' },
        ),
      );
    });
    issuerResource = issuer;
    await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
    const issuerAddress = issuer.address();
    if (!issuerAddress || typeof issuerAddress !== 'object')
      throw new Error('Example issuer listener is unavailable');
    const authority = `http://127.0.0.1:${issuerAddress.port}`;
    const upstream = createServer((_request, reply) => {
      reply.setHeader('content-type', 'application/json');
      reply.end('{"available":true}');
    });
    upstreamResource = upstream;
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    const upstreamAddress = upstream.address();
    if (!upstreamAddress || typeof upstreamAddress !== 'object')
      throw new Error('Example upstream listener is unavailable');
    const upstreamOrigin = `http://127.0.0.1:${upstreamAddress.port}`;
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    if (!reserved || typeof reserved !== 'object')
      throw new Error('Example API port is unavailable');
    app = await createApplication({
      service: { name: 'metering-example', version: '1.0.0', environment: 'test' },
      http: { host: '127.0.0.1', port: reserved.port },
      security: {
        issuer: authority,
        audience: 'api://metering-example',
        assuranceResolver(identity) {
          const authenticatedAt = identity.claims.auth_time;
          const age =
            typeof authenticatedAt === 'number' ? Date.now() / 1000 - authenticatedAt : Infinity;
          return identity.issuer === authority &&
            identity.claims.acr === 'urn:example:recent-mfa' &&
            Array.isArray(identity.claims.amr) &&
            identity.claims.amr.includes('otp') &&
            age >= 0 &&
            age <= 60
            ? 'mfa'
            : 'single-factor';
        },
      },
      telemetry: { mode: 'off' },
      metering: { enabled: true, exporter: 'jsonl', path: 'events.jsonl' },
      plugins: [
        loggingPlugin({ destination: sink }),
        securityPlugin({ allowInsecureLoopback: true }),
        telemetryPlugin(),
        meteringPlugin({
          workspace,
          dependencies: ['telemetry'],
          usageDefinitions: { 'orders.lookup': 'operations' },
        }),
        httpPlugin({
          allowedOrigins: [upstreamOrigin],
          allowPrivateNetwork: true,
          dependencies: ['metering', 'telemetry'],
        }),
        apiPlugin({ dependencies: ['security', 'metering', 'telemetry'] }),
      ],
    });
    const running = app;
    const orders = [
      { id: 'a', tenant: 'tenant-A' },
      { id: 'b', tenant: 'tenant-B' },
    ];
    app.api.get<{ id: string }, Record<string, never>, never, { id: string }>('/orders/:id', {
      schema: {
        response: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
          additionalProperties: false,
        },
      },
      auth: { required: true, scopes: ['orders:read'], assurance: 'mfa' },
      async handler(context) {
        const response = await running.http.get(upstreamOrigin + '/available', {
          signal: context.signal,
        });
        if (response.status !== 200)
          throw new KitError({
            code: 'EK_BACKEND_UNAVAILABLE',
            message: 'Example public upstream is unavailable',
          });
        return running.meter!.measure({ tenant: context.auth!, operation: 'orders.lookup' }, () => {
          running.meter!.current()!.recordOperation('orders.lookup');
          const order = orders.find(
            (row) => row.id === context.params.id && row.tenant === context.auth!.tenantId,
          );
          if (!order)
            throw new KitError({
              code: 'EK_HTTP_NOT_FOUND',
              message: 'Tenant order was not found',
            });
          return { id: order.id };
        });
      },
    });
    await app.start();
    const address = (app.api as ManagedApiServer).address()!;
    const bearer = async (
      tenant: string,
      scope = 'orders:read',
      audience = 'api://metering-example',
      mfa = true,
    ) =>
      'Bearer ' +
      (await new SignJWT({
        tenant_id: tenant,
        scope,
        acr: mfa ? 'urn:example:recent-mfa' : 'urn:example:password',
        amr: mfa ? ['pwd', 'otp'] : ['pwd'],
        auth_time: Math.floor(Date.now() / 1000),
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'meter-example', typ: 'JWT' })
        .setSubject('example-user')
        .setIssuer(authority)
        .setAudience(audience)
        .setExpirationTime('5m')
        .sign(pair.privateKey));
    const tokenA = await bearer('tenant-A'),
      tokenB = await bearer('tenant-B');
    const send = async (
      id: string,
      authorization?: string,
      headers: Record<string, string> = {},
      method = 'GET',
    ) => {
      const reply = await fetch(address + '/orders/' + id, {
        method,
        headers: { ...headers, ...(authorization ? { authorization } : {}) },
      });
      await reply.arrayBuffer();
      return reply.status;
    };
    const [permittedA, permittedB] = await Promise.all([send('a', tokenA), send('b', tokenB)]);
    const statuses = {
      permittedA,
      permittedB,
      spoofed: await send('b', tokenA, {
        'x-tenant-id': 'tenant-B',
        baggage: 'tenant_id=tenant-B',
      }),
      head: await send('a', tokenA, {}, 'HEAD'),
      missing: await send('a'),
      wrongAudience: await send('a', await bearer('tenant-A', 'orders:read', 'api://other')),
      missingScope: await send('a', await bearer('tenant-A', 'orders:write')),
      lowAssurance: await send(
        'a',
        await bearer('tenant-A', 'orders:read', 'api://metering-example', false),
      ),
    };
    await app.stop();
    const events = (await readFile(join(workspace, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => parseMeteringEvent(JSON.parse(line)));
    result = Object.freeze({ statuses: Object.freeze(statuses), events: Object.freeze(events) });
  } catch (error) {
    failed = true;
    primary = error;
  }
  const errors: unknown[] = [];
  for (const cleanup of [
    () => app?.stop(),
    async () => {
      if (!issuerResource) return;
      issuerResource.closeAllConnections();
      const server = issuerResource;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
    async () => {
      if (!upstreamResource) return;
      upstreamResource.closeAllConnections();
      const server = upstreamResource;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
    () => {
      sink.destroy();
    },
    () => rm(workspace, { recursive: true, force: true }),
  ]) {
    try {
      await cleanup();
    } catch (error) {
      errors.push(error);
    }
  }
  if (failed) throw primary;
  if (errors.length) throw new AggregateError(errors, 'Example cleanup failed');
  return result!;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await runMeteringExample();
  console.log(
    JSON.stringify({
      statuses: result.statuses,
      events: result.events.length,
      tenants: [...new Set(result.events.map((event) => event.tenantId))].sort(),
      tracesSampled: false,
    }),
  );
}
