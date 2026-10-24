import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication, KitError } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';

/** Execute a disposable signed-token demonstration with no persistent credentials or data. */
export async function runTenantExample(): Promise<
  Readonly<{
    permitted: number;
    spoofed: number;
    missing: number;
    wrongAudience: number;
    missingScope: number;
  }>
> {
  const pair = await generateKeyPair('RS256');
  const key = {
    ...(await exportJWK(pair.publicKey)),
    kid: 'example-key',
    alg: 'RS256',
    use: 'sig',
  };
  const issuer = createServer((request, reply) => {
    reply.setHeader('content-type', 'application/json');
    reply.end(
      JSON.stringify(
        request.url === '/keys'
          ? { keys: [key] }
          : {
              issuer: authority,
              jwks_uri: authority + '/keys',
            },
      ),
    );
  });
  await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
  const address = issuer.address();
  if (!address || typeof address !== 'object') throw new Error('Issuer listener is unavailable');
  const authority = `http://127.0.0.1:${address.port}`;
  const sink = new Writable({
    write(_chunk, _encoding, done) {
      done();
    },
  });
  const records = [
    { id: 'a', tenant: 'tenant-A' },
    { id: 'b', tenant: 'tenant-B' },
  ];
  let app;
  try {
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    if (!reserved || typeof reserved !== 'object') throw new Error('API test port is unavailable');
    app = await createApplication({
      service: { name: 'tenant-example', version: '1.0.0', environment: 'test' },
      http: { host: '127.0.0.1', port: reserved.port },
      security: { issuer: authority, audience: 'api://orders', algorithms: ['RS256'] },
      plugins: [
        loggingPlugin({ destination: sink }),
        securityPlugin({ allowInsecureLoopback: true }),
        apiPlugin({ dependencies: ['security'] }),
      ],
    });
    const api = app.api as ManagedApiServer;
    app.api.get<{ id: string }, Record<string, never>, never, { id: string }>('/records/:id', {
      auth: { required: true, scopes: ['orders:read'] },
      schema: {
        params: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
        response: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
          additionalProperties: false,
        },
      },
      handler(context) {
        const row = records.find(
          (row) => row.id === context.params.id && row.tenant === context.auth!.tenantId,
        );
        if (!row) throw new KitError({ code: 'EK_HTTP_NOT_FOUND', message: 'Record not found' });
        return { id: row.id };
      },
    });
    await app.start();
    const bearer = async (audience = 'api://orders', scope = 'orders:read') =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: 'tenant-A', scope })
        .setProtectedHeader({ alg: 'RS256', kid: 'example-key', typ: 'JWT' })
        .setSubject('example-user')
        .setIssuer(authority)
        .setAudience(audience)
        .setExpirationTime('2m')
        .sign(pair.privateKey));
    const status = async (id: string, authorization?: string) => {
      const response = await fetch(api.address() + '/records/' + id, {
        headers: {
          'x-tenant-id': 'tenant-B',
          baggage: 'tenant_id=tenant-B',
          ...(authorization ? { authorization } : {}),
        },
      });
      await response.arrayBuffer();
      return response.status;
    };
    const token = await bearer();
    return Object.freeze({
      permitted: await status('a', token),
      spoofed: await status('b', token),
      missing: await status('b'),
      wrongAudience: await status('a', await bearer('api://other')),
      missingScope: await status('a', await bearer('api://orders', 'orders:write')),
    });
  } finally {
    try {
      await app?.stop();
    } finally {
      sink.destroy();
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(JSON.stringify(await runTenantExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'Example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
