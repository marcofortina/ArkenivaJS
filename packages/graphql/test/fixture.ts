// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { Writable } from 'node:stream';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Plugin, ServerTlsFiles } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { GRAPHQL_CAPABILITY, graphqlPlugin } from '../dist/index.js';
import type { GraphqlPluginSettings, GraphqlService } from '../dist/index.js';

export const base = (): GraphqlPluginSettings => ({
  schema: 'type Query { ping: String! }',
  resolvers: { Query: { ping: () => 'pong' } },
  security: { authorizeField: () => true },
});

export async function tlsFiles() {
  const directory = await mkdtemp(join(tmpdir(), 'arkeniva-graphql-tls-'));
  const privateKeyFile = join(directory, 'key.pem'),
    certificateFile = join(directory, 'cert.pem');
  try {
    await promisify(execFile)('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      privateKeyFile,
      '-out',
      certificateFile,
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ]);
    return {
      tls: { privateKeyFile, certificateFile } satisfies ServerTlsFiles,
      ca: await readFile(certificateFile),
      close: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

export async function fixture(
  settings: GraphqlPluginSettings = base(),
  options: {
    authenticated?: boolean;
    tls?: ServerTlsFiles;
    plugins?: readonly Plugin[];
  } = {},
) {
  const pair = await generateKeyPair('ES256'),
    jwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'graphql-fixture',
      alg: 'ES256',
      use: 'sig',
    };
  let issuer = '';
  const authority = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        request.url === '/keys' ? { keys: [jwk] } : { issuer, jwks_uri: issuer + '/keys' },
      ),
    );
  });
  await new Promise<void>((resolve) => authority.listen(0, '127.0.0.1', resolve));
  const address = authority.address();
  if (!address || typeof address !== 'object')
    throw new Error('GraphQL authority address is unavailable');
  issuer = 'http://127.0.0.1:' + address.port;
  let logs = '';
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs += chunk.toString();
      done();
    },
  });
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  const close = async () => {
    try {
      await app?.stop();
    } finally {
      sink.destroy();
      authority.closeAllConnections();
      await new Promise<void>((resolve) => authority.close(() => resolve()));
    }
  };
  try {
    const authenticated = options.authenticated ?? true;
    app = await createApplication({
      service: { name: 'graphql-fixture', version: '1.0.0', environment: 'test' },
      http: {
        host: '127.0.0.1',
        port: 0,
        ...(options.tls ? { protocol: 'https' as const, tls: options.tls } : {}),
      },
      logging: { level: 'debug' },
      ...(authenticated
        ? { security: { issuer, audience: 'api://graphql', algorithms: ['ES256'] } }
        : {}),
      plugins: [
        loggingPlugin({ destination: sink }),
        ...(authenticated ? [securityPlugin({ allowInsecureLoopback: true })] : []),
        apiPlugin({ dependencies: authenticated ? ['security'] : [] }),
        ...(options.plugins ?? []),
        graphqlPlugin(settings),
      ],
    });
    await app.start();
    const api = app.resolve<ManagedApiServer>(COMPONENTS.api),
      service = app.resolve<GraphqlService>(GRAPHQL_CAPABILITY);
    const origin = api.address();
    if (!origin) throw new Error('GraphQL listener address is unavailable');
    return {
      app,
      api,
      service,
      origin,
      logs: () => logs,
      close,
      token: async (tenant = 'tenant-a', scope = 'graphql:read') =>
        'Bearer ' +
        (await new SignJWT({ tenant_id: tenant, scope })
          .setProtectedHeader({ alg: 'ES256', kid: 'graphql-fixture', typ: 'JWT' })
          .setIssuer(issuer)
          .setAudience('api://graphql')
          .setSubject('graphql-user')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(pair.privateKey)),
    };
  } catch (error) {
    await close();
    throw error;
  }
}

/** Real TCP/TLS requests exercise the shared listener rather than Fastify injection. */
export function send(
  origin: string,
  body: unknown,
  options: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    ca?: Buffer;
    raw?: boolean;
  } = {},
): Promise<{ status: number; body: string; json(): Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const outgoing = (origin.startsWith('https:') ? httpsRequest : httpRequest)(
      origin + (options.path ?? '/graphql'),
      {
        method: options.method ?? 'POST',
        headers: { 'content-type': 'application/json', ...options.headers },
        ...(options.ca ? { ca: options.ca } : {}),
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.once('error', reject);
        response.once('end', () => {
          const encoded = Buffer.concat(chunks).toString();
          resolve({
            status: response.statusCode ?? 0,
            body: encoded,
            json: () => JSON.parse(encoded),
          });
        });
      },
    );
    outgoing.once('error', reject);
    outgoing.end(
      body === undefined ? undefined : options.raw ? (body as string) : JSON.stringify(body),
    );
  });
}
