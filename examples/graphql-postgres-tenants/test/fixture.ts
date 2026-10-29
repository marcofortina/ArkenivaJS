// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { request } from 'node:https';
import { Writable } from 'node:stream';
import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { COMPONENTS } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { createCustomerExample } from '../dist/main.js';

/** Owned loopback issuer and verified TLS listener; no external identities or persistent credentials. */
export async function fixture(schema: string) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-graphql-guide-'));
  await chmod(directory, 0o700);
  const key = join(directory, 'server.key'),
    cert = join(directory, 'server.pem');
  const pair = await generateKeyPair('ES256'),
    jwk = { ...(await exportJWK(pair.publicKey)), kid: 'example', alg: 'ES256' };
  let issuer = '',
    logs = '';
  const authority = createServer((incoming, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        incoming.url === '/keys' ? { keys: [jwk] } : { issuer, jwks_uri: issuer + '/keys' },
      ),
    );
  });
  let example: Awaited<ReturnType<typeof createCustomerExample>> | undefined;
  const destination = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs += chunk.toString();
      done();
    },
  });
  const close = async () => {
    try {
      await example?.app.stop();
    } finally {
      destination.destroy();
      authority.closeAllConnections();
      await new Promise<void>((resolve) => authority.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  };
  try {
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        key,
        '-out',
        cert,
      ],
      { timeout: 10000 },
    );
    await chmod(key, 0o600);
    const ca = await readFile(cert);
    await new Promise<void>((resolve) => authority.listen(0, '127.0.0.1', resolve));
    const address = authority.address();
    if (!address || typeof address !== 'object') throw new Error('Example issuer is unavailable');
    issuer = 'http://127.0.0.1:' + address.port;
    example = await createCustomerExample({
      service: { name: 'graphql-example', version: '1.0.0', environment: 'test' },
      http: {
        protocol: 'https',
        host: '127.0.0.1',
        port: 0,
        tls: { privateKeyFile: key, certificateFile: cert },
      },
      issuer,
      audience: 'api://graphql-example',
      allowInsecureLoopback: true,
      destination,
      schema,
    });
    await example.app.start();
    const origin = example.app.resolve<ManagedApiServer>(COMPONENTS.api).address();
    if (!origin) throw new Error('Example HTTPS listener is unavailable');
    const send = (
      body: unknown,
      authorization?: string,
      path = '/graphql',
      method = 'POST',
      trust = true,
      headers: Readonly<Record<string, string>> = {},
    ): Promise<{ status: number; body: string }> =>
      new Promise((resolve, reject) => {
        const outgoing = request(
          origin + path,
          {
            method,
            ...(trust ? { ca } : {}),
            headers: {
              ...headers,
              'content-type': 'application/json',
              ...(authorization ? { authorization } : {}),
            },
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on('data', (chunk: Buffer) => chunks.push(chunk));
            response.once('error', reject);
            response.once('end', () =>
              resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString() }),
            );
          },
        );
        outgoing.once('error', reject);
        outgoing.end(body === undefined ? undefined : JSON.stringify(body));
      });
    return {
      ...example,
      send,
      origin,
      ca,
      logs: () => logs,
      close,
      token: async (tenant = 'tenant-a', scope = 'customers.read') =>
        'Bearer ' +
        (await new SignJWT({ tenant_id: tenant, scope })
          .setProtectedHeader({ alg: 'ES256', kid: 'example', typ: 'JWT' })
          .setIssuer(issuer)
          .setAudience('api://graphql-example')
          .setSubject('guide-user')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(pair.privateKey)),
    };
  } catch (error) {
    await close();
    throw error;
  }
}
