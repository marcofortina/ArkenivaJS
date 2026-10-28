// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, request } from 'node:https';
import { createServer as portServer } from 'node:net';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { proxyPlugin, PROXY_CAPABILITY } from '@arkenivajs/proxy';
import type { ProxyService } from '@arkenivajs/proxy';

/** Fully owned test-only HTTPS listeners; no external service or persistent configuration is changed. */
export async function runProxyExample() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-proxy-example-'));
  await chmod(directory, 0o700);
  const certificateFile = join(directory, 'server.pem'),
    privateKeyFile = join(directory, 'server.key');
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  let upstream: ReturnType<typeof createServer> | undefined;
  const privateMarker = randomBytes(32).toString('base64url');
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
        privateKeyFile,
        '-out',
        certificateFile,
      ],
      { timeout: 10000 },
    );
    await chmod(privateKeyFile, 0o600);
    await chmod(certificateFile, 0o400);
    const ca = await readFile(certificateFile);
    upstream = createServer(
      { key: await readFile(privateKeyFile), cert: ca },
      (request, response) => {
        let bytes = 0;
        request.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
        });
        request.on('end', () => {
          response.setHeader('content-type', 'application/json');
          response.end(
            JSON.stringify({
              rewritten: request.url === '/api/orders/42?state=ready',
              identityHeadersStripped: [
                'authorization',
                'cookie',
                'x-tenant-id',
                'x-forwarded-user',
                'baggage',
              ].every((key) => request.headers[key] === undefined),
              bytes,
            }),
          );
        });
      },
    );
    await new Promise<void>((resolve) => upstream!.listen(0, '127.0.0.1', resolve));
    const upstreamAddress = upstream.address();
    if (!upstreamAddress || typeof upstreamAddress !== 'object')
      throw new Error('The owned HTTPS upstream is unavailable');
    const reservation = portServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    if (!reserved || typeof reserved !== 'object')
      throw new Error('The owned HTTPS proxy port is unavailable');
    app = await createApplication({
      service: { name: 'fixed-proxy-example', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      http: {
        protocol: 'https',
        host: '127.0.0.1',
        port: reserved.port,
        tls: { certificateFile, privateKeyFile },
      },
      plugins: [
        loggingPlugin(),
        apiPlugin(),
        proxyPlugin({
          routes: [
            {
              routeId: 'orders',
              prefix: '/orders',
              upstreamOrigin: 'https://127.0.0.1:' + upstreamAddress.port,
              rewritePrefix: '/api/orders',
              methods: ['GET', 'POST'],
              auth: {
                required: false,
                reason:
                  'The owned tutorial accepts only ephemeral synthetic bytes and no protected account data',
              },
              destinationPolicy: {
                kind: 'private-allowlisted',
                allowedHosts: ['127.0.0.1'],
                allowedCidrs: ['127.0.0.1/32'],
              },
              upstreamCaFile: certificateFile,
              maxRequestBytes: 1048576,
              maxResponseBytes: 1048576,
              timeoutMs: 3000,
            },
          ],
        }),
      ],
    });
    await app.start();
    const origin = (app.api as ManagedApiServer).address()!;
    const exchange = (path: string, trusted = true) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const outgoing = request(
          origin,
          {
            path,
            method: 'POST',
            rejectUnauthorized: true,
            ...(trusted ? { ca } : {}),
            headers: {
              'content-type': 'application/octet-stream',
              authorization: 'Bearer ' + privateMarker,
              cookie: privateMarker,
              'x-tenant-id': privateMarker,
              'x-forwarded-user': privateMarker,
              baggage: privateMarker,
            },
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
            response.once('error', reject);
            response.once('end', () =>
              resolve({
                status: response.statusCode!,
                body: Buffer.concat(chunks).toString('utf8'),
              }),
            );
          },
        );
        outgoing.once('error', reject);
        outgoing.end(Buffer.alloc(65536, 42));
      });
    let untrustedCertificateRejected = false;
    try {
      await exchange('/orders/42?state=ready', false);
    } catch {
      untrustedCertificateRejected = true;
    }
    const result = await exchange('/orders/42?state=ready');
    if (result.status !== 200) throw new Error('The owned HTTPS proxy exchange failed');
    const echoed = JSON.parse(result.body) as {
      rewritten: boolean;
      identityHeadersStripped: boolean;
      bytes: number;
    };
    const denied = await exchange('/orders/%2e%2e/private');
    const proxy = app.resolve<ProxyService>(PROXY_CAPABILITY);
    return {
      untrustedCertificateRejected,
      ...echoed,
      unsafePathRejected: denied.status === 403,
      stats: proxy.stats(),
    };
  } finally {
    try {
      await app?.stop();
    } finally {
      if (upstream) {
        upstream.closeAllConnections();
        await new Promise<void>((resolve) => upstream!.close(() => resolve()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  }
}
