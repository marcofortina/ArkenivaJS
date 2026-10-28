// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, request } from 'node:http';
import { createServer as secureServer, request as secureRequest } from 'node:https';
import type { RequestListener } from 'node:http';
import type { ServerOptions } from 'node:https';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication } from '@arkenivajs/core';
import type { ServerTlsFiles, Plugin } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { proxyPlugin, PROXY_CAPABILITY } from '../dist/index.js';
import type { ProxyRouteConfig, ProxyService, SecretRefResolver } from '../dist/index.js';

export async function fixture(
  change: Partial<ProxyRouteConfig> = {},
  handler?: RequestListener,
  transport: {
    upstreamTls?: ServerOptions;
    plugins?: readonly Plugin[];
    inboundTls?: ServerTlsFiles;
    resolveSecret?: SecretRefResolver;
    telemetry?: { mode: 'standard' | 'detailed'; endpoint: string };
  } = {},
) {
  const received: {
    url: string;
    headers: import('node:http').IncomingHttpHeaders;
    bytes: number;
  }[] = [];
  const listener =
    handler ??
    ((request, response) => {
      const entry = { url: request.url ?? '', headers: request.headers, bytes: 0 };
      received.push(entry);
      request.on('data', (chunk: Buffer) => {
        entry.bytes += chunk.length;
      });
      request.on('end', () => {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify(entry));
      });
    });
  const upstream = transport.upstreamTls
    ? secureServer(transport.upstreamTls, listener)
    : createServer(listener);
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamAddress = upstream.address();
  if (!upstreamAddress || typeof upstreamAddress !== 'object')
    throw new Error('The upstream fixture is unavailable');
  const pair = await generateKeyPair('ES256'),
    jwk = { ...(await exportJWK(pair.publicKey)), kid: 'proxy-fixture', alg: 'ES256', use: 'sig' };
  let authority = '';
  const issuer = createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        request.url === '/keys'
          ? { keys: [jwk] }
          : { issuer: authority, jwks_uri: authority + '/keys' },
      ),
    );
  });
  await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
  const issuerAddress = issuer.address();
  if (!issuerAddress || typeof issuerAddress !== 'object')
    throw new Error('The issuer fixture is unavailable');
  authority = 'http://127.0.0.1:' + issuerAddress.port;
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const reserved = reserve.address();
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  if (!reserved || typeof reserved !== 'object')
    throw new Error('The proxy fixture port is unavailable');
  let logs = '';
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs += chunk.toString('utf8');
      done();
    },
  });
  const route: ProxyRouteConfig = {
    routeId: 'orders',
    prefix: '/orders',
    upstreamOrigin:
      (transport.upstreamTls ? 'https:' : 'http:') + '//127.0.0.1:' + upstreamAddress.port,
    rewritePrefix: '/api/orders',
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
    auth: { required: true, scopes: ['orders:read'] },
    destinationPolicy: {
      kind: 'private-allowlisted',
      allowedHosts: ['127.0.0.1'],
      allowedCidrs: ['127.0.0.1/32'],
    },
    maxRequestBytes: 1048576,
    maxResponseBytes: 1048576,
    timeoutMs: 1000,
    ...change,
  };
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  const close = async () => {
    try {
      await app?.stop();
    } finally {
      sink.destroy();
      await Promise.all(
        [upstream, issuer].map((server) => {
          server.closeAllConnections();
          return new Promise<void>((resolve) => server.close(() => resolve()));
        }),
      );
    }
  };
  try {
    app = await createApplication({
      service: { name: 'proxy-fixture', version: '1.0.0', environment: 'test' },
      http: {
        host: '127.0.0.1',
        port: reserved.port,
        ...(transport.inboundTls ? { protocol: 'https' as const, tls: transport.inboundTls } : {}),
      },
      security: { issuer: authority, audience: 'api://proxy', algorithms: ['ES256'] },
      logging: { level: 'debug' },
      ...(transport.telemetry
        ? { telemetry: { mode: transport.telemetry.mode, samplingRatio: 1 } }
        : {}),
      plugins: [
        loggingPlugin({ destination: sink }),
        ...(transport.plugins ?? []),
        ...(transport.telemetry
          ? [
              telemetryPlugin({
                endpoint: transport.telemetry.endpoint,
                allowInsecureLoopback: true,
                exportIntervalMs: 60000,
                exportTimeoutMs: 1000,
                labelValues: { route: [route.prefix + '/*'], 'peer.service': [route.routeId] },
              }),
            ]
          : []),
        securityPlugin({ allowInsecureLoopback: true }),
        apiPlugin({ dependencies: ['security', ...(transport.telemetry ? ['telemetry'] : [])] }),
        proxyPlugin({
          routes: [route],
          ...(transport.resolveSecret ? { resolveSecret: transport.resolveSecret } : {}),
        }),
      ],
    });
    await app.start();
    return {
      app,
      route,
      origin: (app.api as ManagedApiServer).address()!,
      upstream,
      received,
      logs: () => logs,
      service: app.resolve<ProxyService>(PROXY_CAPABILITY),
      close,
      async token(scope = 'orders:read', tenant = 'tenant-a') {
        return (
          'Bearer ' +
          (await new SignJWT({ scope, tenant_id: tenant })
            .setProtectedHeader({ alg: 'ES256', kid: 'proxy-fixture', typ: 'JWT' })
            .setIssuer(authority)
            .setSubject('proxy-test-account')
            .setAudience('api://proxy')
            .setExpirationTime('2m')
            .sign(pair.privateKey))
        );
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
export function send(
  origin: string,
  path: string,
  method = 'GET',
  headers: Record<string, string> = {},
  chunks: readonly Buffer[] = [],
  ca?: Buffer,
): Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const outgoing = (origin.startsWith('https:') ? secureRequest : request)(
      origin,
      { path, method, headers, ...(ca ? { ca, rejectUnauthorized: true } : {}) },
      (response) => {
        const data: Buffer[] = [];
        response.on('data', (chunk) => data.push(Buffer.from(chunk)));
        response.once('error', reject);
        response.once('end', () =>
          resolve({
            status: response.statusCode!,
            headers: response.headers,
            body: Buffer.concat(data).toString('utf8'),
          }),
        );
      },
    );
    outgoing.once('error', reject);
    for (const chunk of chunks) outgoing.write(chunk);
    outgoing.end();
  });
}
