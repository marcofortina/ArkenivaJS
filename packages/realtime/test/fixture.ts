// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, get } from 'node:http';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication } from '@arkenivajs/core';
import type { ServerTlsFiles, Plugin, ApplicationOptions } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import { apiPlugin } from '@arkenivajs/api';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import type { ManagedApiServer } from '@arkenivajs/api';
import { realtimePlugin, REALTIME_CAPABILITY, SseCursorError } from '../dist/index.js';
import type {
  RealtimeService,
  RealtimePluginSettings,
  RealtimePolicy,
  SseSource,
} from '../dist/index.js';

export const policy: RealtimePolicy = {
  requireAuth: true,
  maxConnectionsPerTenant: 2,
  maxMessageBytes: 32768,
  maxBufferBytes: 65536,
  heartbeatMs: 100,
  idleTimeoutMs: 5000,
};
export async function fixture(
  change: Partial<RealtimePluginSettings> = {},
  transport?: { tls: ServerTlsFiles; http2?: boolean },
  extraPlugins: readonly Plugin[] = [],
  configuration: {
    issuer?: string;
    databases?: ApplicationOptions['databases'];
    environment?: ApplicationOptions['service']['environment'];
    telemetry?: { mode: 'standard' | 'detailed'; endpoint: string };
  } = {},
) {
  const pair = await generateKeyPair('ES256'),
    jwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'realtime-fixture',
      alg: 'ES256',
      use: 'sig',
    };
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
  const address = issuer.address();
  if (!address || typeof address !== 'object')
    throw new Error('The realtime issuer is unavailable');
  authority = 'http://127.0.0.1:' + address.port;
  const reservation = createServer();
  await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
  const reserved = reservation.address();
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  if (!reserved || typeof reserved !== 'object')
    throw new Error('The realtime fixture port is unavailable');
  let logs = '';
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs += chunk.toString('utf8');
      done();
    },
  });
  const events: SseSource & { usage: 'test-only' } = {
    kind: 'durable',
    usage: 'test-only',
    async validateCursor(context) {
      const value = context.lastEventId;
      if (value === undefined) return;
      if (!value.startsWith(context.tenant.tenantId + '_')) throw new SseCursorError('invalid');
      if (value.endsWith('_expired')) throw new SseCursorError('expired');
      if (![context.tenant.tenantId + '_1', context.tenant.tenantId + '_2'].includes(value))
        throw new SseCursorError('invalid');
    },
    async *subscribe(context) {
      for (let index = 1; index <= 2; index++) {
        if (context.signal.aborted) return;
        const id = context.tenant.tenantId + '_' + index;
        if (context.lastEventId && id <= context.lastEventId) continue;
        yield { id, type: 'update', data: 'event ' + index };
      }
    },
  };
  const settings: RealtimePluginSettings = {
    routes: [
      { kind: 'websocket', path: '/socket', policyKey: 'standard', handlerKey: 'echo' },
      { kind: 'sse', path: '/events', policyKey: 'standard', sourceKey: 'events' },
    ],
    policies: { standard: policy },
    sseSources: { events },
    websocketHandlers: {
      async echo(session) {
        for await (const message of session.receive()) await session.send(message);
      },
    },
    policy: { maxConcurrent: 8, timeoutMs: 1000 },
    ...change,
  };
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  const close = async () => {
    try {
      await app?.stop();
    } finally {
      sink.destroy();
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
    }
  };
  try {
    app = await createApplication({
      service: {
        name: 'realtime-fixture',
        version: '1.0.0',
        environment: configuration.environment ?? 'test',
      },
      ...(configuration.databases ? { databases: configuration.databases } : {}),
      logging: { level: 'debug' },
      ...(configuration.telemetry
        ? { telemetry: { mode: configuration.telemetry.mode, samplingRatio: 1 } }
        : {}),
      http: {
        host: '127.0.0.1',
        port: reserved.port,
        ...(transport ? { protocol: 'https' as const, ...transport } : {}),
      },
      security: {
        issuer: configuration.issuer ?? authority,
        audience: 'api://realtime',
        algorithms: ['ES256'],
      },
      plugins: [
        loggingPlugin({ destination: sink }),
        ...(configuration.telemetry
          ? [
              telemetryPlugin({
                endpoint: configuration.telemetry.endpoint,
                allowInsecureLoopback: true,
                exportIntervalMs: 60000,
                exportTimeoutMs: 1000,
              }),
            ]
          : []),
        securityPlugin({ allowInsecureLoopback: true }),
        apiPlugin({
          dependencies: ['security', ...(configuration.telemetry ? ['telemetry'] : [])],
        }),
        ...extraPlugins,
        realtimePlugin(settings),
      ],
    });
    await app.start();
    return {
      app,
      issuer: authority,
      origin: (app.api as ManagedApiServer).address()!,
      service: app.resolve<RealtimeService>(REALTIME_CAPABILITY),
      logs: () => logs,
      close,
      async token(tenant = 'tenant-a', expires = '2m') {
        return (
          'Bearer ' +
          (await new SignJWT({ tenant_id: tenant })
            .setProtectedHeader({ alg: 'ES256', kid: 'realtime-fixture', typ: 'JWT' })
            .setIssuer(authority)
            .setAudience('api://realtime')
            .setSubject('realtime-test-account')
            .setExpirationTime(expires)
            .sign(pair.privateKey))
        );
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
export function sseRequest(
  origin: string,
  headers: Record<string, string> = {},
  path = '/events',
): Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const request = get(
      origin + path,
      { headers: { accept: 'text/event-stream', ...headers } },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        response.once('error', reject);
        response.once('end', () =>
          resolve({
            status: response.statusCode!,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    request.once('error', reject);
  });
}
