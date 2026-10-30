// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type {
  Plugin,
  VerifiedTenantContext,
  ApplicationOptions,
  Application,
  ServerTlsFiles,
} from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { tenantRoutingPlugin, TENANT_ROUTING_CAPABILITY } from '../dist/index.js';
import type {
  TenantRegistrySnapshotV1_1,
  TenantRoutingPluginSettings,
  TenantRoutingService,
} from '../dist/index.js';
import { registryContentChecksum } from '../dist/registry.js';

export function registry() {
  const response = {
    type: 'object',
    properties: {
      tenant: { type: 'string' },
      implementation: { type: 'string' },
      id: { type: 'string' },
    },
    required: ['tenant', 'implementation', 'id'],
    additionalProperties: false,
  };
  const read = {
    id: 'orders.read',
    method: 'GET' as const,
    path: '/api/orders/:id',
    label: 'Read an order',
    schemas: {
      params: {
        type: 'object',
        properties: { id: { type: 'string', minLength: 1 } },
        required: ['id'],
        additionalProperties: false,
      },
      response,
    },
    policy: { requiredScopes: ['orders:read'] },
    maxConcurrency: 2,
    maxBodyBytes: 4096,
    maxResponseBytes: 4096,
    timeoutMs: 2000,
  };
  const write = {
    ...read,
    id: 'orders.create',
    method: 'POST' as const,
    path: '/api/orders',
    label: 'Create an order',
    schemas: {
      body: {
        type: 'object',
        properties: { id: { type: 'string' }, tenant_id: { type: 'string' } },
        required: ['id'],
        additionalProperties: false,
      },
      response,
    },
    policy: { requiredScopes: ['orders:write'] },
  };
  const snapshot = {
    schemaVersion: '1.1.0' as const,
    revision: 'stable-blue',
    activationGeneration: 1,
    contentChecksum: '',
    activatedAt: '2026-01-01T00:00:00.000Z',
    operations: [read, write],
    implementations: [
      { id: 'north-orders', kind: 'handler' as const, handlerKey: 'north' },
      { id: 'south-orders', kind: 'handler' as const, handlerKey: 'south' },
    ],
    bindings: ['north', 'south'].flatMap((tenantId) =>
      [read, write].map((operation) => ({
        tenantId,
        operationId: operation.id,
        implementationId: tenantId + '-orders',
        enabled: true,
      })),
    ),
  };
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  return snapshot;
}
export function settings(
  snapshot: TenantRegistrySnapshotV1_1 = registry(),
): TenantRoutingPluginSettings {
  const handler =
    (implementation: string): TenantRoutingPluginSettings['handlers'][string] =>
    (context) => ({
      tenant: context.auth!.tenantId,
      implementation,
      id: context.params.id ?? (context.body as { id: string } | undefined)?.id ?? 'none',
    });
  return {
    registry: { loadSnapshot: async () => snapshot },
    handlers: { north: handler('north'), south: handler('south') },
    authorize: () => true,
    activation: 'startup',
  };
}
export async function fixture(
  input: TenantRoutingPluginSettings = settings(),
  options: {
    authenticated?: boolean;
    plugins?: readonly Plugin[];
    assuranceResolver?: NonNullable<ApplicationOptions['security']>['assuranceResolver'];
    authorizeTenant?: NonNullable<Parameters<typeof securityPlugin>[0]>['authorizeTenant'];
    databases?: ApplicationOptions['databases'];
    onCreated?: (app: Application) => void;
    tls?: ServerTlsFiles;
    http2?: boolean;
    telemetry?: ApplicationOptions['telemetry'];
    metering?: ApplicationOptions['metering'];
  } = {},
) {
  const pair = await generateKeyPair('ES256'),
    jwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: 'tenant-routing-test',
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
  if (!address || typeof address !== 'object') throw new Error('Authority address unavailable');
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
    const authenticated = options.authenticated !== false;
    app = await createApplication({
      service: { name: 'tenant-routing-test', version: '1.0.0', environment: 'test' },
      http: {
        host: '127.0.0.1',
        port: 0,
        ...(options.tls ? { protocol: 'https' as const, tls: options.tls } : {}),
        ...(options.http2 === undefined ? {} : { http2: options.http2 }),
      },
      logging: { level: 'debug' },
      ...(options.telemetry ? { telemetry: options.telemetry } : {}),
      ...(options.metering ? { metering: options.metering } : {}),
      ...(options.databases ? { databases: options.databases } : {}),
      ...(authenticated
        ? {
            security: {
              issuer,
              audience: 'api://tenant-routing',
              algorithms: ['ES256'],
              ...(options.assuranceResolver
                ? { assuranceResolver: options.assuranceResolver }
                : {}),
            },
          }
        : {}),
      plugins: [
        loggingPlugin({ destination: sink }),
        ...(authenticated
          ? [
              securityPlugin({
                allowInsecureLoopback: true,
                ...(options.authorizeTenant ? { authorizeTenant: options.authorizeTenant } : {}),
              }),
            ]
          : []),
        apiPlugin({
          dependencies: [
            ...(authenticated ? ['security'] : []),
            ...(options.plugins ?? [])
              .filter(
                (plugin) =>
                  plugin.capabilities.has('telemetry') ||
                  (options.metering?.enabled && plugin.capabilities.has('meter')),
              )
              .map((plugin) => plugin.id),
          ],
        }),
        ...(options.plugins ?? []),
        tenantRoutingPlugin(input),
      ],
    });
    options.onCreated?.(app);
    await app.start();
    const api = app.resolve<ManagedApiServer>(COMPONENTS.api),
      service = app.resolve<TenantRoutingService>(TENANT_ROUTING_CAPABILITY),
      origin = api.address();
    if (!origin) throw new Error('Tenant routing listener is unavailable');
    const token = async (
      tenant = 'north',
      scopes = 'orders:read orders:write',
      claims: Record<string, unknown> = {},
    ) =>
      'Bearer ' +
      (await new SignJWT({ ...claims, tenant_id: tenant, scope: scopes })
        .setProtectedHeader({ alg: 'ES256', kid: 'tenant-routing-test', typ: 'JWT' })
        .setIssuer(issuer)
        .setAudience('api://tenant-routing')
        .setSubject('synthetic-operator')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(pair.privateKey));
    return {
      app,
      api,
      service,
      origin,
      token,
      logs: () => logs,
      close,
      async tenant(
        tenant = 'north',
        scopes = 'orders:read orders:write',
      ): Promise<VerifiedTenantContext> {
        const identity = await app!.auth!.verifyBearer(await token(tenant, scopes));
        return app!.auth!.tenantFrom(identity);
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
  options: {
    method?: string;
    body?: unknown;
    raw?: Buffer | string;
    headers?: Record<string, string>;
    ca?: Buffer;
  } = {},
) {
  return new Promise<{
    status: number;
    body: string;
    headers: import('node:http').IncomingHttpHeaders;
    json(): Record<string, unknown>;
  }>((resolve, reject) => {
    const request = (origin.startsWith('https:') ? httpsRequest : httpRequest)(
      origin + path,
      {
        method: options.method ?? 'GET',
        headers: { 'content-type': 'application/json', ...options.headers },
        ...(options.ca ? { ca: options.ca } : {}),
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.once('error', reject);
        response.once('end', () => {
          const body = Buffer.concat(chunks).toString();
          resolve({
            status: response.statusCode ?? 0,
            body,
            headers: response.headers,
            json: () => JSON.parse(body) as Record<string, unknown>,
          });
        });
      },
    );
    request.once('error', reject);
    request.end(
      options.raw ?? (options.body === undefined ? undefined : JSON.stringify(options.body)),
    );
  });
}

/** Ephemeral local TLS material never enters source files or external services. */
export async function tlsFiles() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-tenant-tls-'));
  const privateKeyFile = join(directory, 'key.pem'),
    certificateFile = join(directory, 'certificate.pem');
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
