// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:http';
import { createServer as portServer } from 'node:net';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createAuthService } from '@arkenivajs/security';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Plugin, VerifiedTenantContext } from '@arkenivajs/core';
import { mtlsPlugin } from '@arkenivajs/security-mtls';
import { loadSync } from '@grpc/proto-loader';
import type { Server, ServiceDefinition, ServerDuplexStream } from '@grpc/grpc-js';
import { grpcPlugin, GRPC_CAPABILITY } from '../dist/index.js';
import type { GrpcService, TrustedSecurityAuthority } from '../dist/index.js';
import { fixture as pkiFixture } from '../../security-mtls/dist-test/fixture.js';

async function freePort(): Promise<number> {
  const server = portServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('The loopback port is missing');
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
}
/** Real local JWT signatures, HTTP JWKS, TLS certificates and native protobuf connections. */
export async function fixture(
  observers: {
    plugins?: readonly Plugin[];
    mode?: 'standard' | 'detailed';
    imperative?: boolean;
  } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-runtime-')),
    descriptorFile = join(directory, 'echo.proto'),
    pki = await pkiFixture(),
    keys = await generateKeyPair('ES256'),
    publicKey = {
      ...(await exportJWK(keys.publicKey)),
      kid: 'rpc-public',
      alg: 'ES256',
      use: 'sig',
    };
  await writeFile(
    descriptorFile,
    await readFile(fileURLToPath(new URL('../test/fixtures/echo.proto', import.meta.url))),
    { mode: 0o600 },
  );
  const issuer = createServer((_request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ keys: [publicKey] }));
  });
  await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
  const address = issuer.address();
  if (!address || typeof address === 'string') throw new Error('The JWKS listener is missing');
  const origin = 'http://127.0.0.1:' + address.port,
    auth = await createAuthService({
      issuer: origin,
      audience: 'grpc-fixture',
      algorithms: ['ES256'],
      jwksUrl: origin + '/keys',
      environment: 'test',
      allowInsecureLoopback: true,
    }),
    port = await freePort();
  let calls = 0,
    cancelled = 0,
    denied = false;
  let substitution: 'none' | 'issuer' | 'tenant' = 'none';
  let heldResolve!: () => void, cancellationResolve!: () => void;
  const held = new Promise<void>((resolve) => {
      heldResolve = resolve;
    }),
    cancellation = new Promise<void>((resolve) => {
      cancellationResolve = resolve;
    });
  const tenants: VerifiedTenantContext[] = [];
  let unblock!: () => void, blockedResolve!: () => void, completedResolve!: () => void;
  let blockedCount = 0,
    completedCount = 0;
  const blocked = new Promise<void>((resolve) => {
      blockedResolve = resolve;
    }),
    completion = new Promise<void>((resolve) => {
      completedResolve = resolve;
    }),
    blockedWork = new Promise<void>((resolve) => {
      unblock = resolve;
    });
  const authority: TrustedSecurityAuthority = {
    async require(_action, subject, context) {
      if (
        denied ||
        !subject ||
        !context.tenant ||
        !auth.isVerifiedTenant(context.tenant) ||
        subject.issuer !== context.tenant.identity.issuer ||
        subject.subject !== context.tenant.identity.subject ||
        subject.tenant?.tenantId !== context.tenant.tenantId ||
        subject.tenant?.tenantId !== 'tenant-A'
      )
        throw new Error('The trusted RPC policy rejected the operation');
      tenants.push(context.tenant);
      if (substitution === 'issuer') return { ...subject, issuer: 'https://foreign.example' };
      if (substitution === 'tenant') return { ...subject, tenant: { ...context.tenant } };
      return subject;
    },
  };
  const authPlugin: Plugin = {
    id: 'security',
    version: '0.1.0',
    capabilities: new Set(['auth']),
    init(context) {
      context.provide(COMPONENTS.auth, auth);
    },
    async close() {
      await auth.close();
    },
  };
  const definition = loadSync(descriptorFile, { longs: String, bytes: Buffer, keepCase: true })[
    'fixture.Echo'
  ] as ServiceDefinition;
  const nativePlugin: Plugin = {
    id: 'grpc-native-fixture',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: ['grpc'],
    init(context) {
      const service = context.require<GrpcService>(GRPC_CAPABILITY),
        server = service.nativeServer() as Server;
      if (observers.imperative) {
        const binding = serverSettings.handlers.echo!;
        service.registerService(binding.descriptor, binding.handlers, binding.policy);
      }
      server.addService(
        { Exchange: definition.Exchange! },
        {
          Exchange(call: ServerDuplexStream<unknown, unknown>) {
            call.on('data', (value) => {
              calls++;
              call.write(value);
            });
            call.on('end', () => call.end());
            call.on('error', () => undefined);
          },
        },
      );
    },
    close() {},
  };
  const application = async (options: Parameters<typeof createApplication>[0]) => {
    try {
      return await createApplication(options);
    } catch (error) {
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
      await auth.close();
      await pki.close();
      await rm(directory, { recursive: true, force: true });
      throw error;
    }
  };
  const serverSettings: import('../dist/index.js').GrpcPluginSettings = {
    services: [
      {
        name: 'Echo',
        descriptorFile,
        allowedMethods: ['Bounce', 'Watch', 'Exchange'],
        listener: { host: '127.0.0.1', port, tlsProfile: 'server' },
        maxMessageBytes: 4096,
      },
    ],
    tlsProfiles: { server: pki.profiles.server! },
    authority,
    policy: { maxConcurrent: 4, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 4096 },
    handlers: {
      echo: {
        descriptor: 'Echo',
        policy: {
          requireAuthentication: true,
          methodAllowlist: ['Bounce', 'Watch', 'Exchange'],
          concurrencyLimit: 2,
          maxInboundBytes: 4096,
          maxOutboundBytes: 4096,
        },
        handlers: {
          async Bounce(request, context) {
            calls++;
            if ((request as { value?: string }).value === 'blocked') {
              if (++blockedCount === 2) blockedResolve();
              await blockedWork;
              if (++completedCount === 2) completedResolve();
            }
            if ((request as { value?: string }).value === 'hold') {
              heldResolve();
              await new Promise<void>((resolve) => {
                const abort = () => {
                  cancelled++;
                  cancellationResolve();
                  resolve();
                };
                context.signal.addEventListener('abort', abort, { once: true });
                if (context.signal.aborted) abort();
              });
            }
            return request;
          },
          async Watch(request, context) {
            calls++;
            return (async function* () {
              for (let index = 0; index < 3; index++) {
                if (context.signal.aborted) return;
                yield { ...(request as object), sequence: String(index) };
              }
            })();
          },
        },
      },
    },
  };
  const server = await application({
    service: { name: 'grpc-server', version: '1.0.0', environment: 'test' },
    ...(observers.plugins?.some((plugin) => plugin.capabilities.has('logger'))
      ? { logging: { level: 'debug' as const } }
      : {}),
    ...(observers.plugins?.some((plugin) => plugin.capabilities.has('telemetry'))
      ? { telemetry: { mode: observers.mode ?? 'standard', samplingRatio: 1 } }
      : {}),
    plugins: [
      ...(observers.plugins ?? []),
      authPlugin,
      mtlsPlugin(pki.settings),
      grpcPlugin({
        ...serverSettings,
        handlers: observers.imperative ? {} : serverSettings.handlers,
      }),
      nativePlugin,
    ],
  });
  const client = await application({
    service: { name: 'grpc-client', version: '1.0.0', environment: 'test' },
    ...(observers.plugins?.some((plugin) => plugin.capabilities.has('logger'))
      ? { logging: { level: 'debug' as const } }
      : {}),
    ...(observers.plugins?.some((plugin) => plugin.capabilities.has('telemetry'))
      ? { telemetry: { mode: observers.mode ?? 'standard', samplingRatio: 1 } }
      : {}),
    plugins: [
      ...(observers.plugins ?? []),
      mtlsPlugin(pki.settings),
      grpcPlugin({
        services: [
          {
            name: 'Echo',
            descriptorFile,
            endpoint: 'localhost:' + port,
            allowedMethods: ['Bounce', 'Watch', 'Exchange'],
            maxMessageBytes: 4096,
          },
        ],
        tlsProfiles: { client: pki.profiles.client! },
        authority,
        handlers: {},
        policy: { maxConcurrent: 4, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 4096 },
      }),
    ],
  });
  try {
    await server.start();
    await client.start();
  } catch (error) {
    await Promise.allSettled([client.stop(), server.stop()]);
    issuer.closeAllConnections();
    await new Promise<void>((resolve) => issuer.close(() => resolve()));
    await pki.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
  return {
    server,
    client,
    endpoint: 'https://localhost:' + port,
    pki,
    definition,
    auth,
    service: client.resolve<GrpcService>(GRPC_CAPABILITY),
    serverService: server.resolve<GrpcService>(GRPC_CAPABILITY),
    calls: () => calls,
    held: () => held,
    blocked: () => blocked,
    unblock: () => unblock(),
    unblocked: () => completion,
    cancellation: () => cancellation,
    cancelled: () => cancelled,
    tenants: () => [...tenants],
    deny(value: boolean) {
      denied = value;
    },
    substitute(value: typeof substitution) {
      substitution = value;
    },
    async bearer(tenant = 'tenant-A') {
      return (
        'Bearer ' +
        (await new SignJWT({ tenant_id: tenant })
          .setProtectedHeader({ alg: 'ES256', kid: 'rpc-public', typ: 'JWT' })
          .setSubject('rpc-service')
          .setIssuer(origin)
          .setAudience('grpc-fixture')
          .setExpirationTime('2m')
          .sign(keys.privateKey))
      );
    },
    async close() {
      unblock();
      await Promise.allSettled([client.stop(), server.stop()]);
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
      await pki.close();
      await rm(directory, { recursive: true, force: true });
    },
  };
}
