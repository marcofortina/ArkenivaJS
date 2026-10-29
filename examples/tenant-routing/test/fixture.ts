// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { request } from 'node:https';
import { fork, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import type { TestContext } from 'node:test';
import type {
  ApprovedUpstream,
  TenantRegistrySnapshotV1_1,
  TenantRoutingEventV1,
} from '@arkenivajs/tenant-routing';
import type { TenantRoutingExampleOptions } from '../dist/main.js';

/** Every listener, child, key and deployment file belongs to this disposable test. */
export async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-routing-guide-'));
  await chmod(directory, 0o700);
  const privateKeyFile = join(directory, 'server.key'),
    certificateFile = join(directory, 'server.pem'),
    registryFile = join(directory, 'registry.json');
  const children = new Set<() => Promise<void>>(),
    servers: ReturnType<typeof createServer>[] = [];
  t.after(async () => {
    try {
      await Promise.all([...children].map((close) => close()));
    } finally {
      for (const server of servers) {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
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
  const ca = await readFile(certificateFile),
    pair = await generateKeyPair('ES256'),
    jwk = { ...(await exportJWK(pair.publicKey)), kid: 'routing-guide', alg: 'ES256' };
  let issuer = '';
  const authority = createServer((incoming, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(
      JSON.stringify(
        incoming.url === '/keys' ? { keys: [jwk] } : { issuer, jwks_uri: issuer + '/keys' },
      ),
    );
  });
  servers.push(authority);
  await new Promise<void>((resolve) => authority.listen(0, '127.0.0.1', resolve));
  const authAddress = authority.address();
  assert.ok(authAddress && typeof authAddress === 'object');
  issuer = 'http://127.0.0.1:' + authAddress.port;
  const calls = { one: 0, two: 0 },
    approvedUpstreams: ApprovedUpstream[] = [];
  for (const name of ['one', 'two'] as const) {
    const partner = createServer(async (incoming, response) => {
      assert.equal(incoming.url, '/quote');
      assert.equal(incoming.method, 'POST');
      assert.equal(incoming.headers.authorization, undefined);
      assert.equal(incoming.headers.cookie, undefined);
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of incoming) {
        bytes += chunk.length;
        if (bytes > 8192) {
          response.writeHead(413).end();
          return;
        }
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString()) as { subtotal: number };
      assert.equal(typeof body.subtotal, 'number');
      calls[name]++;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ reference: 'partner-' + name, netAmount: body.subtotal }));
    });
    servers.push(partner);
    await new Promise<void>((resolve) => partner.listen(0, '127.0.0.1', resolve));
    const address = partner.address();
    assert.ok(address && typeof address === 'object');
    approvedUpstreams.push({
      key: 'partner-' + name,
      origin: 'http://127.0.0.1:' + address.port,
      allowedHostnames: ['127.0.0.1'],
      allowedCidrs: ['127.0.0.1/32'],
      connectionTimeoutMs: 1000,
      allowRedirects: false,
    });
  }
  const configuration: TenantRoutingExampleOptions = {
    service: { name: 'tenant-quote-example', version: '1.0.0', environment: 'test' },
    http: {
      protocol: 'https',
      host: '127.0.0.1',
      port: 0,
      tls: { privateKeyFile, certificateFile },
    },
    issuer,
    audience: 'api://tenant-quote-example',
    allowInsecureLoopback: true,
    registryFile,
    approvedUpstreams,
  };
  const start = async (patch: Partial<TenantRoutingExampleOptions> = {}) => {
    const child = fork(fileURLToPath(new URL('./child.js', import.meta.url)), [], {
      execArgv: [],
      env: { ...process.env, ARKENIVA_TENANT_EXAMPLE_DISPOSABLE: '1' },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    let output = '',
      done = false,
      readySeen = false;
    for (const stream of [child.stdout, child.stderr])
      stream!.on('data', (chunk: Buffer) => {
        output = (output + chunk.toString()).slice(-65536);
      });
    const ended = new Promise<number | null>((resolve) => child.once('exit', resolve));
    const close = async () => {
      if (done) return;
      done = true;
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const exit = await Promise.race([
          ended,
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
              child.kill('SIGKILL');
              reject(new Error('Example child cleanup deadline exceeded'));
            }, 10000);
          }),
        ]);
        if (readySeen) assert.equal(exit, 0, 'An admitted example process must close successfully');
      } finally {
        if (timer) clearTimeout(timer);
        children.delete(close);
      }
    };
    children.add(close);
    const events: TenantRoutingEventV1[] = [];
    const ready = new Promise<{ origin: string; revision: string }>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('Example child startup deadline exceeded')),
        10000,
      );
      const onExit = () => {
        clearTimeout(timer);
        reject(new Error('Example child exited before readiness'));
      };
      child.once('exit', onExit);
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on(
        'message',
        (message: {
          type?: string;
          origin?: string;
          revision?: string;
          events?: TenantRoutingEventV1[];
          codes?: string[];
        }) => {
          if (message.type === 'events') events.push(...(message.events ?? []));
          if (message.type === 'failed') {
            clearTimeout(timer);
            reject(new Error('Example child startup failed: ' + (message.codes ?? []).join(',')));
          }
          if (
            message.type === 'ready' &&
            typeof message.origin === 'string' &&
            typeof message.revision === 'string'
          ) {
            readySeen = true;
            clearTimeout(timer);
            child.off('exit', onExit);
            resolve({ origin: message.origin, revision: message.revision });
          }
        },
      );
      child.send({ ...configuration, ...patch }, (error) => {
        if (error) {
          clearTimeout(timer);
          reject(error);
        }
      });
    });
    try {
      return { ...(await ready), events, close, logs: () => output };
    } catch (error) {
      await close();
      throw error;
    }
  };
  const send = (
    origin: string,
    path: string,
    options: {
      authorization?: string;
      body?: unknown;
      headers?: Record<string, string>;
      trust?: boolean;
    } = {},
  ) =>
    new Promise<{
      status: number;
      body: string;
      headers: import('node:http').IncomingHttpHeaders;
      json(): Record<string, unknown>;
    }>((resolve, reject) => {
      const outgoing = request(
        origin + path,
        {
          method: options.body === undefined ? 'GET' : 'POST',
          ...(options.trust === false ? {} : { ca }),
          headers: {
            'content-type': 'application/json',
            ...(options.authorization ? { authorization: options.authorization } : {}),
            ...options.headers,
          },
        },
        (incoming) => {
          const chunks: Buffer[] = [];
          incoming.on('data', (chunk: Buffer) => chunks.push(chunk));
          incoming.once('error', reject);
          incoming.once('end', () => {
            const body = Buffer.concat(chunks).toString();
            resolve({
              status: incoming.statusCode ?? 0,
              body,
              headers: incoming.headers,
              json: () => JSON.parse(body) as Record<string, unknown>,
            });
          });
        },
      );
      outgoing.once('error', reject);
      outgoing.end(options.body === undefined ? undefined : JSON.stringify(options.body));
    });
  return {
    registryFile,
    catalog: Object.freeze([...approvedUpstreams]),
    calls,
    start,
    send,
    write: (snapshot: TenantRegistrySnapshotV1_1) =>
      writeFile(registryFile, JSON.stringify(snapshot), { mode: 0o600 }),
    validate: () =>
      promisify(execFile)(
        'pnpm',
        [
          'exec',
          'arkenivajs-tenant-registry',
          'validate',
          '--file',
          registryFile,
          '--environment',
          'test',
        ],
        { cwd: fileURLToPath(new URL('../', import.meta.url)), timeout: 10000, maxBuffer: 16384 },
      ),
    token: async (tenant = 'tenant-a', scope = 'quotes:write orders:read') =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: tenant, scope })
        .setProtectedHeader({ alg: 'ES256', kid: 'routing-guide', typ: 'JWT' })
        .setIssuer(issuer)
        .setAudience(configuration.audience)
        .setSubject('synthetic-guide-user')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(pair.privateKey)),
  };
}
