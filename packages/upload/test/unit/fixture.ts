// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, request } from 'node:http';
import { Writable } from 'node:stream';
import { once } from 'node:events';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createApplication } from '@arkenivajs/core';
import type { ServerTlsFiles } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { uploadPlugin, UPLOAD_CAPABILITY } from '../../dist/index.js';
import type { UploadRoute, UploadService, UploadPolicy } from '../../dist/index.js';

export const policy: UploadPolicy = Object.freeze({
  maxRequestBytes: 1000000,
  maxFileBytes: 100000,
  maxFiles: 2,
  maxFields: 4,
  maxFieldBytes: 1024,
  maxParts: 6,
  allowedMediaTypes: Object.freeze(['application/pdf', 'application/octet-stream']),
});
export const schema = {
  type: 'object',
  required: ['files', 'bytes', 'order'],
  properties: {
    files: { type: 'integer' },
    bytes: { type: 'integer' },
    order: { type: 'array', items: { type: 'string' } },
    tenant: { type: 'string' },
  },
  additionalProperties: false,
};
async function attemptFixture(
  input: Partial<UploadRoute> = {},
  timeoutMs = 5000,
  transport?: { tls: ServerTlsFiles; http2?: boolean },
  telemetryEndpoint?: string,
) {
  const pair = await generateKeyPair('ES256'),
    jwk = { ...(await exportJWK(pair.publicKey)), kid: 'upload-fixture', alg: 'ES256', use: 'sig' };
  const issuer = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify(
        req.url === '/keys'
          ? { keys: [jwk] }
          : { issuer: authority, jwks_uri: authority + '/keys' },
      ),
    );
  });
  await new Promise<void>((resolve) => issuer.listen(0, '127.0.0.1', resolve));
  const address = issuer.address();
  if (!address || typeof address !== 'object') throw new Error('Fixture issuer is unavailable');
  const authority = `http://127.0.0.1:${address.port}`;
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const reserved = reserve.address();
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  if (!reserved || typeof reserved !== 'object') throw new Error('Fixture port is unavailable');
  let logs = '',
    calls = 0;
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs += chunk.toString();
      done();
    },
  });
  const app = await createApplication({
    service: { name: 'upload-fixture', version: '1.0.0', environment: 'test' },
    http: {
      host: '127.0.0.1',
      port: reserved.port,
      requestTimeoutMs: timeoutMs,
      ...(transport ? { protocol: 'https' as const, ...transport } : {}),
    },
    security: { issuer: authority, audience: 'api://upload', algorithms: ['ES256'] },
    logging: { level: 'debug' },
    ...(telemetryEndpoint ? { telemetry: { mode: 'standard' as const, samplingRatio: 1 } } : {}),
    plugins: [
      loggingPlugin({ destination: sink }),
      ...(telemetryEndpoint
        ? [
            telemetryPlugin({
              endpoint: telemetryEndpoint,
              allowInsecureLoopback: true,
              exportIntervalMs: 60000,
            }),
          ]
        : []),
      securityPlugin({ allowInsecureLoopback: true }),
      apiPlugin({ dependencies: ['security', ...(telemetryEndpoint ? ['telemetry'] : [])] }),
      uploadPlugin({
        routes: [
          {
            path: '/uploads',
            method: 'POST',
            policy,
            auth: { required: true, scopes: ['documents:write'] },
            responseSchema: schema,
            ...input,
            async handler(request) {
              calls++;
              if (input.handler) return input.handler(request);
              let files = 0,
                bytes = 0;
              const order: string[] = [];
              for await (const part of request.parts) {
                order.push(part.kind + ':' + part.fieldName);
                if (part.kind === 'file') {
                  files++;
                  for await (const chunk of part.stream) bytes += chunk.byteLength;
                }
              }
              return { files, bytes, order, tenant: request.context.auth!.tenantId };
            },
          },
        ],
      }),
    ],
  });
  const close = async () => {
    try {
      await app.stop();
    } finally {
      sink.destroy();
      issuer.closeAllConnections();
      await new Promise<void>((resolve) => issuer.close(() => resolve()));
    }
  };
  try {
    await app.start();
  } catch (cause) {
    await close();
    throw cause;
  }
  const origin = (app.api as ManagedApiServer).address()!;
  const service = app.resolve<UploadService>(UPLOAD_CAPABILITY);
  return {
    app,
    origin,
    policy,
    logs: () => logs,
    calls: () => calls,
    stats: () => service.stats(),
    close,
    token: async (tenant = 'tenant-a', scope = 'documents:write') =>
      'Bearer ' +
      (await new SignJWT({ tenant_id: tenant, scope })
        .setProtectedHeader({ alg: 'ES256', kid: 'upload-fixture', typ: 'JWT' })
        .setIssuer(authority)
        .setSubject('upload-fixture-user')
        .setAudience('api://upload')
        .setExpirationTime('2m')
        .sign(pair.privateKey)),
  };
}
export const boundary = 'arkeniva-upload-fixture';
export function body(
  parts: readonly { name: string; value: string | Uint8Array; filename?: string; type?: string }[],
  closed = true,
): Buffer {
  const buffers: Buffer[] = [];
  for (const part of parts)
    buffers.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${part.name}"${part.filename === undefined ? '' : `; filename="${part.filename}"`}\r\n${part.type ? `Content-Type: ${part.type}\r\n` : ''}\r\n`,
      ),
      typeof part.value === 'string' ? Buffer.from(part.value) : Buffer.from(part.value),
      Buffer.from('\r\n'),
    );
  if (closed) buffers.push(Buffer.from(`--${boundary}--\r\n`));
  return Buffer.concat(buffers);
}
/** Real chunked transfer with native socket backpressure and no Content-Length. */
export async function send(
  origin: string,
  data: Buffer | AsyncIterable<Uint8Array>,
  authorization?: string,
  method = 'POST',
) {
  const req = request(origin + '/uploads', {
    method,
    headers: {
      'content-type': 'multipart/form-data; boundary=' + boundary,
      ...(authorization ? { authorization } : {}),
      'x-tenant-id': 'forged-tenant',
    },
  });
  const result = new Promise<{ status: number; body: string }>((resolve, reject) => {
    req.once('error', reject);
    req.once('response', (res) => {
      let output = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        output += chunk;
      });
      res.once('error', reject);
      res.once('end', () => resolve({ status: res.statusCode!, body: output }));
    });
  });
  void result.catch(() => undefined);
  try {
    if (Buffer.isBuffer(data)) req.end(data);
    else {
      for await (const chunk of data) if (!req.write(chunk)) await once(req, 'drain');
      req.end();
    }
    return await result;
  } catch (cause) {
    req.destroy();
    throw cause;
  }
}

/** Retry only a disposable bind race; protocol operations and production listeners are never retried. */
export async function fixture(
  input: Partial<UploadRoute> = {},
  timeoutMs = 5000,
  transport?: { tls: ServerTlsFiles; http2?: boolean },
  telemetryEndpoint?: string,
) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await attemptFixture(input, timeoutMs, transport, telemetryEndpoint);
    } catch (cause) {
      let current: unknown = cause,
        collision = false;
      for (let depth = 0; depth < 8 && current instanceof Error; depth++) {
        if (Object.getOwnPropertyDescriptor(current, 'code')?.value === 'EADDRINUSE')
          collision = true;
        current = current.cause;
      }
      if (!collision || attempt >= 3) throw cause;
    }
  }
}
