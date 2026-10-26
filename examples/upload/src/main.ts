// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer, request } from 'node:http';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createApplication } from '@arkenivajs/core';
import type { Application, MeteringEvent } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { uploadPlugin, UPLOAD_CAPABILITY } from '@arkenivajs/upload';
import type { UploadService } from '@arkenivajs/upload';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';
import { meteringPlugin } from '@arkenivajs/metering';
import type { ManagedUsageMeter } from '@arkenivajs/metering';

/** Run the public capability against owned loopback OIDC, HTTP and SDK collector fixtures. */
async function runUploadAttempt(registerUsageDefinitions: boolean) {
  const pair = await generateKeyPair('ES256'),
    key = {
      ...(await exportJWK(pair.publicKey)),
      alg: 'ES256',
      kid: 'owned-upload-key',
      use: 'sig',
    };
  const envelopes: {
      resourceMetrics?: { scopeMetrics: { metrics: { name: string; unit: string }[] }[] }[];
    }[] = [],
    events: MeteringEvent[] = [],
    logs: string[] = [];
  let authority = '',
    app: Application | undefined;
  const fixture = createServer((req, res) => {
    void (async () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/keys') {
        res.end(JSON.stringify({ keys: [key] }));
        return;
      }
      if (req.url === '/.well-known/openid-configuration') {
        res.end(JSON.stringify({ issuer: authority, jwks_uri: authority + '/keys' }));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 1048576) throw new Error('Fixture input limit exceeded');
        chunks.push(chunk);
      }
      if (req.url === '/v1/metrics')
        envelopes.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.end('{}');
    })().catch(() => {
      res.statusCode = 400;
      res.end('{}');
    });
  });
  const destination = new Writable({
    write(chunk: Buffer, _encoding, done) {
      logs.push(chunk.toString('utf8'));
      done();
    },
  });
  try {
    await new Promise<void>((resolve) => fixture.listen(0, '127.0.0.1', resolve));
    const address = fixture.address();
    if (!address || typeof address !== 'object')
      throw new Error('The disposable collector is unavailable');
    authority = `http://127.0.0.1:${address.port}`;
    const reservation = createServer();
    await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
    const reserved = reservation.address();
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    if (!reserved || typeof reserved !== 'object')
      throw new Error('The disposable API port is unavailable');
    app = await createApplication({
      service: { name: 'upload-example', version: '0.1.0', environment: 'test' },
      http: { host: '127.0.0.1', port: reserved.port },
      logging: { level: 'debug' },
      security: { issuer: authority, audience: 'api://upload', algorithms: ['ES256'] },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      metering: { enabled: true, exporter: 'http' },
      plugins: [
        loggingPlugin({ destination }),
        securityPlugin({ allowInsecureLoopback: true }),
        telemetryPlugin({
          endpoint: authority,
          allowInsecureLoopback: true,
          exportIntervalMs: 1000,
          exportTimeoutMs: 1000,
        }),
        meteringPlugin({
          dependencies: ['telemetry'],
          ...(registerUsageDefinitions
            ? {
                usageDefinitions: {
                  'upload.request.bytes': 'bytes',
                  'upload.files': 'items',
                  'upload.parts': 'items',
                } as const,
              }
            : {}),
          exporter: {
            kind: 'http',
            async export(batch) {
              events.push(...batch);
            },
            async close() {},
          },
        }),
        apiPlugin({ dependencies: ['security', 'telemetry', 'metering'] }),
        uploadPlugin({
          routes: [
            {
              path: '/uploads',
              method: 'POST',
              auth: { required: true, scopes: ['documents:write'] },
              policy: {
                maxRequestBytes: 1000000,
                maxFileBytes: 500000,
                maxFiles: 1,
                maxFields: 2,
                maxFieldBytes: 1024,
                maxParts: 3,
                allowedMediaTypes: ['application/pdf'],
              },
              responseSchema: {
                type: 'object',
                required: ['files', 'bytes', 'tenant'],
                properties: {
                  files: { type: 'integer' },
                  bytes: { type: 'integer' },
                  tenant: { type: 'string' },
                },
                additionalProperties: false,
              },
              async handler(input) {
                let files = 0,
                  bytes = 0;
                for await (const part of input.parts)
                  if (part.kind === 'file') {
                    files++;
                    for await (const chunk of part.stream) bytes += chunk.byteLength;
                  }
                return { files, bytes, tenant: input.context.auth!.tenantId };
              },
            },
          ],
        }),
      ],
    });
    await app.start();
    const origin = (app.api as ManagedApiServer).address()!,
      boundary = 'owned-upload-example',
      payload = Buffer.concat([
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="private-field"\r\n\r\nprivate-field-content\r\n--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="private-upload.pdf"\r\nContent-Type: application/pdf\r\n\r\n`,
        ),
        Buffer.from([0, 1, 2, 253, 254, 255]),
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]),
      authorization =
        'Bearer ' +
        (await new SignJWT({ tenant_id: 'verified-upload-tenant', scope: 'documents:write' })
          .setProtectedHeader({ alg: 'ES256', kid: 'owned-upload-key', typ: 'JWT' })
          .setIssuer(authority)
          .setAudience('api://upload')
          .setSubject('owned-upload-subject')
          .setExpirationTime('2m')
          .sign(pair.privateKey));
    const send = (authenticated: boolean) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = request(
          origin + '/uploads',
          {
            method: 'POST',
            headers: {
              'content-type': 'multipart/form-data; boundary=' + boundary,
              'x-tenant-id': 'forged-tenant',
              ...(authenticated ? { authorization } : {}),
            },
          },
          (res) => {
            let output = '';
            res.setEncoding('utf8');
            res.on('data', (chunk: string) => {
              output += chunk;
            });
            res.once('error', reject);
            res.once('end', () => resolve({ status: res.statusCode!, body: output }));
          },
        );
        req.once('error', reject);
        req.end(payload);
      });
    const accepted = await send(true),
      denied = await send(false),
      receipt = JSON.parse(accepted.body),
      stats = app.resolve<UploadService>(UPLOAD_CAPABILITY).stats();
    await app.meter.flush();
    await app.telemetry.flush();
    await app.logger.flush();
    const privateValues = ['private-field-content', 'private-upload.pdf', authorization],
      wire = JSON.stringify(envelopes),
      log = logs.join(''),
      eventText = JSON.stringify(events),
      metrics = envelopes
        .flatMap((entry) => entry.resourceMetrics ?? [])
        .flatMap((entry) => entry.scopeMetrics)
        .flatMap((entry) => entry.metrics);
    return Object.freeze({
      accepted: accepted.status,
      denied: denied.status,
      files: receipt.files as number,
      bytes: receipt.bytes as number,
      wireBytesVerified: stats.observedBytes === payload.length,
      tenantVerified: receipt.tenant === 'verified-upload-tenant',
      logsPrivate: !privateValues.some((value) => log.includes(value)),
      metricsObserved:
        metrics.some((metric) => metric.name === 'upload.request.bytes' && metric.unit === 'By') &&
        metrics.some((metric) => metric.name === 'upload.duration.ms'),
      metricsPrivate: ![...privateValues, 'verified-upload-tenant', 'owned-upload-subject'].some(
        (value) => wire.includes(value),
      ),
      meterObserved:
        events.length === 1 &&
        events[0]!.tenantId === 'verified-upload-tenant' &&
        events[0]!.counters['upload.request.bytes']?.value === payload.length &&
        events[0]!.counters['http.requests']?.value === 1,
      meterPrivate: !privateValues.some((value) => eventText.includes(value)),
      meterClosed: (app.meter as ManagedUsageMeter).snapshot().activeSessions === 0,
      meterGap: events.some((event) => event.quality.missing.includes('span_not_instrumented')),
    });
  } finally {
    try {
      await app?.stop();
    } finally {
      destination.destroy();
      fixture.closeAllConnections();
      if (fixture.listening) await new Promise<void>((resolve) => fixture.close(() => resolve()));
    }
  }
}
/** A released ephemeral port can be claimed by another test before bind; retry only that startup race. */
export async function runUploadExample(registerUsageDefinitions = true) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await runUploadAttempt(registerUsageDefinitions);
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
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.log(JSON.stringify(await runUploadExample()));
}
