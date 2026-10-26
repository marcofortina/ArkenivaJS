// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, request } from 'node:https';
import type { Server } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import type { SecretProvider, SecretValue } from '@arkenivajs/security-crypto';

const unavailable = () =>
  new KitError({
    code: 'EK_CRYPTO_KEY_UNAVAILABLE',
    message: 'The disposable secret endpoint is unavailable',
  });

/** Private fixture resources and explicit test-only transports, without exposing TLS key material. */
export interface DisposableSecretFixture {
  readonly provider: SecretProvider;
  readonly untrustedProvider: SecretProvider;
  readonly publicKey: Uint8Array;
  requestCount(): number;
  rotate(): void;
  close(): Promise<void>;
}

/** Disposable HTTPS transport example; this is deliberately not a production secret manager. */
export async function createSecretFixture(authorization: {
  readonly testOnly: true;
}): Promise<DisposableSecretFixture> {
  if (authorization?.testOnly !== true)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Explicit disposable secret fixture authorization is required',
    });
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-crypto-secrets-'));
  await chmod(directory, 0o700);
  const values = new Map<string, SecretValue>();
  const issued = new Set<Buffer>();
  let encryptionVersion = 1;
  let server: Server | undefined,
    privateKey: Buffer | undefined,
    certificate: Buffer | undefined,
    closed = false;
  const bearer = randomBytes(32).toString('base64url');
  let requests = 0;
  try {
    const keyFile = join(directory, 'key.pem'),
      certificateFile = join(directory, 'certificate.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:prime256v1',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-addext',
        'extendedKeyUsage=serverAuth',
        '-keyout',
        keyFile,
        '-out',
        certificateFile,
      ],
      { stdio: 'ignore', timeout: 10000 },
    );
    await Promise.all([chmod(keyFile, 0o600), chmod(certificateFile, 0o600)]);
    privateKey = await readFile(keyFile);
    certificate = await readFile(certificateFile);
    const signing = generateKeyPairSync('ed25519');
    values.set('encryption', { bytes: randomBytes(32), keyVersion: randomUUID() });
    values.set('previous', { bytes: randomBytes(32), keyVersion: 'fixture-unused-v0' });
    values.set('hmac', { bytes: randomBytes(32), keyVersion: 'fixture-hmac-v1' });
    values.set('signing', {
      bytes: signing.privateKey.export({ format: 'der', type: 'pkcs8' }),
      keyVersion: randomUUID(),
    });
    server = createServer(
      { key: privateKey, cert: certificate, minVersion: 'TLSv1.3', maxHeaderSize: 4096 },
      (incoming, response) => {
        requests++;
        const supplied = Buffer.from(incoming.headers.authorization ?? ''),
          expected = Buffer.from('Bearer ' + bearer);
        const authenticated =
          supplied.length === expected.length && timingSafeEqual(supplied, expected);
        supplied.fill(0);
        expected.fill(0);
        const reference = incoming.url?.slice(1),
          value = reference ? values.get(reference) : undefined;
        if (incoming.method !== 'GET' || !authenticated || !value) {
          response.writeHead(403);
          response.end();
          return;
        }
        response.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': value.bytes.length,
          'x-key-version': value.keyVersion,
          'cache-control': 'no-store',
        });
        response.end(value.bytes);
      },
    );
    server.requestTimeout = 1000;
    server.headersTimeout = 1000;
    server.maxConnections = 8;
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject);
      server!.listen(0, '127.0.0.1', () => {
        server!.removeListener('error', reject);
        resolve();
      });
    });
    privateKey.fill(0);
    privateKey = undefined;
    const address = server.address();
    if (!address || typeof address === 'string') throw unavailable();
    const port = address.port,
      ca = Buffer.from(certificate);
    /** Closed origin, pinned private CA, no redirects and a strict binary response budget. */
    class FixtureSecretProvider implements SecretProvider {
      readonly usage = 'test-only' as const;
      constructor(private readonly trustedCA: Buffer) {}
      get(reference: string, options: OperationOptions = {}): Promise<SecretValue> {
        const timeoutMs = options.timeoutMs ?? 1000;
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3000)
          return Promise.reject(
            new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid secret fixture deadline' }),
          );
        if (closed || !['encryption', 'previous', 'hmac', 'signing'].includes(reference))
          return Promise.reject(unavailable());
        if (issued.size >= 128) return Promise.reject(unavailable());
        return new Promise((resolve, reject) => {
          const chunks: Buffer[] = [];
          let size = 0,
            settled = false;
          const fail = () => {
            if (settled) return;
            settled = true;
            for (const chunk of chunks) chunk.fill(0);
            reject(unavailable());
          };
          const outbound = request(
            {
              hostname: '127.0.0.1',
              port,
              path: '/' + reference,
              method: 'GET',
              ca: this.trustedCA,
              minVersion: 'TLSv1.3',
              rejectUnauthorized: true,
              headers: { authorization: 'Bearer ' + bearer },
              signal: AbortSignal.any([
                AbortSignal.timeout(timeoutMs),
                ...(options.signal ? [options.signal] : []),
              ]),
              timeout: timeoutMs,
              agent: false,
            },
            (incoming) => {
              const version = incoming.headers['x-key-version'];
              if (
                incoming.statusCode !== 200 ||
                incoming.headers['content-type'] !== 'application/octet-stream' ||
                typeof version !== 'string' ||
                version.length < 1 ||
                version.length > 512
              ) {
                incoming.destroy();
                fail();
                return;
              }
              incoming.on('data', (chunk: Buffer) => {
                size += chunk.length;
                if (size > 16384) {
                  chunk.fill(0);
                  incoming.destroy();
                  fail();
                } else chunks.push(chunk);
              });
              incoming.once('error', fail);
              incoming.once('aborted', fail);
              incoming.once('end', () => {
                if (settled) return;
                settled = true;
                const bytes = Buffer.concat(chunks);
                issued.add(bytes);
                for (const chunk of chunks) chunk.fill(0);
                resolve({ bytes, keyVersion: version });
              });
            },
          );
          outbound.once('timeout', () => {
            outbound.destroy();
            fail();
          });
          outbound.once('error', fail);
          outbound.end();
        });
      }
    }
    const provider = new FixtureSecretProvider(ca);
    return {
      provider,
      untrustedProvider: new FixtureSecretProvider(Buffer.alloc(0)),
      publicKey: signing.publicKey.export({ format: 'der', type: 'spki' }),
      requestCount: () => requests,
      rotate() {
        if (closed) throw unavailable();
        const previous = values.get('previous')!,
          current = values.get('encryption')!;
        if (previous !== current) previous.bytes.fill(0);
        values.set('previous', current);
        values.set('encryption', {
          bytes: randomBytes(32),
          keyVersion: 'fixture-encryption-v' + ++encryptionVersion,
        });
      },
      async close() {
        if (closed) return;
        closed = true;
        server!.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
          server!.close((error) => (error ? reject(unavailable()) : resolve())),
        );
        ca.fill(0);
        certificate?.fill(0);
        for (const value of values.values()) value.bytes.fill(0);
        for (const value of issued) value.fill(0);
        issued.clear();
        values.clear();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch {
    server?.closeAllConnections();
    server?.close();
    privateKey?.fill(0);
    certificate?.fill(0);
    for (const value of values.values()) value.bytes.fill(0);
    for (const value of issued) value.fill(0);
    issued.clear();
    await rm(directory, { recursive: true, force: true });
    throw unavailable();
  }
}
