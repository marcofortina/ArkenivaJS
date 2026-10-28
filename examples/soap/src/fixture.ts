// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createServer } from 'node:https';
import { mkdtemp, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { listen } from 'soap';
import type { SoapPluginSettings } from '@arkenivajs/soap';

/** An owned local TLS fixture; its provider is rejected by the production plugin configuration. */
export async function createFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-example-'));
  await chmod(directory, 0o700);
  const keyFile = join(directory, 'private.pem'),
    certificate = join(directory, 'certificate.pem'),
    wsdlFile = join(directory, 'stock.wsdl'),
    password = randomUUID(),
    fault = 'private-soap-fault-' + randomUUID();
  let server: ReturnType<typeof createServer> | undefined;
  try {
    const xml = await readFile(new URL('../test/fixtures/stock.wsdl', import.meta.url), 'utf8');
    await writeFile(wsdlFile, xml, { mode: 0o400, flag: 'wx' });
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
        '-sha256',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
        '-keyout',
        keyFile,
        '-out',
        certificate,
      ],
      { timeout: 10000 },
    );
    await chmod(keyFile, 0o600);
    const key = await readFile(keyFile),
      ca = await readFile(certificate),
      expected = Buffer.from('Basic ' + Buffer.from('stock-demo:' + password).toString('base64'));
    let calls = 0,
      requestBytes = 0;
    server = createServer({ key, cert: ca, minVersion: 'TLSv1.2' });
    server.on('tlsClientError', () => undefined);
    const native = listen(
      server,
      '/stock',
      {
        InventoryService: {
          InventoryPort: {
            ReadStock(value: { sku: string }) {
              calls++;
              if (value.sku === 'fault')
                throw { Fault: { faultcode: 'soap:Server', faultstring: fault, statusCode: 500 } };
              return { quantity: 42 };
            },
          },
        },
      },
      xml,
    );
    native.authenticate = (_security, _callback, request) => {
      const actual = Buffer.from(request?.headers.authorization ?? '');
      return actual.length === expected.length && timingSafeEqual(actual, expected);
    };
    native.log = (kind: string, value: unknown) => {
      if (kind === 'received' && typeof value === 'string')
        requestBytes += Buffer.byteLength(value);
    };
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address !== 'object')
      throw new Error('The disposable SOAP listener is unavailable');
    const provider = {
      usage: 'test-only' as const,
      async get(reference: string) {
        if (reference === 'ca') return { bytes: ca.slice(), keyVersion: 'v1' };
        if (reference !== 'auth') throw new Error('Unknown fixture secret reference');
        return {
          bytes: Buffer.from(
            JSON.stringify({
              version: 1,
              httpAuth: { scheme: 'basic', username: 'stock-demo', password },
            }),
          ),
          keyVersion: 'v1',
        };
      },
    };
    const settings: SoapPluginSettings = {
      services: [
        {
          id: 'stock.v1',
          wsdlFile,
          endpoint: 'https://127.0.0.1:' + address.port + '/stock',
          protocol: '1.1',
          allowedOperations: ['ReadStock'],
          credentialsRef: 'auth',
          trustedCaRef: 'ca',
          maxResponseBytes: 16384,
        },
      ],
      secretProvider: provider,
      policy: { maxConcurrent: 2, timeoutMs: 10000, maxInputBytes: 16384, maxOutputBytes: 16384 },
    };
    let closing: Promise<void> | undefined;
    return {
      settings,
      privateMarkers: [password, fault],
      calls: () => calls,
      requestBytes: () => requestBytes,
      close() {
        if (!closing)
          closing = (async () => {
            server!.closeAllConnections();
            await new Promise<void>((resolve) => server!.close(() => resolve()));
            key.fill(0);
            expected.fill(0);
            await rm(directory, { recursive: true, force: true });
          })();
        return closing;
      },
    };
  } catch (error) {
    server?.closeAllConnections();
    server?.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
