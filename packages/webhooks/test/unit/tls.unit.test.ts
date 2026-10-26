// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:https';

test(
  'Real HTTPS accepts only the owned explicitly trusted CA and never disables certificate verification',
  { timeout: 20000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'arkeniva-webhook-tls-'));
    await chmod(directory, 0o700);
    t.after(() => rm(directory, { recursive: true, force: true }));
    const keyFile = join(directory, 'private.pem'),
      certFile = join(directory, 'certificate.pem');
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
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        keyFile,
        '-out',
        certFile,
      ],
      { timeout: 10000 },
    );
    await chmod(keyFile, 0o600);
    let received = 0;
    const server = createServer(
      { key: await readFile(keyFile), cert: await readFile(certFile), minVersion: 'TLSv1.2' },
      (req, res) => {
        req.resume();
        req.once('end', () => {
          received++;
          res.statusCode = 202;
          res.end('{}');
        });
      },
    );
    server.on('tlsClientError', () => {
      /* The negative trust case is an expected handshake rejection. */
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const address = server.address();
    if (!address || typeof address !== 'object')
      throw new Error('Disposable TLS listener unavailable');
    const environment = Object.fromEntries(
      ['PATH', 'HOME', 'TMPDIR', 'NODE_V8_COVERAGE']
        .filter((name) => process.env[name] !== undefined)
        .map((name) => [name, process.env[name]!]),
    );
    const child = async (trusted: boolean) => {
      const result = await promisify(execFile)(
        process.execPath,
        [
          fileURLToPath(new URL('./tls-client.js', import.meta.url)),
          'https://127.0.0.1:' + address.port,
        ],
        {
          timeout: 10000,
          env: {
            ...environment,
            ARKENIVA_WEBHOOKS_DISPOSABLE: '1',
            ...(trusted ? { NODE_EXTRA_CA_CERTS: certFile } : {}),
          },
        },
      );
      assert.equal(result.stderr, '');
      return JSON.parse(result.stdout);
    };
    assert.deepEqual(await child(false), { status: 'unknown', attemptCount: 1 });
    assert.equal(received, 0);
    assert.deepEqual(await child(true), { status: 'accepted', attemptCount: 1 });
    assert.equal(received, 1);
  },
);
