// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { listen } from 'soap';
import { contract } from '../../packages/soap/dist-test/fixture.js';

/** Reuse the compiled conformance WSDL; each invocation owns its TLS server and private files. */
export async function startSoapFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-comparison-'));
  const certificateFile = join(directory, 'server.pem'),
    keyFile = join(directory, 'server.key'),
    wsdlFile = join(directory, 'contract.wsdl');
  const calls = [],
    failures = [];
  let server;
  const close = async () => {
    try {
      if (server?.listening) {
        server.closeAllConnections();
        await new Promise((done) => server.close(done));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  };
  try {
    await chmod(directory, 0o700);
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
        '/CN=Owned SOAP Comparison',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        keyFile,
        '-out',
        certificateFile,
      ],
      { timeout: 10000, maxBuffer: 65536 },
    );
    await chmod(keyFile, 0o600);
    await writeFile(wsdlFile, contract, { mode: 0o600, flag: 'wx' });
    const marker = '0007-owned-soap-private-sku-π';
    server = createServer(
      {
        key: await readFile(keyFile),
        cert: await readFile(certificateFile),
        minVersion: 'TLSv1.2',
      },
      (_request, response) => response.writeHead(404).end(),
    );
    server.on('tlsClientError', () => undefined);
    await new Promise((done, reject) =>
      listen(
        server,
        '/soap',
        {
          InventoryService: {
            InventoryPort: {
              ReadStock(value) {
                try {
                  assert.ok([marker + '-0', marker + '-1'].includes(value.sku));
                  calls.push(value.sku);
                  return { quantity: 12 };
                } catch (cause) {
                  failures.push(cause);
                  throw new Error('The owned SOAP fixture rejected its request', { cause });
                }
              },
            },
          },
        },
        contract,
        (cause) => (cause ? reject(cause) : done()),
      ),
    );
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    const fixture = {
      endpoint: 'https://127.0.0.1:' + server.address().port + '/soap',
      certificateFile,
      wsdlFile,
      marker,
    };
    return {
      fixture,
      close,
      verify(expectedCalls) {
        assert.equal(failures.length, 0);
        assert.equal(calls.length, expectedCalls);
        assert.equal(calls.filter((value) => value === marker + '-0').length, expectedCalls / 2);
        assert.equal(calls.filter((value) => value === marker + '-1').length, expectedCalls / 2);
        return {
          actualNativeRequests: calls.length,
          distinctInputsVerified: true,
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
