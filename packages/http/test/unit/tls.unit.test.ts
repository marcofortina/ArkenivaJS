import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import { createHttpClient } from '@arkenivajs/http';

const execute = promisify(execFile);
test('EK-SEC-001 TLS transport rejects an untrusted issuer and a trusted certificate with the wrong hostname', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-tls-'));
  const certificate = join(directory, 'certificate.pem'),
    key = join(directory, 'key.pem');
  let server: ReturnType<typeof createServer> | undefined;
  try {
    await execute(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=wrong.example.invalid',
        '-addext',
        'subjectAltName=DNS:wrong.example.invalid',
        '-keyout',
        key,
        '-out',
        certificate,
      ],
      { timeout: 10000 },
    );
    server = createServer(
      { key: await readFile(key), cert: await readFile(certificate), minVersion: 'TLSv1.2' },
      (_request, reply) => reply.end('untrusted'),
    );
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const origin = `https://127.0.0.1:${address.port}`;
    const client = createHttpClient({
      allowedOrigins: [origin],
      allowPrivateNetwork: true,
      timeoutMs: 1000,
    });
    try {
      await assert.rejects(
        client.get(origin),
        (error) => error instanceof KitError && error.code === 'EK_HTTP_UPSTREAM',
      );
    } finally {
      await client.close();
    }
    const module = new URL('../../../dist/index.js', import.meta.url).href;
    const script = `
      const { createHttpClient } = await import(${JSON.stringify(module)});
      const client = createHttpClient({ allowedOrigins:[process.argv[1]],allowPrivateNetwork:true,timeoutMs:1000 });
      try {
        await client.get(process.argv[1]);
        throw new Error('A hostname mismatch was accepted');
      } catch (error) {
        if (error.code !== 'EK_HTTP_UPSTREAM' || error.cause?.cause?.code !== 'ERR_TLS_CERT_ALTNAME_INVALID') throw error;
        process.stdout.write('TLS hostname mismatch rejected');
      } finally { await client.close(); }
    `;
    const result = await execute(process.execPath, ['--input-type=module', '-e', script, origin], {
      timeout: 5000,
      env: { ...process.env, NODE_EXTRA_CA_CERTS: certificate },
    });
    assert.equal(result.stdout, 'TLS hostname mismatch rejected');
  } finally {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    await rm(directory, { recursive: true, force: true });
  }
});
