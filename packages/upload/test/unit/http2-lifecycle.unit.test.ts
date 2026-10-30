// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, chmod } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { connect, constants } from 'node:http2';
import type { ClientHttp2Session, ClientHttp2Stream } from 'node:http2';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import type { UploadRoute } from '../../dist/index.js';
import { fixture, body, boundary, policy } from './fixture.js';

async function until(predicate: () => boolean): Promise<void> {
  for (let index = 0; index < 200; index++) {
    if (predicate()) return;
    await delay(10);
  }
  assert.ok(predicate(), 'The owned HTTP2 stream did not reach its expected state');
}

async function secureFixture(t: TestContext, route: Partial<UploadRoute> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'arkeniva-upload-h2-lifecycle-'));
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const certificateFile = join(directory, 'certificate.pem'),
    privateKeyFile = join(directory, 'private.pem');
  execFileSync(
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
      privateKeyFile,
      '-out',
      certificateFile,
    ],
    { stdio: 'ignore', timeout: 10000 },
  );
  await chmod(privateKeyFile, 0o600);
  const f = await fixture(route, 5000, {
    tls: { certificateFile, privateKeyFile },
    http2: true,
  });
  const client = connect(f.origin, {
    ca: await readFile(certificateFile),
    servername: 'localhost',
  });
  const errors: Error[] = [];
  client.on('error', (error) => errors.push(error));
  t.after(async () => {
    client.destroy();
    await f.close();
  });
  await once(client, 'connect');
  assert.equal(client.alpnProtocol, 'h2');
  return { ...f, client, errors };
}

function upload(client: ClientHttp2Session, authorization: string, length?: number) {
  const stream = client.request({
    ':method': 'POST',
    ':path': '/uploads',
    authorization,
    'x-tenant-id': 'forged-http2-tenant',
    'content-type': 'multipart/form-data; boundary=' + boundary,
    ...(length === undefined ? {} : { 'content-length': String(length) }),
  });
  stream.setTimeout(3000, () => stream.destroy(new Error('The owned HTTP2 upload timed out')));
  return stream;
}

function receipt(stream: ClientHttp2Stream) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    let status = 0,
      output = '',
      ended = false;
    stream.setEncoding('utf8');
    stream.once('response', (headers) => {
      status = Number(headers[':status']);
      assert.equal(headers.connection, undefined);
    });
    stream.on('data', (chunk: string) => {
      output += chunk;
      if (Buffer.byteLength(output) > 65536)
        stream.destroy(new Error('The owned HTTP2 receipt exceeded its bound'));
    });
    stream.once('error', reject);
    stream.once('end', () => {
      ended = true;
      resolve({ status, body: output });
    });
    stream.once('close', () => {
      if (!ended) reject(new Error('The HTTP2 upload closed without a complete receipt'));
    });
  });
}

const file = (value: string | Uint8Array) => ({
  name: 'file',
  filename: 'owned.pdf',
  type: 'application/pdf',
  value,
});

test(
  'Canceling one authenticated HTTP2 upload preserves its sibling tenant and physical work ownership',
  { timeout: 15000 },
  async (t) => {
    let release!: () => void,
      cancelled = false,
      consumed = false;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const f = await secureFixture(t, {
      async handler(input) {
        const tenant = input.context.auth!.tenantId;
        let files = 0,
          bytes = 0;
        input.context.signal.addEventListener(
          'abort',
          () => {
            if (tenant === 'tenant-a') cancelled = true;
          },
          { once: true },
        );
        try {
          for await (const part of input.parts) {
            if (part.kind !== 'file') continue;
            files++;
            for await (const chunk of part.stream) {
              bytes += chunk.byteLength;
              if (tenant === 'tenant-a') consumed = true;
            }
          }
          return { files, bytes, order: [], tenant };
        } finally {
          if (tenant === 'tenant-a') await gate;
        }
      },
    });
    try {
      const interrupted = upload(f.client, await f.token('tenant-a'));
      interrupted.on('error', () => {
        /* Cancellation is the tested wire condition. */
      });
      interrupted.write(body([file(Buffer.alloc(4096, 97))], false));
      await until(() => consumed);
      const sibling = upload(f.client, await f.token('tenant-b')),
        siblingReceipt = receipt(sibling);
      sibling.end(body([file('%PDF-sibling')]));
      const closed = once(interrupted, 'close');
      interrupted.close(constants.NGHTTP2_CANCEL);
      await closed;
      await until(() => cancelled);
      const accepted = await siblingReceipt;
      assert.equal(accepted.status, 200, accepted.body);
      assert.deepEqual(JSON.parse(accepted.body), {
        files: 1,
        bytes: 12,
        order: [],
        tenant: 'tenant-b',
      });
      await until(() => f.stats().successfulRequests === 1);
      assert.equal(f.stats().activeRequests, 1);
      assert.equal(f.stats().rejectedRequests, 1);
      assert.equal(f.client.closed, false);
      assert.equal(f.client.destroyed, false);
      release();
      await until(() => f.stats().activeRequests === 0);
      const recovery = upload(f.client, await f.token('tenant-b')),
        recoveredReceipt = receipt(recovery);
      recovery.end(body([file('%PDF-recovered')]));
      const recovered = await recoveredReceipt;
      assert.equal(recovered.status, 200, recovered.body);
      assert.equal(JSON.parse(recovered.body).tenant, 'tenant-b');
      assert.equal(JSON.parse(recovered.body).bytes, 14);
      await until(() => f.stats().activeRequests === 0);
      assert.equal(f.stats().receivedRequests, 3);
      assert.equal(f.stats().successfulRequests, 2);
      assert.equal(f.stats().rejectedRequests, 1);
      assert.deepEqual(f.errors, []);
      assert.equal(/forged-http2-tenant|%PDF-sibling|%PDF-recovered|Bearer /.test(f.logs()), false);
    } finally {
      release();
    }
  },
);

test(
  'Declared and observed HTTP2 upload limits reject only their stream while the verified session remains usable',
  { timeout: 15000 },
  async (t) => {
    const f = await secureFixture(t, {
      policy: { ...policy, maxRequestBytes: 1024, maxFileBytes: 512 },
    });
    const token = await f.token('tenant-b');
    for (const [bytes, declared] of [
      [1536, true],
      [1536, false],
      [513, false],
    ] as const) {
      const input = body([file(Buffer.alloc(bytes, 120))]);
      const rejected = upload(f.client, token, declared ? input.length : undefined),
        rejectedReceipt = receipt(rejected),
        sibling = upload(f.client, token),
        siblingReceipt = receipt(sibling);
      rejected.end(input);
      sibling.end(body([file('%PDF-safe')]));
      const [failure, success] = await Promise.all([rejectedReceipt, siblingReceipt]);
      assert.equal(failure.status, 413, failure.body);
      assert.match(failure.body, /EK_UPLOAD_LIMIT/);
      assert.equal(failure.body.includes('xxxxxxxx'), false);
      assert.equal(success.status, 200, success.body);
      assert.equal(JSON.parse(success.body).tenant, 'tenant-b');
      assert.equal(JSON.parse(success.body).bytes, 9);
      assert.equal(f.client.closed, false);
      assert.equal(f.client.destroyed, false);
      await until(() => f.stats().activeRequests === 0);
    }
    const recovery = upload(f.client, token),
      recoveredReceipt = receipt(recovery);
    recovery.end(body([file('%PDF-final')]));
    const recovered = await recoveredReceipt;
    assert.equal(recovered.status, 200, recovered.body);
    assert.equal(JSON.parse(recovered.body).bytes, 10);
    await until(() => f.stats().activeRequests === 0);
    assert.equal(f.stats().receivedRequests, 7);
    assert.equal(f.stats().successfulRequests, 4);
    assert.equal(f.stats().rejectedRequests, 3);
    assert.deepEqual(f.errors, []);
  },
);
