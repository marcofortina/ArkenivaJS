// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, chmod } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { request } from 'node:https';
import { connect } from 'node:http2';
import { fixture, body, boundary } from './fixture.js';

test(
  'Multipart shares the verified direct HTTPS listener and native HTTP2 listener without accepting an untrusted certificate',
  { timeout: 15000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'arkeniva-upload-tls-'));
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
    const ca = await readFile(certificateFile);
    for (const http2 of [false, true]) {
      const f = await fixture({}, 5000, { tls: { certificateFile, privateKeyFile }, http2 });
      t.after(f.close);
      const token = await f.token(),
        input = body([
          { name: 'file', filename: 'owned.pdf', type: 'application/pdf', value: '%PDF-TLS' },
        ]);
      const h1 = (trusted: boolean) =>
        new Promise<{ status: number; body: string }>((resolve, reject) => {
          const req = request(
            f.origin + '/uploads',
            {
              method: 'POST',
              servername: 'localhost',
              ...(trusted ? { ca } : {}),
              headers: {
                authorization: token,
                'content-type': 'multipart/form-data; boundary=' + boundary,
              },
            },
            (res) => {
              let data = '';
              res.setEncoding('utf8');
              res.on('data', (chunk: string) => {
                data += chunk;
              });
              res.once('end', () => resolve({ status: res.statusCode!, body: data }));
              res.once('error', reject);
            },
          );
          req.once('error', reject);
          req.end(input);
        });
      await assert.rejects(h1(false), /certificate|self.signed/i);
      assert.equal(f.calls(), 0);
      const first = await h1(true);
      assert.equal(first.status, 200, first.body);
      assert.equal(JSON.parse(first.body).bytes, 8);
      if (http2) {
        const client = connect(f.origin, { ca, servername: 'localhost' });
        t.after(() => client.destroy());
        const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
          client.once('error', reject);
          const stream = client.request({
            ':method': 'POST',
            ':path': '/uploads',
            authorization: token,
            'content-type': 'multipart/form-data; boundary=' + boundary,
          });
          let status = 0,
            output = '';
          stream.setEncoding('utf8');
          stream.once('response', (headers) => {
            status = Number(headers[':status']);
          });
          stream.on('data', (chunk: string) => {
            output += chunk;
          });
          stream.once('error', reject);
          stream.once('end', () => resolve({ status, body: output }));
          stream.end(input);
        });
        client.close();
        assert.equal(result.status, 200, result.body);
        assert.equal(JSON.parse(result.body).bytes, 8);
      }
    }
  },
);
