// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, fork } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { createServer } from 'node:https';
import { mkdtemp, readFile, rm, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FederationProtocolHttp } from '../../dist/protocol-http.js';
import { capture } from '../../dist/settings.js';
import { transactionFixture } from '../fixtures/transactions.js';
import { registration } from '../fixtures/registration.js';

test(
  'Actual HTTPS protocol requests use exact approved destinations and isolate credentials',
  { timeout: 20000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-eid-protocol-')),
      certificate = join(directory, 'certificate.pem'),
      privateKey = join(directory, 'key.pem');
    try {
      await promisify(execFile)(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-noenc',
          '-days',
          '1',
          '-subj',
          '/CN=127.0.0.1',
          '-addext',
          'subjectAltName=IP:127.0.0.1',
          '-addext',
          'basicConstraints=critical,CA:TRUE',
          '-keyout',
          privateKey,
          '-out',
          certificate,
        ],
        { timeout: 10000 },
      );
      await Promise.all([chmod(privateKey, 0o600), chmod(certificate, 0o600)]);
      const requests: {
          path: string;
          method: string;
          authorization?: string;
          cookie?: string;
          body: string;
        }[] = [],
        server = createServer(
          { key: await readFile(privateKey), cert: await readFile(certificate) },
          (request, response) => {
            let body = '';
            request.on('data', (chunk) => {
              body += String(chunk);
            });
            request.on('end', () => {
              const path = request.url!;
              requests.push({
                path,
                method: request.method!,
                ...(request.headers.authorization
                  ? { authorization: request.headers.authorization }
                  : {}),
                ...(request.headers.cookie ? { cookie: request.headers.cookie } : {}),
                body,
              });
              if (path === '/redirect') {
                response.writeHead(302, { location: '/capture' });
                response.end();
                return;
              }
              if (path === '/wrong-type') {
                response.setHeader('content-type', 'text/plain');
                response.end('unexpected');
                return;
              }
              if (path === '/missing-type') {
                response.end('untyped');
                return;
              }
              if (path === '/jwks') {
                response.setHeader('content-type', 'application/jwk-set+json');
                response.end('{"keys":[]}');
                return;
              }
              if (path === '/token' || path === '/unavailable') {
                response.statusCode = path === '/unavailable' ? 503 : 200;
                response.setHeader('content-type', 'application/json');
                response.end('{"ok":true}');
                return;
              }
              response.setHeader('content-type', 'application/jwt');
              if (path === '/empty') {
                response.end();
                return;
              }
              if (path === '/utf8') {
                response.end(Buffer.from([0xc3, 0x28]));
                return;
              }
              if (path === '/oversized') {
                response.end('x'.repeat(8193));
                return;
              }
              if (path === '/slow') {
                setTimeout(() => response.end('late-fixture-response'), 250).unref();
                return;
              }
              response.end('fixture-signed-encrypted-response');
            });
          },
        );
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const child = fork(new URL('../fixtures/protocol-http-worker.js', import.meta.url), [], {
        execArgv: [],
        env: { ...process.env, NODE_EXTRA_CA_CERTS: certificate },
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      });
      let diagnostics = '';
      child.stderr?.on('data', (chunk: Buffer) => {
        if (diagnostics.length < 8192) diagnostics += chunk.toString();
      });
      try {
        const result = Promise.race([
          once(child, 'message'),
          once(child, 'exit').then(() => {
            throw new Error('Protocol worker exited before evidence: ' + diagnostics);
          }),
        ]);
        child.send({ origin: `https://127.0.0.1:${address.port}` });
        assert.deepEqual((await result)[0], { ok: true });
        await once(child, 'exit');
        assert.equal(requests.filter((request) => request.path === '/token').length, 1);
        assert.equal(requests.filter((request) => request.path === '/userinfo').length, 1);
        assert.equal(requests.filter((request) => request.path === '/jwks').length, 1);
        assert.equal(
          requests.filter((request) => request.path === '/unavailable').length,
          1,
          'Code exchange must never retry',
        );
        assert.equal(
          requests.filter((request) => ['/capture', '/not-approved'].includes(request.path)).length,
          0,
        );
        assert.ok(requests.every((request) => request.cookie === undefined));
        assert.ok(
          requests
            .filter((request) => ['/token', '/jwks', '/unavailable'].includes(request.path))
            .every((request) => request.authorization === undefined),
        );
        assert.equal(
          requests.find((request) => request.path === '/userinfo')!.authorization,
          'Bearer fixture-access-token',
        );
        assert.equal(
          new URLSearchParams(requests.find((request) => request.path === '/token')!.body).get(
            'code',
          ),
          'fixture-code',
        );
      } finally {
        child.kill();
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
test('Protocol endpoints require a bounded immutable approved catalog; omission grants no I/O', async () => {
  const f = await transactionFixture();
  try {
    assert.throws(
      () => new FederationProtocolHttp(capture(f.settings, 'test'), f.profile.profileId),
      { code: 'EK_EID_PROFILE' },
    );
    const input = await registration(f.profile.entityId);
    for (const approvedProtocolEndpoints of [
      [],
      ['http://idp.example.test/token'],
      ['https://idp.example.test/token', 'https://idp.example.test/token'],
    ])
      assert.throws(
        () =>
          capture(
            {
              ...f.settings,
              profiles: [
                { ...f.profile, oidcRegistration: { ...input, approvedProtocolEndpoints } },
              ],
            },
            'test',
          ),
        { code: 'EK_EID_PROFILE' },
      );
    const destinations = ['https://idp.example.test/token', 'https://idp.example.test/userinfo'],
      settings = capture(
        {
          ...f.settings,
          profiles: [
            {
              ...f.profile,
              oidcRegistration: { ...input, approvedProtocolEndpoints: destinations },
            },
          ],
        },
        'test',
      );
    destinations[0] = 'https://foreign.example.test/token';
    assert.equal(
      settings.profiles[0]!.oidcRegistration!.approvedProtocolEndpoints![0],
      'https://idp.example.test/token',
    );
    const transport = new FederationProtocolHttp(settings, f.profile.profileId);
    try {
      await assert.rejects(
        () =>
          f.runtime.run(async (call) =>
            transport.fetch(call, {
              tokenEndpoint: 'https://foreign.example.test/token',
              userInfoEndpoint: 'https://idp.example.test/userinfo',
            }),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    } finally {
      await transport.close();
    }
  } finally {
    await f.close();
  }
});
