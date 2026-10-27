// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, chmod } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:http2';
import { setImmediate } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { fixtureSettings, startFixture } from './fixture.js';

test('Exact Referer fallback works only when Origin is absent and hostile/silent browser contexts remain rejected', async () => {
  const f = await startFixture();
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    const base = {
      cookie: '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + token.split('.')[1]!,
      'x-csrf-token': token,
    };
    const accepted = await fetch(f.origin + '/protected', {
      method: 'POST',
      headers: { ...base, referer: 'https://app.fixture.invalid/owned/page' },
    });
    assert.equal(accepted.status, 200);
    await accepted.arrayBuffer();
    for (const headers of [
      base,
      { ...base, referer: 'not-a-url' },
      { ...base, referer: 'https://user:secret@app.fixture.invalid/' },
      { ...base, referer: 'https://evil.fixture.invalid/' },
      { ...base, origin: 'null', referer: 'https://app.fixture.invalid/' },
    ]) {
      const response = await fetch(f.origin + '/protected', { method: 'POST', headers });
      assert.equal(response.status, 403);
      await response.arrayBuffer();
    }
    assert.equal(f.state.effects, 1);
  } finally {
    await f.close();
  }
});

test('Bearer-only header configuration does not implicitly require CSRF and cannot mint or verify a disabled token', async () => {
  const input = fixtureSettings();
  input.settings = {
    ...input.settings,
    policy: { ...input.settings.policy, csrfEnabled: false },
    cookieRoutes: [],
    allowedOrigins: [],
  };
  const f = await startFixture(input);
  try {
    const ordinary = await fetch(f.origin + '/ordinary', { method: 'POST' });
    assert.equal(ordinary.status, 200);
    assert.ok(ordinary.headers.get('content-security-policy'));
    await ordinary.arrayBuffer();
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId })),
      (error) => error instanceof KitError && error.code === 'EK_HTTP_CSRF',
    );
    assert.throws(
      () => f.service.installHeaders({ ...f.settings.policy, csrfEnabled: true }),
      (error) => error instanceof KitError,
    );
  } finally {
    await f.close();
  }
});

test(
  'Direct native HTTPS retains certificate verification and issues secure CSRF cookies',
  { timeout: 15000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkeniva-csrf-tls-'));
    await chmod(directory, 0o700);
    let f: Awaited<ReturnType<typeof startFixture>> | undefined;
    try {
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
      f = await startFixture(fixtureSettings(), { certificateFile, privateKeyFile });
      const current = f;
      const call = (trusted: boolean) =>
        new Promise<{ status: number; cookie: string; body: string }>((resolve, reject) => {
          const request = httpsRequest(
            current.origin + '/token',
            {
              servername: 'localhost',
              ...(trusted ? { ca } : {}),
              headers: {
                cookie: '__Host-session=' + current.alice.cookie,
                'x-session-hint': current.alice.sessionId,
              },
            },
            (response) => {
              let body = '';
              response.setEncoding('utf8');
              response.on('data', (chunk: string) => {
                body += chunk;
              });
              response.once('error', reject);
              response.once('end', () =>
                resolve({
                  status: response.statusCode!,
                  cookie: response.headers['set-cookie']?.[0] ?? '',
                  body,
                }),
              );
            },
          );
          request.once('error', reject);
          request.end();
        });
      await assert.rejects(call(false), /certificate|self.signed/i);
      assert.equal(current.state.authorizations, 0);
      const accepted = await call(true);
      assert.equal(accepted.status, 200);
      assert.match(accepted.cookie, /Secure/);
      assert.match(accepted.cookie, /HttpOnly/);
      assert.equal(typeof JSON.parse(accepted.body).token, 'string');
      await f.close();
      f = await startFixture(
        fixtureSettings(),
        { certificateFile, privateKeyFile },
        undefined,
        true,
      );
      const h2Fixture = f,
        client = connect(f.origin, { ca, servername: 'localhost' });
      client.on('error', () => undefined);
      const h2 = (method: string, path: string, headers: Readonly<Record<string, string>>) =>
        new Promise<{ status: number; body: string; cookies: readonly string[]; csp: string }>(
          (resolve, reject) => {
            const stream = client.request({ ':method': method, ':path': path, ...headers });
            let body = '',
              status = 0,
              cookies: readonly string[] = [],
              csp = '';
            stream.setEncoding('utf8');
            stream.once('response', (response) => {
              status = Number(response[':status']);
              cookies = response['set-cookie'] ?? [];
              csp = String(response['content-security-policy'] ?? '');
            });
            stream.on('data', (chunk: string) => {
              body += chunk;
            });
            stream.once('error', reject);
            stream.once('end', () => resolve({ status, body, cookies, csp }));
            stream.end();
          },
        );
      try {
        const issued = await h2('GET', '/token', {
          cookie: '__Host-session=' + h2Fixture.alice.cookie,
          'x-session-hint': h2Fixture.alice.sessionId,
        });
        assert.equal(issued.status, 200);
        assert.match(issued.csp, /frame-ancestors 'none'/);
        const verified = await h2('POST', '/protected', {
          cookie:
            '__Host-session=' + h2Fixture.alice.cookie + '; ' + issued.cookies[0]!.split(';')[0],
          origin: 'https://app.fixture.invalid',
          'x-csrf-token': JSON.parse(issued.body).token,
        });
        assert.equal(verified.status, 200);
        assert.equal(h2Fixture.state.effects, 1);
      } finally {
        client.destroy();
      }
    } finally {
      try {
        await f?.close();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  },
);

test('Disconnect during an uncooperative state read never invokes the protected handler and shutdown reports retained work', async () => {
  const f = await startFixture();
  let release!: () => void;
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    f.state.holdRead = new Promise<void>((resolve) => {
      release = resolve;
    });
    const request = httpRequest(f.origin + '/protected', {
      method: 'POST',
      headers: {
        cookie:
          '__Host-session=' + f.alice.cookie + '; __Host-arkeniva-csrf=' + token.split('.')[1],
        origin: 'https://app.fixture.invalid',
        'x-csrf-token': token,
      },
    });
    request.on('error', () => undefined);
    const closed = new Promise<void>((resolve) => request.once('close', resolve));
    request.end();
    const deadline = performance.now() + 1000;
    while (f.state.authorizations < 2) {
      assert.ok(performance.now() < deadline);
      await setImmediate();
    }
    await setImmediate();
    request.destroy();
    await closed;
    await assert.rejects(f.app.stop({ timeoutMs: 20 }), (error) => error instanceof KitError);
    release();
    await setImmediate();
    assert.equal(f.state.effects, 0);
  } finally {
    release?.();
    await f.close();
  }
});
