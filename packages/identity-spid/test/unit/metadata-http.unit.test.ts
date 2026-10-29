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
import { generateKeyPair, exportJWK, exportSPKI, SignJWT } from 'jose';

test(
  'Actual HTTPS federation documents use pinned paths, native TLS, bounded requests and signed status without forwarding credentials',
  { timeout: 20000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-eid-metadata-'));
    const certificate = join(directory, 'certificate.pem'),
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
      const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
      const issuer = 'https://anchor.example.test',
        subject = 'https://idp.example.test',
        now = Math.floor(Date.now() / 1000);
      const jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'root-public' }] };
      const sign = (claims: Record<string, unknown>, typ: string) =>
        new SignJWT({ iss: issuer, iat: now, ...claims })
          .setProtectedHeader({ alg: 'RS256', typ, kid: 'root-public' })
          .sign(pair.privateKey);
      const statement = await sign({ sub: subject, exp: now + 60, jwks }, 'entity-statement+jwt');
      const trustMark = await sign(
        {
          sub: subject,
          exp: now + 60,
          trust_mark_type: 'https://anchor.example.test/openid_provider',
        },
        'trust-mark+jwt',
      );
      const status = await sign(
        { trust_mark: trustMark, status: 'active' },
        'trust-mark-status-response+jwt',
      );
      const requests: {
        path: string;
        method: string;
        authorization?: string;
        cookie?: string;
        body: string;
      }[] = [];
      let rootConfiguration = '',
        delegation = '',
        federationStatus = '';
      const server = createServer(
        { key: await readFile(privateKey), cert: await readFile(certificate) },
        async (request, response) => {
          const chunks: Buffer[] = [];
          for await (const chunk of request) chunks.push(chunk);
          const path = request.url!;
          requests.push({
            path,
            method: request.method!,
            ...(request.headers.authorization
              ? { authorization: request.headers.authorization }
              : {}),
            ...(request.headers.cookie ? { cookie: request.headers.cookie } : {}),
            body: Buffer.concat(chunks).toString(),
          });
          if (path.startsWith('/federation-root/')) {
            if (path === '/federation-root/status') {
              response.setHeader('content-type', 'application/trust-mark-status-response+jwt');
              response.end(federationStatus);
              return;
            }
            response.setHeader('content-type', 'application/entity-statement+jwt');
            response.end(
              path.startsWith('/federation-root/fetch?') ? delegation : rootConfiguration,
            );
            return;
          }
          if (path.startsWith('/status')) {
            response.setHeader('content-type', 'application/trust-mark-status-response+jwt');
            response.end(status);
            return;
          }
          if (path === '/redirect') {
            response.writeHead(302, { location: '/not-approved' });
            response.end();
            return;
          }
          if (path === '/wrong-type') {
            response.setHeader('content-type', 'application/json');
            response.end('{}');
            return;
          }
          response.setHeader('content-type', 'application/entity-statement+jwt; charset=utf-8');
          if (path === '/utf8') {
            response.end(Buffer.from([0xc3, 0x28]));
            return;
          }
          if (path === '/oversized') {
            response.end('x'.repeat(4097));
            return;
          }
          if (path === '/slow') {
            setTimeout(() => response.end(statement), 250);
            return;
          }
          response.end(statement);
        },
      );
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const origin = `https://127.0.0.1:${address.port}`,
        federationRoot = origin + '/federation-root',
        federationLeaf = origin + '/federation-leaf';
      const federationType = origin + '/openid_provider/public/',
        federationMark = await sign(
          { iss: federationRoot, sub: federationLeaf, exp: now + 60, id: federationType },
          'trust-mark+jwt',
        );
      federationStatus = await sign(
        { iss: federationRoot, trust_mark: federationMark, status: 'active' },
        'trust-mark-status-response+jwt',
      );
      rootConfiguration = await sign(
        {
          iss: federationRoot,
          sub: federationRoot,
          exp: now + 60,
          jwks,
          constraints: { max_path_length: 0 },
          trust_mark_issuers: { [federationType]: [federationRoot] },
          metadata: {
            federation_entity: {
              federation_fetch_endpoint: federationRoot + '/fetch',
              federation_trust_mark_status_endpoint: federationRoot + '/status',
            },
          },
        },
        'entity-statement+jwt',
      );
      delegation = await sign(
        { iss: federationRoot, sub: federationLeaf, exp: now + 60, jwks },
        'entity-statement+jwt',
      );
      const leafConfiguration = await sign(
        {
          iss: federationLeaf,
          sub: federationLeaf,
          exp: now + 60,
          jwks,
          authority_hints: [federationRoot],
          metadata: { openid_provider: { issuer: federationLeaf } },
        },
        'entity-statement+jwt',
      );
      const deniedConfiguration = await sign(
        {
          iss: federationLeaf,
          sub: federationLeaf,
          exp: now + 60,
          jwks,
          authority_hints: [origin + '/not-approved'],
        },
        'entity-statement+jwt',
      );
      const membershipConfiguration = await sign(
        {
          iss: federationLeaf,
          sub: federationLeaf,
          exp: now + 60,
          jwks,
          authority_hints: [federationRoot],
          metadata: { openid_provider: { issuer: federationLeaf } },
          trust_marks: [{ id: federationType, trust_mark: federationMark }],
        },
        'entity-statement+jwt',
      );
      const child = fork(new URL('../fixtures/metadata-http-worker.js', import.meta.url), [], {
        execArgv: [],
        env: { ...process.env, NODE_EXTRA_CA_CERTS: certificate },
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      });
      let diagnostics = '';
      child.stderr?.on('data', (chunk: Buffer) => {
        if (diagnostics.length < 8192) diagnostics += chunk.toString();
      });
      try {
        const received = Promise.race([
          once(child, 'message'),
          once(child, 'exit').then(() => {
            throw new Error('The metadata worker exited before returning evidence: ' + diagnostics);
          }),
        ]);
        child.send({
          origin,
          issuer,
          subject,
          trustMark,
          leafConfiguration,
          deniedConfiguration,
          membershipConfiguration,
          anchor: {
            kid: 'root-public',
            issuer,
            publicKeyPem: await exportSPKI(pair.publicKey),
            validFrom: new Date(Date.now() - 60000).toISOString(),
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          },
        });
        const [result] = await received;
        assert.deepEqual(result, { ok: true });
        await once(child, 'exit');
        assert.ok(
          requests.every(
            (request) => request.authorization === undefined && request.cookie === undefined,
          ),
        );
        assert.equal(requests.filter((request) => request.path === '/statement').length, 1);
        assert.equal(
          requests.filter(
            (request) => request.path === '/not-approved' || request.path === '/cancel',
          ).length,
          0,
        );
        const fetched = requests.find((request) => request.path.startsWith('/fetch?'))!;
        assert.equal(
          new URL(fetched.path, 'https://fixture.invalid').searchParams.get('sub'),
          subject,
        );
        const checked = requests.find((request) => request.path === '/status')!;
        assert.equal(checked.method, 'POST');
        assert.equal(new URLSearchParams(checked.body).get('trust_mark'), trustMark);
        assert.equal(
          requests.filter((request) => request.path.startsWith('/federation-root/')).length,
          5,
        );
        assert.equal(
          requests.some((request) => request.path.startsWith('/not-approved/')),
          false,
        );
        const federationFetch = requests.find((request) =>
          request.path.startsWith('/federation-root/fetch?'),
        )!;
        assert.equal(new URL(federationFetch.path, origin).searchParams.get('sub'), federationLeaf);
      } finally {
        if (child.exitCode === null) {
          child.kill('SIGTERM');
          await once(child, 'exit');
        }
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
