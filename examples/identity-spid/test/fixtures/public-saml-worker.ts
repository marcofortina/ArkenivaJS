// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer, request as httpsRequest } from 'node:https';
import { readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { generateKeyPairSync, verify, X509Certificate } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { Writable } from 'node:stream';
import { exportJWK, SignJWT } from 'jose';
import { createApplication } from '@arkenivajs/core';
import { HEALTH_PROBES } from '@arkenivajs/core/support';
import type { PluginHealthProbe } from '@arkenivajs/core/support';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityPlugin } from '@arkenivajs/security';
import type { ManagedAuthService } from '@arkenivajs/security';
import { cryptoPlugin } from '@arkenivajs/security-crypto';
import { spidPlugin, SPID_CAPABILITY } from '@arkenivajs/identity-spid';
import type { SpidService, ItalianEidPluginSettings } from '@arkenivajs/identity-spid';
import { transactionFixture } from './transactions.js';
import { samlMaterial } from './saml-material.js';
import {
  beginSamlBrowserLogin,
  consumeSamlBrowserLogin,
  clearSamlBrowserCookie,
} from '../../dist/saml-browser-flow.js';

export async function runPublicSaml(files: { certificate: string; privateKey: string }) {
  const base = await transactionFixture(),
    material = await samlMaterial(dirname(files.privateKey)),
    canonical = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    publicKey = {
      ...(await exportJWK(canonical.publicKey)),
      kid: 'canonical-public',
      alg: 'ES256',
      use: 'sig',
    },
    messages: string[] = [],
    destination = new Writable({
      write(chunk, _encoding, callback) {
        messages.push(String(chunk));
        callback();
      },
    });
  let origin = '',
    service: SpidService | undefined,
    health: PluginHealthProbe | undefined,
    paths = 0,
    mapped = 0,
    active = true,
    beginAllowed = true,
    consumeAllowed = true,
    wrongTenant = false,
    downgrade = false;
  const server = createServer(
    { key: await readFile(files.privateKey), cert: await readFile(files.certificate) },
    (request, response) => {
      void (async () => {
        const url = new URL(request.url!, origin);
        if (url.pathname === '/canonical-jwks') {
          response.setHeader('content-type', 'application/jwk-set+json');
          response.end(JSON.stringify({ keys: [publicKey] }));
          return;
        }
        if (url.pathname.startsWith('/registry/')) {
          paths++;
          const role = url.pathname.includes('/sp') ? 'sp' : 'idp';
          response.setHeader(
            'content-type',
            url.pathname.endsWith('-status') ? 'application/json' : 'application/samlmetadata+xml',
          );
          response.end(
            url.pathname.endsWith('-status')
              ? JSON.stringify(material.status(profile, role, role === 'idp' && !active))
              : documents[role],
          );
          return;
        }
        if (url.pathname === '/begin') {
          const result = await beginSamlBrowserLogin(
            service!,
            { returnPath: '/private', tenantId: 'tenant-A' },
            'spid-l2',
          );
          response.writeHead(result.status, result.headers);
          response.end(result.body);
          return;
        }
        if (url.pathname === '/login') {
          const signature = url.searchParams.get('Signature')!,
            signed = url.search
              .slice(1)
              .split('&')
              .filter((part) => !part.startsWith('Signature='))
              .join('&');
          assert.equal(
            verify(
              'RSA-SHA256',
              Buffer.from(signed),
              new X509Certificate(material.sp.certificate).publicKey,
              Buffer.from(signature, 'base64'),
            ),
            true,
          );
          const xml = inflateRawSync(
              Buffer.from(url.searchParams.get('SAMLRequest')!, 'base64'),
            ).toString(),
            id = /\bID="([^"]+)"/u.exec(xml)![1]!;
          assert.equal(url.searchParams.get('RelayState'), id);
          assert.ok(xml.includes('ForceAuthn="true"'));
          assert.ok(xml.includes('https://www.spid.gov.it/SpidL2'));
          response.setHeader('content-type', 'application/json');
          response.end(
            JSON.stringify({
              SAMLResponse: material.response(
                profile,
                id,
                downgrade ? 'https://www.spid.gov.it/SpidL1' : undefined,
              ),
              RelayState: id,
            }),
          );
          return;
        }
        if (url.pathname === '/acs') {
          let body = '';
          for await (const chunk of request) {
            body += String(chunk);
            if (Buffer.byteLength(body) > 65536)
              throw new Error('The disposable ACS form exceeds its bound');
          }
          const result = await consumeSamlBrowserLogin(
            service!,
            request.headers.cookie,
            {
              method: request.method!,
              url: origin + request.url!,
              contentType: request.headers['content-type'],
              body,
            },
            profile.redirectUri,
            profile.expectedIssuers[0]!,
          );
          response.writeHead(200, { ...result.headers, 'content-type': 'application/json' });
          response.end(JSON.stringify(result.identity));
          return;
        }
        response.writeHead(404);
        response.end();
      })().catch(() => {
        response.writeHead(401, {
          'cache-control': 'no-store',
          'set-cookie': clearSamlBrowserCookie,
        });
        response.end('Authentication denied');
      });
    },
  );
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  origin = `https://127.0.0.1:${address.port}`;
  const profile = material.profile(origin),
    documents = { sp: material.metadata(profile, 'sp'), idp: material.metadata(profile, 'idp') };
  const settings: ItalianEidPluginSettings = {
    ...base.settings,
    profiles: [profile],
    secretProvider: {
      ...{ usage: 'test-only' as const },
      async get(reference, options) {
        if (reference === profile.signingKeyRef)
          return {
            bytes: Buffer.from(material.sp.privateKey.export({ format: 'pem', type: 'pkcs8' })),
            keyVersion: 'fixture',
          };
        if (reference === profile.samlRegistration!.signingCertificateRef)
          return { bytes: Buffer.from(material.sp.certificate), keyVersion: 'fixture' };
        return base.settings.secretProvider.get(reference, options);
      },
    },
    policy: { maxConcurrent: 8, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
    identityMappers: {
      [profile.tenantMappingId]: {
        async map(input) {
          mapped++;
          assert.equal(input.subject, 'synthetic-upstream-account');
          assert.equal(input.assurance, 'spid-l2');
          const auth = app!.auth as ManagedAuthService,
            bearer = await new SignJWT({
              tenant_id: wrongTenant ? 'tenant-B' : 'tenant-A',
              scope: 'application:read',
            })
              .setProtectedHeader({ alg: 'ES256', kid: 'canonical-public', typ: 'JWT' })
              .setIssuer(origin + '/accounts')
              .setSubject('canonical-account')
              .setAudience('api://canonical-identity')
              .setIssuedAt()
              .setExpirationTime('2m')
              .sign(canonical.privateKey),
            identity = await auth.verifyBearer('Bearer ' + bearer),
            tenant = auth.tenantFrom(identity);
          return {
            issuer: identity.issuer,
            subject: identity.subject,
            tenant,
            assurance: input.assurance,
          };
        },
      },
    },
    authority: {
      async require(action, subject, context) {
        if (action === 'spid.begin_authentication') {
          if (!beginAllowed) throw new Error('Anonymous ceremony denied');
          return { issuer: profile.entityId, subject: 'ceremony-policy' };
        }
        assert.equal(action, 'spid.consume_authentication');
        assert.ok(subject);
        if (!consumeAllowed) throw new Error('Canonical authentication denied');
        assert.equal((app!.auth as ManagedAuthService).isVerifiedTenant(context.tenant), true);
        assert.equal(subject.tenant, context.tenant);
        return subject;
      },
    },
  };
  const app = await createApplication({
    service: { name: 'public-saml-fixture', version: '1.0.0', environment: 'test' },
    security: {
      issuer: origin + '/accounts',
      audience: 'api://canonical-identity',
      algorithms: ['ES256'],
    },
    plugins: [
      loggingPlugin({ destination }),
      securityPlugin({
        jwksUrl: origin + '/canonical-jwks',
        allowedJwksOrigins: [origin],
        allowInsecureLoopback: true,
      }),
      cryptoPlugin({
        secrets: base.settings.secretProvider,
        encryptionKeyRefs: base.settings.stateEncryptionKeyRefs!,
        signingKeyRefs: base.settings.stateMacKeyRefs!,
        policy: { maxConcurrent: 32, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 65536 },
      }),
      spidPlugin(settings),
      {
        id: 'saml-readiness-probe',
        version: '1.0.0',
        dependencies: ['spid'],
        capabilities: new Set(['health']),
        async init(context) {
          health = context
            .require<readonly PluginHealthProbe[]>(HEALTH_PROBES)
            .find((probe) => probe.name === 'plugin.spid');
          assert.ok(health);
          const early = context.require<SpidService>(SPID_CAPABILITY),
            before = paths;
          await assert.rejects(() => early.metadata(), { code: 'EK_LIFECYCLE_STATE' });
          assert.equal(paths, before);
        },
        close() {},
      },
    ],
  });
  async function browser(url: string, method = 'GET', cookie?: string, form?: string) {
    return new Promise<{
      status: number;
      headers: import('node:http').IncomingHttpHeaders;
      body: string;
    }>((resolve, reject) => {
      const request = httpsRequest(
        url,
        {
          method,
          headers: {
            ...(cookie ? { cookie } : {}),
            ...(form === undefined
              ? {}
              : {
                  'content-type': 'application/x-www-form-urlencoded',
                  'content-length': Buffer.byteLength(form),
                }),
          },
        },
        (response) => {
          let body = '';
          response.on('data', (chunk) => {
            body += String(chunk);
          });
          response.once('end', () =>
            resolve({ status: response.statusCode!, headers: response.headers, body }),
          );
        },
      );
      request.once('error', reject);
      request.end(form);
    });
  }
  try {
    await app.start();
    assert.ok(health);
    assert.equal(await health.check({ timeoutMs: 5000 }), true);
    base.state.storage = false;
    assert.equal(await health.check({ timeoutMs: 5000 }), false);
    base.state.storage = true;
    service = app.resolve<SpidService>(SPID_CAPABILITY).forProfile(profile.profileId);
    assert.equal(await service.metadata(), documents.sp);
    assert.equal((await service.verifyFederationTrust(documents.sp)).trusted, true);
    assert.equal((await service.verifyFederationTrust(documents.idp)).trusted, true);
    assert.equal(
      (
        await service.verifyFederationTrust(
          documents.idp.replace(
            'WantAuthnRequestsSigned="true"',
            'WantAuthnRequestsSigned="false"',
          ),
        )
      ).trusted,
      false,
    );
    async function ceremony() {
      const begin = await browser(origin + '/begin');
      assert.equal(begin.status, 303);
      assert.ok(begin.headers['set-cookie']![0]!.includes('SameSite=None'));
      const cookie = begin.headers['set-cookie']![0]!.split(';')[0]!,
        idp = await browser(begin.headers.location!);
      assert.equal(idp.status, 200);
      const form = new URLSearchParams(JSON.parse(idp.body) as Record<string, string>).toString();
      return { cookie, form };
    }
    const first = await ceremony(),
      before = paths,
      missing = await browser(profile.redirectUri, 'POST', undefined, first.form);
    assert.equal(missing.status, 401);
    assert.equal(paths, before);
    const good = await browser(profile.redirectUri, 'POST', first.cookie, first.form);
    assert.equal(good.status, 200);
    const identity = JSON.parse(good.body);
    assert.equal(identity.subject, 'canonical-account');
    assert.equal(identity.claims.tenant_id, 'tenant-A');
    assert.equal(identity.federationAssurance, 'spid-l2');
    assert.equal(identity.assurance, undefined);
    assert.equal(good.headers['set-cookie']![0], clearSamlBrowserCookie);
    assert.equal(
      (await browser(profile.redirectUri, 'POST', first.cookie, first.form)).status,
      401,
    );
    const left = await ceremony(),
      right = await ceremony();
    assert.equal((await browser(profile.redirectUri, 'POST', left.cookie, right.form)).status, 401);
    assert.equal(
      (await browser(profile.redirectUri, 'POST', right.cookie, right.form)).status,
      200,
    );
    const revoked = await ceremony();
    active = false;
    assert.equal(await health.check({ timeoutMs: 5000 }), false);
    assert.equal(
      (await browser(profile.redirectUri, 'POST', revoked.cookie, revoked.form)).status,
      401,
    );
    assert.equal((await service.verifyFederationTrust(documents.idp)).trusted, false);
    active = true;
    for (const kind of ['downgrade', 'tenant', 'authority', 'storage'] as const) {
      downgrade = kind === 'downgrade';
      const input = await ceremony();
      downgrade = false;
      wrongTenant = kind === 'tenant';
      consumeAllowed = kind !== 'authority';
      base.state.storage = kind !== 'storage';
      assert.equal(
        (await browser(profile.redirectUri, 'POST', input.cookie, input.form)).status,
        401,
      );
      wrongTenant = false;
      consumeAllowed = true;
      base.state.storage = true;
    }
    const denied = paths;
    beginAllowed = false;
    assert.equal((await browser(origin + '/begin')).status, 401);
    assert.equal(paths, denied);
    assert.ok(mapped >= 4);
    await app.stop();
    await assert.rejects(() => service!.metadata(), { code: 'EK_RESOURCE_CLOSED' });
    const logs = messages.join('');
    for (const sensitive of [
      'synthetic-upstream-account',
      'synthetic-transient-subject',
      'synthetic-private-session',
      first.cookie,
      first.form,
      'saml-private-signing',
    ])
      assert.equal(logs.includes(sensitive), false);
  } finally {
    await app.stop();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    await base.close();
  }
}

process.once('message', (files: { certificate: string; privateKey: string }) => {
  void runPublicSaml(files).then(
    () => {
      process.send?.({ ok: true, mode: 'public' });
      process.disconnect();
    },
    (error: unknown) => {
      process.send?.({
        ok: false,
        message: error instanceof Error ? error.message : 'The SAML public fixture failed',
      });
      process.disconnect();
    },
  );
});
