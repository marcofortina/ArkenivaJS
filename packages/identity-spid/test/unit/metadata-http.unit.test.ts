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
import { generateKeyPair, exportJWK, exportSPKI, exportPKCS8, SignJWT } from 'jose';
import { SignedXml } from 'xml-crypto';
import { X509Certificate } from 'node:crypto';
import { FederationHttp } from '../../dist/metadata-http.js';

test('Metadata transport construction rejects duplicate approvals, invalid environments and nonpositive budgets', () => {
  const metadata = {
      approvedMetadataEndpoints: ['https://metadata.example.test/document'],
      maxBytes: 4096,
    },
    policy = { maxConcurrent: 1, timeoutMs: 1000 };
  for (const value of [
    [],
    [...metadata.approvedMetadataEndpoints, ...metadata.approvedMetadataEndpoints],
    ['http://metadata.example.test/document'],
  ])
    assert.throws(
      () => new FederationHttp({ ...metadata, approvedMetadataEndpoints: value }, policy, 'test'),
      { code: 'EK_EID_PROFILE' },
    );
  for (const mutation of [
    { maxConcurrent: 0 },
    { timeoutMs: 0 },
    { maxOutputBytes: 0 },
    { maxInputBytes: 0 },
  ])
    assert.throws(() => new FederationHttp(metadata, { ...policy, ...mutation }, 'test'), {
      code: 'EK_EID_PROFILE',
    });
  assert.throws(() => new FederationHttp(metadata, policy, 'untrusted' as 'test'), {
    code: 'EK_EID_PROFILE',
  });
});

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
      const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
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
        accept?: string;
        cacheControl?: string;
        body: string;
      }[] = [];
      const canonical = 'http://www.w3.org/2001/10/xml-exc-c14n#',
        xmlSigner = new SignedXml({
          privateKey: await exportPKCS8(pair.privateKey),
          signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          canonicalizationAlgorithm: canonical,
        });
      xmlSigner.addReference({
        xpath: "/*[local-name(.)='EntityDescriptor']",
        transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', canonical],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      });
      const protocolCertificate = new X509Certificate(await readFile(certificate)).raw.toString(
        'base64',
      );
      xmlSigner.computeSignature(
        `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="native_metadata" entityID="${subject}" validUntil="${new Date(Date.now() + 60000).toISOString()}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${protocolCertificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>`,
        {
          prefix: 'ds',
          location: { reference: "/*[local-name(.)='EntityDescriptor']", action: 'prepend' },
        },
      );
      const samlMetadata = xmlSigner.getSignedXml();
      const registryStatus = JSON.stringify({
        entity_id: subject,
        _deleted: 'N',
        _disabled: 'N',
        delete_date: null,
        signing_certificate_x509: [protocolCertificate],
      });
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
            ...(request.headers.accept ? { accept: request.headers.accept } : {}),
            ...(request.headers['cache-control']
              ? { cacheControl: request.headers['cache-control'] }
              : {}),
            body: Buffer.concat(chunks).toString(),
          });
          if (path.startsWith('/registry/')) {
            if (path !== '/registry/missing-type')
              response.setHeader(
                'content-type',
                path === '/registry/wrong-type' ? 'text/xml' : 'application/json; charset=utf-8',
              );
            if (
              path === '/registry/withdrawn' ||
              (path === '/registry/cache' && requests.filter((r) => r.path === path).length > 1)
            )
              response.statusCode = 410;
            if (path === '/registry/slow') {
              setTimeout(() => response.end(registryStatus), 250);
              return;
            }
            response.end(
              path === '/registry/empty'
                ? ''
                : path === '/registry/utf8'
                  ? Buffer.from([0xc3, 0x28])
                  : path === '/registry/oversized'
                    ? 'x'.repeat(4097)
                    : path === '/registry/disabled'
                      ? registryStatus.replace('"_disabled":"N"', '"_disabled":"Y"')
                      : registryStatus,
            );
            return;
          }
          if (path.startsWith('/saml/')) {
            response.setHeader(
              'content-type',
              path === '/saml/application-xml'
                ? 'application/xml; charset=utf-8'
                : path === '/saml/text-xml'
                  ? 'text/xml'
                  : 'application/samlmetadata+xml',
            );
            if (
              path === '/saml/withdrawn' ||
              (path === '/saml/cache' && requests.filter((r) => r.path === path).length > 1)
            )
              response.statusCode = 410;
            if (path === '/saml/slow') {
              setTimeout(() => response.end(samlMetadata), 250);
              return;
            }
            response.end(
              path === '/saml/empty'
                ? ''
                : path === '/saml/utf8'
                  ? Buffer.from([0xc3, 0x28])
                  : path === '/saml/oversized'
                    ? 'x'.repeat(4097)
                    : path === '/saml/tampered'
                      ? samlMetadata.replace(
                          'protocolSupportEnumeration=',
                          'altered="true" protocolSupportEnumeration=',
                        )
                      : samlMetadata,
            );
            return;
          }
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
          if (path === '/missing-type') {
            response.end(statement);
            return;
          }
          response.setHeader('content-type', 'application/entity-statement+jwt; charset=utf-8');
          if (path === '/empty') {
            response.end();
            return;
          }
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
        const untrustedTls = new FederationHttp(
          {
            approvedMetadataEndpoints: [origin + '/saml/metadata', origin + '/registry/status'],
            maxBytes: 4096,
          },
          { maxConcurrent: 1, timeoutMs: 1000 },
          'test',
        );
        try {
          await assert.rejects(() => untrustedTls.samlMetadata(origin + '/saml/metadata'), {
            code: 'EK_EID_FEDERATION',
          });
          await assert.rejects(() => untrustedTls.samlRegistryStatus(origin + '/registry/status'), {
            code: 'EK_EID_FEDERATION',
          });
        } finally {
          await untrustedTls.close();
        }
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
          samlMetadata,
          registryStatus,
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
        assert.equal(requests.filter((request) => request.path === '/statement').length, 2);
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
        const xmlRequests = requests.filter((request) => request.path.startsWith('/saml/'));
        assert.ok(xmlRequests.length >= 8);
        assert.ok(
          xmlRequests.every(
            (request) =>
              request.method === 'GET' &&
              request.body === '' &&
              request.cacheControl === 'no-cache, no-store' &&
              request.accept === 'application/samlmetadata+xml, application/xml, text/xml',
          ),
        );
        assert.equal(requests.filter((request) => request.path === '/saml/cache').length, 2);
        const registryRequests = requests.filter((request) =>
          request.path.startsWith('/registry/'),
        );
        assert.ok(registryRequests.length >= 8);
        assert.ok(
          registryRequests.every(
            (request) =>
              request.method === 'GET' &&
              request.body === '' &&
              request.cacheControl === 'no-cache, no-store' &&
              request.accept === 'application/json',
          ),
        );
        assert.equal(requests.filter((request) => request.path === '/registry/cache').length, 2);
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
