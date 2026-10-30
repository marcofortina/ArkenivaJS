// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { createVerify, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { DOMParser } from '@xmldom/xmldom';
import { fixture as samlFixture } from '../../packages/security-saml/dist-test/fixture.js';

/** The existing signing fixture owns the IdP keys; an actual HTTPS endpoint verifies SP signatures first. */
export async function startSamlFixture() {
  const f = await samlFixture(),
    bearer = randomBytes(32).toString('base64url');
  let server;
  const tasks = new Set(),
    ids = new Set();
  const counts = { verifiedSignedRequests: 0, signedResponses: 0 };
  try {
    const [idpKey, idpCertificate, spKey, spCertificate] = await Promise.all(
      ['idp.key', 'idp.pem', 'sp.key', 'sp.pem'].map((name) =>
        readFile(join(f.directory, name), 'utf8'),
      ),
    );
    server = createServer(
      { key: idpKey, cert: idpCertificate, minVersion: 'TLSv1.2' },
      (request, response) => {
        const task = (async () => {
          assert.equal(request.method, 'POST');
          assert.equal(request.url, '/response');
          const actual = Buffer.from(request.headers.authorization ?? ''),
            expected = Buffer.from('Bearer ' + bearer);
          assert.equal(actual.length, expected.length);
          assert.ok(timingSafeEqual(actual, expected));
          const chunks = [];
          let size = 0;
          for await (const chunk of request) {
            size += chunk.length;
            assert.ok(size <= 32768);
            chunks.push(chunk);
          }
          const input = JSON.parse(Buffer.concat(chunks).toString('utf8')),
            url = new URL(input.redirectUrl);
          assert.equal(url.origin + url.pathname, 'https://idp.fixture.invalid/login');
          const fields = url.search.slice(1).split('&');
          assert.deepEqual(
            fields.map((value) => value.split('=')[0]),
            ['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'],
          );
          assert.equal(
            url.searchParams.get('SigAlg'),
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          );
          assert.ok(
            createVerify('RSA-SHA256')
              .update(fields.slice(0, 3).join('&'))
              .verify(spCertificate, Buffer.from(url.searchParams.get('Signature'), 'base64')),
          );
          const xml = inflateRawSync(Buffer.from(url.searchParams.get('SAMLRequest'), 'base64'), {
            maxOutputLength: 262144,
          }).toString('utf8');
          const root = new DOMParser().parseFromString(xml, 'application/xml').documentElement;
          assert.equal(root.localName, 'AuthnRequest');
          assert.equal(root.getAttribute('ID'), input.requestId);
          assert.equal(root.getAttribute('AssertionConsumerServiceURL'), f.settings.acsUrl);
          assert.equal(
            root.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0]
              .textContent,
            f.settings.entityId,
          );
          assert.equal(url.searchParams.get('RelayState'), input.requestId);
          assert.equal(ids.has(input.requestId), false);
          ids.add(input.requestId);
          assert.ok(['healthy', 'wrong-audience'].includes(input.kind));
          counts.verifiedSignedRequests++;
          const signed = f.response(
            input.requestId,
            input.kind === 'wrong-audience' ? { audience: 'https://foreign.invalid/entity' } : {},
          );
          counts.signedResponses++;
          response
            .writeHead(200, { 'content-type': 'application/json' })
            .end(JSON.stringify({ response: signed }));
        })()
          .catch(() => response.writeHead(400).end())
          .finally(() => tasks.delete(task));
        tasks.add(task);
      },
    );
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    return {
      fixture: {
        endpoint: 'https://127.0.0.1:' + server.address().port + '/response',
        caFile: join(f.directory, 'idp.pem'),
        bearer,
        settings: JSON.stringify({
          entityId: f.settings.entityId,
          acsUrl: f.settings.acsUrl,
          expectedAudience: f.settings.expectedAudience,
          trustedIdpMetadata: f.settings.trustedIdpMetadata,
          signingKeyRef: f.settings.signingKeyRef,
          signingCertificateRef: f.settings.signingCertificateRef,
        }),
        spKey,
        spCertificate,
        idpCertificate,
      },
      observations: () => ({ ...counts }),
      verify(profiles) {
        assert.equal(counts.verifiedSignedRequests, profiles * 3);
        assert.equal(counts.signedResponses, profiles * 3);
        return {
          actualVerifiedSignedRequests: counts.verifiedSignedRequests,
          actualSignedResponses: counts.signedResponses,
          releaseGate: false,
        };
      },
      async close() {
        try {
          server.closeAllConnections();
          await new Promise((done) => server.close(done));
          await Promise.allSettled([...tasks]);
        } finally {
          await f.close();
        }
      },
    };
  } catch (cause) {
    if (server?.listening) {
      server.closeAllConnections();
      await new Promise((done) => server.close(done));
    }
    await f.close();
    throw cause;
  }
}
