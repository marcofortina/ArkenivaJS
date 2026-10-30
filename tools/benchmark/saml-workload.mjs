// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { request } from 'node:https';
import { readFile } from 'node:fs/promises';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import { getVerifiedXml } from '@node-saml/node-saml/lib/xml.js';
import { DOMParser } from '@xmldom/xmldom';
import { memoryStore } from '../../packages/security-saml/dist-test/fixture.js';

export function samlConnection(fixture) {
  const url = new URL(fixture.endpoint);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && !url.username && !url.password && !url.search && !url.hash);
  assert.equal(url.pathname, '/response');
  assert.ok(fixture.caFile?.startsWith('/'));
  return JSON.parse(fixture.settings);
}

export function samlSettings(fixture) {
  const settings = samlConnection(fixture);
  return {
    ...settings,
    environment: 'test',
    binding: 'redirect',
    replayStore: memoryStore(),
    secretProvider: {
      usage: 'test-only',
      async get(reference) {
        assert.ok([settings.signingKeyRef, settings.signingCertificateRef].includes(reference));
        return {
          bytes: Buffer.from(
            reference === settings.signingKeyRef ? fixture.spKey : fixture.spCertificate,
          ),
          keyVersion: 'fixture',
        };
      },
    },
    authority: {
      usage: 'test-only',
      async require() {
        throw new Error('Logout is outside the SAML comparison authority');
      },
    },
  };
}

/** The selected SDK owns signatures, correlation cache and signed response validation. */
export function nativeSaml(fixture) {
  const settings = samlConnection(fixture);
  let nextId;
  const saml = new SAML({
    issuer: settings.entityId,
    callbackUrl: settings.acsUrl,
    entryPoint: 'https://idp.fixture.invalid/login',
    audience: settings.expectedAudience,
    idpIssuer: 'https://idp.fixture.invalid/entity',
    idpCert: fixture.idpCertificate,
    privateKey: fixture.spKey,
    publicCert: fixture.spCertificate,
    acceptedClockSkewMs: 0,
    maxAssertionAgeMs: 300000,
    requestIdExpirationPeriodMs: 300000,
    validateInResponseTo: ValidateInResponseTo.always,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    signMetadata: true,
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256',
    authnRequestBinding: 'HTTP-Redirect',
    generateUniqueId: () => nextId,
  });
  return {
    async beginLogin(context) {
      assert.equal(context.returnPath, '/app');
      nextId = '_' + randomUUID().replaceAll('-', '');
      const requestId = nextId,
        redirectUrl = await saml.getAuthorizeUrlAsync(requestId, undefined, {});
      return { binding: 'redirect', requestId, redirectUrl };
    },
    async consumeResponse(context, response) {
      assert.equal(context.relayState, context.inResponseTo);
      const result = await saml.validatePostResponseAsync({
        SAMLResponse: response,
        RelayState: context.relayState,
      });
      assert.equal(result.loggedOut, false);
      const profile = result.profile;
      return {
        subject: profile.nameID,
        issuer: profile.issuer,
        scopes: [],
        assurance: 'single-factor',
        attributes: {
          tenant_id: Array.isArray(profile.tenant_id) ? profile.tenant_id : [profile.tenant_id],
        },
      };
    },
    async createMetadata() {
      return saml.generateServiceProviderMetadata(null, fixture.spCertificate);
    },
  };
}

async function signedResponse(fixture, transfer, kind) {
  const ca = await readFile(fixture.caFile);
  return new Promise((done, reject) => {
    const outgoing = request(
      fixture.endpoint,
      {
        method: 'POST',
        ca,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        agent: false,
        signal: AbortSignal.timeout(4000),
        headers: { authorization: 'Bearer ' + fixture.bearer, 'content-type': 'application/json' },
      },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 524288)
            response.destroy(new Error('The owned SAML response exceeded its bound'));
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () => {
          try {
            assert.equal(response.statusCode, 200);
            done(JSON.parse(Buffer.concat(chunks).toString('utf8')).response);
          } catch (cause) {
            reject(cause);
          }
        });
      },
    );
    outgoing.once('error', reject);
    outgoing.end(
      JSON.stringify({ requestId: transfer.requestId, redirectUrl: transfer.redirectUrl, kind }),
    );
  });
}

export async function verifySaml(service, fixture) {
  const settings = samlConnection(fixture),
    metadata = await service.createMetadata();
  const root = new DOMParser().parseFromString(metadata, 'application/xml').documentElement;
  assert.equal(root.localName, 'EntityDescriptor');
  assert.equal(root.getAttribute('entityID'), settings.entityId);
  assert.ok(getVerifiedXml(metadata, root, [fixture.spCertificate]));
  for (const kind of ['healthy', 'tampered', 'wrong-audience']) {
    const transfer = await service.beginLogin({ returnPath: '/app' });
    assert.equal(transfer.binding, 'redirect');
    let response = await signedResponse(
      fixture,
      transfer,
      kind === 'wrong-audience' ? kind : 'healthy',
    );
    const context = { inResponseTo: transfer.requestId, relayState: transfer.requestId };
    if (kind === 'tampered')
      response = Buffer.from(
        Buffer.from(response, 'base64')
          .toString('utf8')
          .replaceAll('synthetic-account', 'forged-account'),
      ).toString('base64');
    if (kind !== 'healthy') {
      await assert.rejects(service.consumeResponse(context, response));
      continue;
    }
    const identity = await service.consumeResponse(context, response);
    assert.equal(identity.subject, 'synthetic-account');
    assert.equal(identity.issuer, 'https://idp.fixture.invalid/entity');
    assert.equal(identity.assurance, 'single-factor');
    assert.deepEqual([...identity.scopes], []);
    assert.deepEqual([...identity.attributes.tenant_id], ['untrusted-tenant-hint']);
    assert.equal(identity.claims?.tenant_id, undefined);
    await assert.rejects(service.consumeResponse(context, response));
  }
  return {
    signedMetadataVerified: true,
    actualSpSignaturesVerifiedByIdp: 3,
    signedIdentityVerified: true,
    replayRejected: true,
    tamperingAndWrongAudienceRejected: true,
    tenantHintNotTrusted: true,
  };
}
