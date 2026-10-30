// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createVerify, randomUUID } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { request } from 'node:https';
import { readFile } from 'node:fs/promises';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import { getVerifiedXml } from '@node-saml/node-saml/lib/xml.js';
import { DOMParser } from '@xmldom/xmldom';
import { memoryStore } from '../../packages/security-saml/dist-test/fixture.js';

/** These markers cover emitted protocol forms without choosing protocol identifiers. */
export function samlPrivacyValues(fixture) {
  return [
    ...Object.values(fixture).filter((value) => typeof value === 'string'),
    'synthetic-account',
    'untrusted-tenant-hint',
    'private-session-index',
    '127.0.0.1',
    'localhost',
    '"stringValue":"_',
    'SAMLRequest',
    'RelayState',
    'AuthnRequest',
  ];
}

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
      assert.ok(
        context.returnPath === '/app' ||
          (typeof fixture.sampleReturnPath === 'string' &&
            context.returnPath === fixture.sampleReturnPath),
      );
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

/** Verify the exact signed query bytes independently of the producing SAML SDK. */
export function verifySamlRedirect(transfer, fixture) {
  const settings = samlConnection(fixture);
  assert.equal(transfer.binding, 'redirect');
  assert.match(transfer.requestId, /^_[a-f0-9]{32,40}$/);
  assert.equal(typeof transfer.redirectUrl, 'string');
  assert.ok(Buffer.byteLength(transfer.redirectUrl) <= 32768);
  const url = new URL(transfer.redirectUrl);
  assert.equal(url.origin + url.pathname, 'https://idp.fixture.invalid/login');
  assert.ok(!url.username && !url.password && !url.hash);
  const fields = url.search.slice(1).split('&');
  assert.deepEqual(
    fields.map((value) => value.split('=')[0]),
    ['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'],
  );
  assert.equal(url.searchParams.get('SigAlg'), 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  const signature = Buffer.from(url.searchParams.get('Signature'), 'base64');
  assert.equal(signature.toString('base64'), url.searchParams.get('Signature'));
  assert.ok(
    createVerify('RSA-SHA256')
      .update(fields.slice(0, 3).join('&'))
      .verify(fixture.spCertificate, signature),
  );
  const compressed = Buffer.from(url.searchParams.get('SAMLRequest'), 'base64');
  assert.equal(compressed.toString('base64'), url.searchParams.get('SAMLRequest'));
  const xml = inflateRawSync(compressed, { maxOutputLength: 262144 }).toString('utf8'),
    root = new DOMParser().parseFromString(xml, 'application/xml').documentElement;
  assert.equal(root.localName, 'AuthnRequest');
  assert.equal(root.namespaceURI, 'urn:oasis:names:tc:SAML:2.0:protocol');
  assert.equal(root.getAttribute('Version'), '2.0');
  assert.equal(root.getAttribute('ID'), transfer.requestId);
  assert.equal(root.getAttribute('Destination'), 'https://idp.fixture.invalid/login');
  assert.equal(root.getAttribute('AssertionConsumerServiceURL'), settings.acsUrl);
  const issuers = root.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer');
  assert.equal(issuers.length, 1);
  assert.equal(issuers[0].textContent, settings.entityId);
  assert.equal(url.searchParams.get('RelayState'), transfer.requestId);
  if (transfer.expiresAt !== undefined) assert.ok(Date.parse(transfer.expiresAt) > Date.now());
  return {
    signedQueryBytes: Buffer.byteLength(fields.slice(0, 3).join('&')),
    requestXmlBytes: Buffer.byteLength(xml),
  };
}

const sampling = new WeakMap();

export function prepareSamlRedirect(service, fixture) {
  assert.equal(sampling.has(service), false);
  assert.equal(typeof fixture.sampleReturnPath, 'string');
  assert.match(fixture.sampleReturnPath, /^\/owned-saml-correlation-[a-f0-9]{32}$/);
  sampling.set(service, {
    fixture,
    ids: new Set(),
    verifiedRequests: 0,
    signedQueryBytes: 0,
    requestXmlBytes: 0,
  });
}

export function samlRedirectWorkload(service) {
  const state = sampling.get(service);
  assert.ok(state);
  return {
    async signedRedirectCreation() {
      assert.ok(state.verifiedRequests < 120 && state.ids.size < 128);
      const transfer = await service.beginLogin({ returnPath: state.fixture.sampleReturnPath }),
        verified = verifySamlRedirect(transfer, state.fixture);
      assert.equal(state.ids.has(transfer.requestId), false);
      state.ids.add(transfer.requestId);
      state.verifiedRequests++;
      state.signedQueryBytes += verified.signedQueryBytes;
      state.requestXmlBytes += verified.requestXmlBytes;
      return true;
    },
  };
}

export function completeSamlRedirect(service, { measure, records }) {
  if (!measure) {
    assert.equal(sampling.has(service), false);
    return { sampledCreations: 0, warmupCreations: 0, verifiedSignedCreations: 0 };
  }
  const state = sampling.get(service);
  try {
    assert.ok(state);
    assert.equal(records.length, 1);
    assert.equal(records[0].sampleCount, 100);
    assert.equal(records[0].warmupIterations, 20);
    assert.equal(state.verifiedRequests, 120);
    assert.equal(state.ids.size, 120);
    return {
      sampledCreations: 100,
      warmupCreations: 20,
      verifiedSignedCreations: 120,
      uniqueCorrelationsVerified: 120,
      signedQueryBytes: state.signedQueryBytes,
      requestXmlBytes: state.requestXmlBytes,
      retainedCorrelationIdentifiers: 0,
      actualMeasuredIdpRequests: 0,
      durableReplayStore: false,
    };
  } finally {
    state?.ids.clear();
    sampling.delete(service);
  }
}
