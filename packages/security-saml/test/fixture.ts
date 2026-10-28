// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { signSamlPost } from '@node-saml/node-saml/lib/saml-post-signing.js';
import { SAML } from '@node-saml/node-saml';
import { createSamlService } from '../dist/index.js';
import type { SamlSettings, SecurityStateStore } from '../dist/index.js';

export const escapeXml = (value: string) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
/** Unit-only state implements atomic calls in one process; distributed acceptance uses actual PostgreSQL. */
export function memoryStore(): SecurityStateStore & { usage: 'test-only' } {
  const records = new Map<string, Readonly<Record<string, unknown>>>(),
    claims = new Map<string, number>();
  const key = (namespace: string, id: string) => JSON.stringify([namespace, id]);
  return {
    usage: 'test-only',
    async read(namespace, id) {
      const row = records.get(key(namespace, id));
      return row &&
        (row.expiresAt === undefined || Date.parse(row.expiresAt as string) > Date.now())
        ? row
        : null;
    },
    async compareAndSet(namespace, id, expected, next) {
      const name = key(namespace, id),
        before = records.get(name);
      if ((before?.version ?? null) !== expected) return { committed: false };
      const version = randomUUID();
      if (next === null) records.delete(name);
      else records.set(name, Object.freeze({ ...structuredClone(next), version }));
      return { committed: true, version };
    },
    async claimOnce(namespace, id, expiresAt) {
      const name = key(namespace, id);
      if ((claims.get(name) ?? 0) > Date.now()) return false;
      claims.set(name, Date.parse(expiresAt));
      return true;
    },
  };
}
export async function fixture(
  binding: 'redirect' | 'post' = 'redirect',
  store: SecurityStateStore = memoryStore(),
) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-'));
  await chmod(directory, 0o700);
  try {
    for (const name of ['idp', 'sp']) {
      await promisify(execFile)(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-days',
          '1',
          '-subj',
          '/CN=localhost',
          '-addext',
          'subjectAltName=DNS:localhost,IP:127.0.0.1',
          '-keyout',
          join(directory, name + '.key'),
          '-out',
          join(directory, name + '.pem'),
        ],
        { timeout: 10000 },
      );
      await chmod(join(directory, name + '.key'), 0o600);
      await chmod(join(directory, name + '.pem'), 0o400);
    }
    const idpKey = await readFile(join(directory, 'idp.key'), 'utf8'),
      idpCertificate = await readFile(join(directory, 'idp.pem'), 'utf8'),
      spKey = await readFile(join(directory, 'sp.key'), 'utf8'),
      spCertificate = await readFile(join(directory, 'sp.pem'), 'utf8');
    const certificate = idpCertificate.replace(/-----[^-]+-----|\s/g, '');
    let authorized = true;
    const settings: SamlSettings = {
      entityId: 'https://sp.fixture.invalid/entity',
      acsUrl: 'https://sp.fixture.invalid/acs',
      expectedAudience: 'https://sp.fixture.invalid/entity',
      environment: 'test',
      binding,
      trustedIdpMetadata: `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.fixture.invalid/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>${['HTTP-Redirect', 'HTTP-POST'].map((value) => `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:${value}" Location="https://idp.fixture.invalid/login"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:${value}" Location="https://idp.fixture.invalid/logout"/>`).join('')}</md:IDPSSODescriptor></md:EntityDescriptor>`,
      signingKeyRef: 'fixture/sp-key',
      signingCertificateRef: 'fixture/sp-certificate',
      secretProvider: {
        async get(reference) {
          if (!['fixture/sp-key', 'fixture/sp-certificate'].includes(reference))
            throw new Error('The fixture reference is unknown');
          return {
            bytes: Buffer.from(reference === 'fixture/sp-key' ? spKey : spCertificate),
            keyVersion: 'fixture',
          };
        },
      },
      replayStore: store,
      authority: {
        async require(action, subject) {
          if (!authorized || action !== 'saml.logout' || !subject)
            throw new Error('The fixture session is not authorized');
          return subject;
        },
      },
    };
    const sign = (xml: string, name: string) =>
      signSamlPost(
        xml,
        `/*[local-name(.)="${name}" and namespace-uri(.)="${name === 'Assertion' ? 'urn:oasis:names:tc:SAML:2.0:assertion' : 'urn:oasis:names:tc:SAML:2.0:protocol'}"]`,
        {
          privateKey: idpKey,
          publicCert: idpCertificate,
          signatureAlgorithm: 'sha256',
          digestAlgorithm: 'sha256',
        },
      );
    return {
      settings,
      service: createSamlService(settings),
      directory,
      authorize(value: boolean) {
        authorized = value;
      },
      response(
        id: string,
        changes: {
          audience?: string;
          destination?: string;
          subject?: string;
          expiresOffsetMs?: number;
          issuer?: string;
          signedAssertion?: boolean;
          transformAssertion?: (xml: string) => string;
          signedResponse?: boolean;
        } = {},
      ) {
        const now = new Date().toISOString(),
          expires = new Date(Date.now() + (changes.expiresOffsetMs ?? 240000)).toISOString(),
          before = new Date(Date.now() - 30000).toISOString(),
          issuer = changes.issuer ?? 'https://idp.fixture.invalid/entity',
          audience = changes.audience ?? settings.expectedAudience,
          destination = changes.destination ?? settings.acsUrl;
        let assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID().replaceAll('-', '')}" Version="2.0" IssueInstant="${now}"><saml:Issuer>${escapeXml(issuer)}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${escapeXml(changes.subject ?? 'synthetic-account')}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${id}" Recipient="${escapeXml(destination)}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${escapeXml(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="private-session-index" SessionNotOnOrAfter="${new Date(Date.now() + 3600000).toISOString()}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="displayName"><saml:AttributeValue>Fixture account</saml:AttributeValue></saml:Attribute><saml:Attribute Name="tenant_id"><saml:AttributeValue>untrusted-tenant-hint</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
        if (changes.transformAssertion) assertion = changes.transformAssertion(assertion);
        if (changes.signedAssertion !== false) assertion = sign(assertion, 'Assertion');
        let xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID().replaceAll('-', '')}" Version="2.0" IssueInstant="${now}" InResponseTo="${id}" Destination="${escapeXml(destination)}"><saml:Issuer>${escapeXml(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
        if (changes.signedResponse !== false) xml = sign(xml, 'Response');
        return Buffer.from(xml).toString('base64');
      },
      sign,
      async logoutResponse(id: string, success = true) {
        const idp = new SAML({
          issuer: 'https://idp.fixture.invalid/entity',
          callbackUrl: 'https://idp.fixture.invalid/acs',
          entryPoint: settings.acsUrl,
          idpCert: spCertificate,
          privateKey: idpKey,
          publicCert: idpCertificate,
          logoutUrl: settings.acsUrl,
          signatureAlgorithm: 'sha256',
          digestAlgorithm: 'sha256',
        });
        const profile = {
          issuer: settings.entityId,
          nameID: 'synthetic-account',
          nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
          ID: id,
        };
        if (binding === 'redirect')
          return new URL(
            await idp.getLogoutResponseUrlAsync(profile, id, {}, success),
          ).search.slice(1);
        const xml = idp._generateLogoutResponse(profile, success);
        return Buffer.from(sign(xml, 'LogoutResponse')).toString('base64');
      },
      close: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
