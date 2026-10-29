// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { SignedXml } from 'xml-crypto';
import type { FederatedLogin } from '../../dist/index.js';
import type { samlLoginFixture } from './saml-login.js';
import { foreign, root, c14n, enveloped } from './saml-metadata.js';

const assertionNamespace = 'urn:oasis:names:tc:SAML:2.0:assertion',
  protocolNamespace = 'urn:oasis:names:tc:SAML:2.0:protocol';
const escape = (value: string) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');

/** Generate actual independently signed protocol elements using the existing native XML library. */
export function samlResponse(
  fixture: Awaited<ReturnType<typeof samlLoginFixture>>,
  login: FederatedLogin,
  changes: {
    issuer?: string;
    audience?: string;
    recipient?: string;
    inResponseTo?: string;
    subject?: string;
    context?: string;
    nameIDFormat?: string;
    nameQualifier?: string;
    spNameQualifier?: string;
    expiresAt?: string;
    signedAssertion?: boolean;
    signedResponse?: boolean;
    foreignKey?: boolean;
    attributes?: Readonly<Record<string, readonly string[]>>;
  } = {},
) {
  const target = new URL(login.redirectUrl),
    request = inflateRawSync(
      Buffer.from(target.searchParams.get('SAMLRequest')!, 'base64'),
    ).toString(),
    requestId = /\bID="([^"]+)"/u.exec(request)![1]!,
    issuer = changes.issuer ?? fixture.input.issuer,
    audience = changes.audience ?? fixture.document.profile.entityId,
    recipient = changes.recipient ?? fixture.document.profile.redirectUri,
    now = new Date().toISOString(),
    expires = changes.expiresAt ?? new Date(Date.now() + 60000).toISOString(),
    before = new Date(Date.now() - 30000).toISOString(),
    correlation = changes.inResponseTo ?? requestId,
    sign = (xml: string, name: string) => {
      const signer = new SignedXml({
        privateKey: changes.foreignKey ? root.privateKey : foreign.privateKey,
        signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        canonicalizationAlgorithm: c14n,
        getKeyInfoContent: () => '',
      });
      signer.addReference({
        xpath: `/*[local-name(.)='${name}']`,
        transforms: [enveloped, c14n],
        digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      });
      signer.computeSignature(xml, {
        prefix: 'ds',
        location: { reference: "/*/*[local-name(.)='Issuer']", action: 'after' },
      });
      return signer.getSignedXml();
    },
    attributes = changes.attributes ?? {
      name: ['Fixture Member'],
      fiscalNumber: ['synthetic-account'],
      tenant_id: ['untrusted-tenant'],
    };
  let assertion = `<saml:Assertion xmlns:saml="${assertionNamespace}" ID="_${randomUUID().replaceAll('-', '')}" Version="2.0" IssueInstant="${now}"><saml:Issuer>${escape(issuer)}</saml:Issuer><saml:Subject><saml:NameID Format="${escape(changes.nameIDFormat ?? 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient')}" NameQualifier="${escape(changes.nameQualifier ?? issuer)}" SPNameQualifier="${escape(changes.spNameQualifier ?? audience)}">${escape(changes.subject ?? 'synthetic-transient-subject')}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${escape(correlation)}" Recipient="${escape(recipient)}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${escape(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" SessionIndex="synthetic-session" SessionNotOnOrAfter="${expires}"><saml:AuthnContext><saml:AuthnContextClassRef>${escape(changes.context ?? 'https://www.spid.gov.it/SpidL2')}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>${Object.entries(
    attributes,
  )
    .map(
      ([name, values]) =>
        `<saml:Attribute Name="${escape(name)}">${values.map((value) => `<saml:AttributeValue>${escape(value)}</saml:AttributeValue>`).join('')}</saml:Attribute>`,
    )
    .join('')}</saml:AttributeStatement></saml:Assertion>`;
  if (changes.signedAssertion !== false) assertion = sign(assertion, 'Assertion');
  let xml = `<samlp:Response xmlns:samlp="${protocolNamespace}" xmlns:saml="${assertionNamespace}" ID="_${randomUUID().replaceAll('-', '')}" Version="2.0" IssueInstant="${now}" InResponseTo="${escape(correlation)}" Destination="${escape(recipient)}"><saml:Issuer>${escape(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  if (changes.signedResponse !== false) xml = sign(xml, 'Response');
  return {
    transactionId: login.transactionId,
    issuer: fixture.input.issuer,
    relayState: requestId,
    samlResponse: Buffer.from(xml).toString('base64'),
  };
}
