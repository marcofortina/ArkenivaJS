// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { generateKeyPairSync, randomUUID, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { SignedXml } from 'xml-crypto';
import type { FederationProfileV1 } from '@arkenivajs/identity-spid';

const md = 'urn:oasis:names:tc:SAML:2.0:metadata',
  ds = 'http://www.w3.org/2000/09/xmldsig#',
  assertionNs = 'urn:oasis:names:tc:SAML:2.0:assertion',
  protocolNs = 'urn:oasis:names:tc:SAML:2.0:protocol';
const escape = (value: string) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
function signed(xml: string, name: string, key: KeyObject) {
  const signer = new SignedXml({
    privateKey: key,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    getKeyInfoContent: () => '',
  });
  signer.addReference({
    xpath: `/*[local-name(.)='${name}']`,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  signer.computeSignature(xml, { prefix: 'ds', location: { reference: '/*', action: 'prepend' } });
  return signer.getSignedXml();
}
/** Ephemeral keys belong to this disposable fixture; protocol signatures use pinned xml-crypto. */
export async function samlMaterial(directory: string) {
  const root = generateKeyPairSync('rsa', { modulusLength: 2048 });
  async function identity(name: string) {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 }),
      keyFile = join(directory, name + '-saml.key'),
      certFile = join(directory, name + '-saml.pem');
    await writeFile(keyFile, pair.privateKey.export({ format: 'pem', type: 'pkcs8' }), {
      mode: 0o600,
    });
    await writeFile(certFile, '', { mode: 0o600 });
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-key',
        keyFile,
        '-out',
        certFile,
        '-days',
        '1',
        '-subj',
        '/CN=Synthetic SAML fixture',
      ],
      { timeout: 10000 },
    );
    return { ...pair, certificate: await readFile(certFile, 'utf8') };
  }
  const sp = await identity('sp'),
    idp = await identity('idp');
  return {
    sp,
    idp,
    profile(origin: string): FederationProfileV1 {
      const entityId = origin + '/sp',
        issuer = origin + '/idp',
        sources = {
          [entityId]: {
            metadataEndpoint: origin + '/registry/sp',
            statusEndpoint: origin + '/registry/sp-status',
          },
          [issuer]: {
            metadataEndpoint: origin + '/registry/idp',
            statusEndpoint: origin + '/registry/idp-status',
          },
        };
      return {
        schemaVersion: '1.0.0',
        profileId: 'saml-profile',
        system: 'spid',
        protocol: 'saml2',
        entityId,
        redirectUri: origin + '/acs',
        signingKeyRef: 'saml-private-signing',
        expectedIssuers: [issuer],
        allowedAssurance: ['spid-l2'],
        metadata: {
          trustAnchors: [
            {
              kid: 'root-public',
              issuer: origin + '/registry',
              publicKeyPem: root.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
              validFrom: new Date(Date.now() - 60000).toISOString(),
              expiresAt: new Date(Date.now() + 3600000).toISOString(),
            },
          ],
          approvedMetadataEndpoints: Object.values(sources).flatMap((s) => [
            s.metadataEndpoint,
            s.statusEndpoint,
          ]),
          maxBytes: 65536,
          refreshIntervalSeconds: 60,
          maxChainDepth: 4,
          revocation: 'mandatory',
          stalePolicy: 'reject',
        },
        subjectClaim: 'fiscalNumber',
        tenantMappingId: 'approved-accounts',
        identityMappingVersion: '1',
        sessionTtlSeconds: 300,
        samlRegistration: {
          signingCertificateRef: 'saml-public-certificate',
          registrySources: sources,
        },
      };
    },
    metadata(profile: FederationProfileV1, role: 'sp' | 'idp') {
      const entity = role === 'sp' ? profile.entityId : profile.expectedIssuers[0]!,
        cert = new X509Certificate(role === 'sp' ? sp.certificate : idp.certificate).raw.toString(
          'base64',
        ),
        descriptor = role === 'sp' ? 'SPSSODescriptor' : 'IDPSSODescriptor',
        signing = role === 'sp' ? 'AuthnRequestsSigned' : 'WantAuthnRequestsSigned',
        service =
          role === 'sp'
            ? `<md:AssertionConsumerService index="0" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${profile.redirectUri}"/>`
            : `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${new URL('/login', profile.entityId).href}"/>`,
        xml = `<md:EntityDescriptor xmlns:md="${md}" xmlns:ds="${ds}" ID="_${randomUUID().replaceAll('-', '')}" entityID="${entity}" validUntil="${new Date(Date.now() + 120000).toISOString()}"><md:${descriptor} protocolSupportEnumeration="${protocolNs}" ${signing}="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>${service}</md:${descriptor}></md:EntityDescriptor>`;
      return signed(xml, 'EntityDescriptor', root.privateKey);
    },
    status(profile: FederationProfileV1, role: 'sp' | 'idp', disabled: boolean) {
      return {
        entity_id: role === 'sp' ? profile.entityId : profile.expectedIssuers[0]!,
        _deleted: 'N',
        _disabled: disabled ? 'Y' : 'N',
        delete_date: null,
        signing_certificate_x509: [
          new X509Certificate(role === 'sp' ? sp.certificate : idp.certificate).raw.toString(
            'base64',
          ),
        ],
      };
    },
    response(
      profile: FederationProfileV1,
      request: string,
      context = 'https://www.spid.gov.it/SpidL2',
    ) {
      const issuer = profile.expectedIssuers[0]!,
        now = new Date().toISOString(),
        expiry = new Date(Date.now() + 60000).toISOString(),
        before = new Date(Date.now() - 30000).toISOString(),
        assertion = `<saml:Assertion xmlns:saml="${assertionNs}" ID="_${randomUUID().replaceAll('-', '')}" Version="2.0" IssueInstant="${now}"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="${issuer}" SPNameQualifier="${profile.entityId}">synthetic-transient-subject</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${escape(request)}" Recipient="${profile.redirectUri}" NotOnOrAfter="${expiry}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${expiry}"><saml:AudienceRestriction><saml:Audience>${profile.entityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}" ${context === 'https://www.spid.gov.it/SpidL1' ? 'SessionIndex="synthetic-private-session" ' : ''}SessionNotOnOrAfter="${expiry}"><saml:AuthnContext><saml:AuthnContextClassRef>${escape(context)}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="fiscalNumber"><saml:AttributeValue>synthetic-upstream-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name="tenant_id"><saml:AttributeValue>untrusted-tenant</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`,
        response = `<samlp:Response xmlns:samlp="${protocolNs}" xmlns:saml="${assertionNs}" ID="_${randomUUID().replaceAll('-', '')}" Version="2.0" IssueInstant="${now}" InResponseTo="${escape(request)}" Destination="${profile.redirectUri}"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${signed(assertion, 'Assertion', idp.privateKey)}</samlp:Response>`;
      return Buffer.from(signed(response, 'Response', idp.privateKey)).toString('base64');
    },
  };
}
