// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignedXml } from 'xml-crypto';
import type { FederationProfileV1 } from '../../dist/index.js';

export const md = 'urn:oasis:names:tc:SAML:2.0:metadata',
  protocol = 'urn:oasis:names:tc:SAML:2.0:protocol',
  c14n = 'http://www.w3.org/2001/10/xml-exc-c14n#',
  enveloped = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
export const root = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  foreign = generateKeyPairSync('rsa', { modulusLength: 2048 });
export function profile(): FederationProfileV1 {
  return {
    schemaVersion: '1.0.0',
    profileId: 'saml-profile',
    system: 'spid',
    protocol: 'saml2',
    entityId: 'https://application.example.test',
    redirectUri: 'https://application.example.test/acs',
    signingKeyRef: 'application-signing-key',
    expectedIssuers: ['https://idp.example.test'],
    allowedAssurance: ['spid-l2'],
    metadata: {
      trustAnchors: [
        {
          kid: 'root-pin',
          issuer: 'https://registry.example.test',
          publicKeyPem: root.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
          validFrom: new Date(Date.now() - 60000).toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      ],
      approvedMetadataEndpoints: ['https://registry.example.test/idp'],
      maxBytes: 65536,
      refreshIntervalSeconds: 60,
      maxChainDepth: 4,
      revocation: 'mandatory',
      stalePolicy: 'reject',
    },
    subjectClaim: 'NameID',
    tenantMappingId: 'approved-accounts',
    identityMappingVersion: '1',
    sessionTtlSeconds: 300,
    samlRegistration: { signingCertificateRef: 'application-certificate' },
  };
}
export function signed(
  options: {
    role?: 'idp' | 'sp';
    entity?: string;
    extra?: string;
    expiry?: string | null;
    algorithm?: string;
    digest?: string;
    key?: typeof root.privateKey;
    descriptorAttributes?: string;
    descriptorContent?: string;
  } = {},
) {
  const role = options.role ?? 'idp',
    issuer =
      options.entity ??
      (role === 'idp' ? 'https://idp.example.test' : 'https://application.example.test'),
    expiry =
      options.expiry === null
        ? ''
        : ` validUntil="${options.expiry ?? new Date(Date.now() + 60000).toISOString()}"`,
    descriptor = role === 'idp' ? 'IDPSSODescriptor' : 'SPSSODescriptor',
    xml = `<md:EntityDescriptor xmlns:md="${md}" ID="metadata_root" entityID="${issuer}"${expiry}><md:${descriptor} protocolSupportEnumeration="${protocol}"${options.descriptorAttributes ?? ''}>${options.descriptorContent ?? ''}</md:${descriptor}>${options.extra ?? ''}</md:EntityDescriptor>`,
    signer = new SignedXml({
      privateKey: options.key ?? root.privateKey,
      signatureAlgorithm: options.algorithm ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: c14n,
      getKeyInfoContent: () => '<KeyName>untrusted-root-claim</KeyName>',
    });
  signer.addReference({
    xpath: `/*[local-name(.)='EntityDescriptor' and namespace-uri(.)='${md}']`,
    transforms: [enveloped, c14n],
    digestAlgorithm: options.digest ?? 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  signer.computeSignature(xml, {
    prefix: 'ds',
    location: { reference: "/*[local-name(.)='EntityDescriptor']", action: 'prepend' },
  });
  return signer.getSignedXml();
}

async function prepareRegistry() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-registry-'));
  try {
    async function certificate(name: string, key: typeof root.privateKey) {
      const keyPath = join(directory, name + '-key.pem'),
        certPath = join(directory, name + '-cert.pem');
      await writeFile(keyPath, key.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
      await writeFile(certPath, '', { mode: 0o600 });
      await promisify(execFile)(
        'openssl',
        [
          'req',
          '-x509',
          '-key',
          keyPath,
          '-out',
          certPath,
          '-days',
          '1',
          '-subj',
          '/CN=Registry Public Fixture',
        ],
        { timeout: 10000 },
      );
      const pem = await readFile(certPath, 'utf8');
      return { pem, encoded: new X509Certificate(pem).raw.toString('base64') };
    }
    const first = await certificate('first', foreign.privateKey),
      second = await certificate('second', root.privateKey),
      ec = await certificate(
        'ec',
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey,
      ),
      weak = await certificate(
        'weak',
        generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey,
      ),
      p = profile(),
      entity = p.entityId,
      issuer = p.expectedIssuers[0]!,
      registrySources = {
        [entity]: {
          metadataEndpoint: 'https://registry.example.test/sp',
          statusEndpoint: 'https://registry.example.test/sp-status',
        },
        [issuer]: {
          metadataEndpoint: 'https://registry.example.test/idp',
          statusEndpoint: 'https://registry.example.test/idp-status',
        },
      },
      configured: FederationProfileV1 = {
        ...p,
        metadata: {
          ...p.metadata,
          approvedMetadataEndpoints: Object.values(registrySources).flatMap((source) => [
            source.metadataEndpoint,
            source.statusEndpoint,
          ]),
        },
        samlRegistration: { ...p.samlRegistration!, registrySources },
      },
      descriptor = (encoded = first.encoded) =>
        `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${encoded}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
      consumer = `<md:AssertionConsumerService index="0" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${p.redirectUri}"/>`,
      xml = (role: 'idp' | 'sp', options: Parameters<typeof signed>[0] = {}) =>
        signed({
          role,
          descriptorAttributes:
            role === 'sp' ? ' AuthnRequestsSigned="true"' : ' WantAuthnRequestsSigned="true"',
          descriptorContent:
            descriptor() +
            (role === 'sp'
              ? consumer
              : '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/login"/>'),
          ...options,
        }),
      status = (role: 'idp' | 'sp', changes: Record<string, unknown> = {}) =>
        JSON.stringify({
          entity_id: role === 'sp' ? entity : issuer,
          _deleted: 'N',
          _disabled: 'N',
          delete_date: null,
          signing_certificate_x509: [first.encoded],
          ...changes,
        });
    return {
      directory,
      profile: configured,
      entity,
      issuer,
      first,
      second,
      ec,
      weak,
      descriptor,
      consumer,
      xml,
      status,
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
let registryData: ReturnType<typeof prepareRegistry> | undefined;
export const registry = () => (registryData ??= prepareRegistry());
export async function closeRegistryFixture(): Promise<void> {
  if (registryData) await rm((await registryData).directory, { recursive: true, force: true });
}
