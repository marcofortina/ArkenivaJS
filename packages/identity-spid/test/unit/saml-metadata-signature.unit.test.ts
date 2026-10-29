// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignedXml } from 'xml-crypto';
import { verifySamlMetadataSignature } from '../../dist/saml-metadata-signature.js';
import type { FederationProfileV1 } from '../../dist/index.js';

const md = 'urn:oasis:names:tc:SAML:2.0:metadata',
  protocol = 'urn:oasis:names:tc:SAML:2.0:protocol',
  c14n = 'http://www.w3.org/2001/10/xml-exc-c14n#',
  enveloped = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const root = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  foreign = generateKeyPairSync('rsa', { modulusLength: 2048 });
function profile(): FederationProfileV1 {
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
function signed(
  options: {
    role?: 'idp' | 'sp';
    entity?: string;
    extra?: string;
    expiry?: string | null;
    algorithm?: string;
    digest?: string;
    key?: typeof root.privateKey;
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
    xml = `<md:EntityDescriptor xmlns:md="${md}" ID="metadata_root" entityID="${issuer}"${expiry}><md:${descriptor} protocolSupportEnumeration="${protocol}"/>${options.extra ?? ''}</md:EntityDescriptor>`,
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

test('Native SAML metadata signatures bind issuer, role and verified reference bytes without granting current membership', () => {
  for (const role of ['idp', 'sp'] as const) {
    const result = verifySamlMetadataSignature(signed({ role }), profile(), role);
    assert.equal(
      result.issuer,
      role === 'idp' ? 'https://idp.example.test' : 'https://application.example.test',
    );
    assert.equal(result.signerKid, 'root-pin');
    assert.equal(result.role, role);
    assert.ok(result.validUntil);
    assert.ok(result.verifiedXml.includes('EntityDescriptor'));
    assert.equal(result.verifiedXml.includes('SignatureValue'), false);
    assert.equal('trusted' in result, false);
    assert.ok(Object.isFrozen(result));
  }
  const withoutExpiry = verifySamlMetadataSignature(signed({ expiry: null }), profile(), 'idp');
  assert.equal(
    withoutExpiry.validUntil,
    undefined,
    'An absent metadata expiry is not replaced with a fabricated freshness guarantee',
  );
});

test('Only current explicitly pinned RSA roots verify; embedded identity claims and wrong signing keys cannot authorize metadata', () => {
  const xml = signed(),
    p = profile(),
    pin = p.metadata.trustAnchors[0]!;
  const rollover = {
    ...p,
    metadata: {
      ...p.metadata,
      trustAnchors: [
        {
          ...pin,
          kid: 'other-pin',
          publicKeyPem: foreign.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        },
        pin,
      ],
    },
  };
  assert.equal(verifySamlMetadataSignature(xml, rollover, 'idp').signerKid, 'root-pin');
  for (const input of [
    signed({ key: foreign.privateKey }),
    xml.replace('protocolSupportEnumeration=', 'altered="true" protocolSupportEnumeration='),
  ])
    assert.throws(() => verifySamlMetadataSignature(input, p, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  const withdrawn = {
    ...rollover,
    metadata: {
      ...rollover.metadata,
      trustAnchors: rollover.metadata.trustAnchors.map((item) =>
        item.kid === 'root-pin'
          ? { ...item, expiresAt: new Date(Date.now() - 1).toISOString() }
          : item,
      ),
    },
  };
  assert.throws(() => verifySamlMetadataSignature(xml, withdrawn, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
  const notYetActive = {
      ...rollover,
      metadata: {
        ...rollover.metadata,
        trustAnchors: rollover.metadata.trustAnchors.map((item) =>
          item.kid === 'root-pin'
            ? { ...item, validFrom: new Date(Date.now() + 60000).toISOString() }
            : item,
        ),
      },
    },
    ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      .publicKey.export({ format: 'pem', type: 'spki' })
      .toString(),
    wrongFamily = {
      ...p,
      metadata: { ...p.metadata, trustAnchors: [{ ...pin, publicKeyPem: ec }] },
    };
  for (const configured of [notYetActive, wrongFamily])
    assert.throws(() => verifySamlMetadataSignature(xml, configured, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
});

test('Unknown metadata roles cannot select another parser or execute coercion hooks', () => {
  let calls = 0;
  for (const role of [
    'provider',
    {
      [Symbol.toPrimitive]() {
        calls++;
        return 'idp';
      },
    },
  ])
    assert.throws(() => verifySamlMetadataSignature(signed(), profile(), role as never), {
      code: 'EK_EID_PROFILE',
    });
  assert.equal(calls, 0);
});

test('Pinned X.509 roots and native RSA SHA512 preserve independently bounded root validity', async (context) => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-metadata-root-')),
    keyPath = join(directory, 'key.pem'),
    certPath = join(directory, 'certificate.pem');
  try {
    await writeFile(keyPath, root.privateKey.export({ format: 'pem', type: 'pkcs8' }), {
      mode: 0o600,
    });
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
        '/CN=Pinned Metadata Fixture',
      ],
      { timeout: 10000 },
    );
    const p = profile(),
      cert = await readFile(certPath, 'utf8'),
      configured = {
        ...p,
        metadata: {
          ...p.metadata,
          trustAnchors: [{ ...p.metadata.trustAnchors[0]!, publicKeyPem: cert }],
        },
      },
      result = verifySamlMetadataSignature(
        signed({
          algorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          digest: 'http://www.w3.org/2001/04/xmlenc#sha512',
        }),
        configured,
        'idp',
      );
    assert.equal(result.signerKid, 'root-pin');
    assert.ok(Date.parse(result.trustAnchorExpiresAt) > Date.now());
    assert.ok(
      Date.parse(result.trustAnchorExpiresAt) <=
        Date.parse(configured.metadata.trustAnchors[0]!.expiresAt),
    );
    const certificate = new X509Certificate(cert),
      expiry = Date.parse(certificate.validTo),
      wide = {
        ...configured,
        metadata: {
          ...configured.metadata,
          trustAnchors: [
            {
              ...configured.metadata.trustAnchors[0]!,
              expiresAt: new Date(expiry + 3600000).toISOString(),
            },
          ],
        },
      },
      document = signed({ expiry: new Date(expiry + 7200000).toISOString() });
    for (const now of [Date.parse(certificate.validFrom) - 1, expiry + 1]) {
      context.mock.method(Date, 'now', () => now);
      assert.throws(() => verifySamlMetadataSignature(document, wide, 'idp'), {
        code: 'EK_EID_FEDERATION',
      });
      context.mock.restoreAll();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('A root expiring during actual native signature verification cannot produce reusable evidence', (context) => {
  const p = profile(),
    expiry = Date.now() + 10000,
    configuration = {
      ...p,
      metadata: {
        ...p.metadata,
        trustAnchors: [
          { ...p.metadata.trustAnchors[0]!, expiresAt: new Date(expiry).toISOString() },
        ],
      },
    },
    xml = signed({ expiry: new Date(expiry + 3600000).toISOString() }),
    native = SignedXml.prototype.checkSignature;
  let now = Date.now(),
    verified = 0;
  context.mock.method(Date, 'now', () => now);
  context.mock.method(
    SignedXml.prototype,
    'checkSignature',
    function (this: SignedXml, input: string) {
      const result = Reflect.apply(native, this, [input]);
      assert.equal(result, true, 'The signature itself must remain natively valid');
      verified++;
      now = expiry + 1;
      return result;
    },
  );
  assert.throws(() => verifySamlMetadataSignature(xml, configuration, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
  assert.equal(verified, 1);
});

test('Metadata expiring during actual native verification cannot authorize a fresh result', (context) => {
  const configuration = profile(),
    expiry = Date.now() + 10000,
    xml = signed({ expiry: new Date(expiry).toISOString() }),
    native = SignedXml.prototype.checkSignature;
  let now = Date.now(),
    verified = 0;
  context.mock.method(Date, 'now', () => now);
  context.mock.method(
    SignedXml.prototype,
    'checkSignature',
    function (this: SignedXml, input: string) {
      const result = Reflect.apply(native, this, [input]);
      assert.equal(result, true);
      verified++;
      now = expiry + 1;
      return result;
    },
  );
  assert.throws(() => verifySamlMetadataSignature(xml, configuration, 'idp'), {
    code: 'EK_EID_FEDERATION',
  });
  assert.equal(verified, 1);
});

test('Native verification cannot authorize missing or differently bound authenticated reference evidence', (context) => {
  const xml = signed(),
    configuration = profile(),
    native = SignedXml.prototype.getSignedReferences;
  let substitute: 'missing' | 'identity' | 'id' = 'missing',
    calls = 0;
  context.mock.method(SignedXml.prototype, 'getSignedReferences', function (this: SignedXml) {
    const references = Reflect.apply(native, this, []) as string[];
    assert.equal(
      references.length,
      1,
      'The actual signature must authenticate exactly one reference',
    );
    calls++;
    if (substitute === 'missing') return [];
    return [
      references[0]!.replace(
        substitute === 'identity' ? 'https://idp.example.test' : 'metadata_root',
        substitute === 'identity' ? 'https://foreign.example.test' : 'different_root',
      ),
    ];
  });
  for (substitute of ['missing', 'identity', 'id'] as const)
    assert.throws(() => verifySamlMetadataSignature(xml, configuration, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  assert.equal(calls, 3);
});

test('Valid signatures cannot bypass expiry, issuer, role, ID, algorithm and wrapping policy', () => {
  const p = profile();
  for (const xml of [
    signed({ entity: 'https://foreign.example.test' }),
    signed({ role: 'sp' }),
    signed({ expiry: new Date(Date.now() - 1).toISOString() }),
    signed({ expiry: '2026-02-30T00:00:00Z' }),
    signed({ expiry: '' }),
    signed({ expiry: '2999-12-31T00:00:00' }),
    signed({ algorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' }),
    signed({ digest: 'http://www.w3.org/2000/09/xmldsig#sha1' }),
    signed({ extra: `<md:SPSSODescriptor protocolSupportEnumeration="${protocol}"/>` }),
    signed({ extra: '<md:Extensions><other ID="metadata_root"/></md:Extensions>' }),
    signed({ extra: '<md:Extensions><?unsafe data?></md:Extensions>' }),
    '<wrapper>' + signed() + '</wrapper>',
    `<md:EntitiesDescriptor xmlns:md="${md}">` + signed() + '</md:EntitiesDescriptor>',
    '<?unsafe data?>' + signed(),
  ])
    assert.throws(() => verifySamlMetadataSignature(xml, p, 'idp'), { code: 'EK_EID_FEDERATION' });
});

test('External references, malformed XML, DTDs and bounded parser limits fail closed before any resource discovery', () => {
  const xml = signed(),
    p = profile();
  for (const value of [
    '',
    null,
    xml + '\0',
    'not XML',
    '\ud800' + xml,
    verifySamlMetadataSignature(xml, p, 'idp').verifiedXml,
    '<!DOCTYPE a [<!ENTITY b SYSTEM "file:///private-material">]>' + xml,
    xml.replace('URI="#metadata_root"', 'URI="https://unapproved.example.test/material"'),
    xml.replace('URI="#metadata_root"', 'URI="#another-node"'),
    xml.replace('ID="metadata_root"', 'ID="invalid id"'),
    xml.replace('ID="metadata_root"', 'Id="metadata_root"'),
    xml.replace(
      'protocolSupportEnumeration="' + protocol + '"',
      'protocolSupportEnumeration="unapproved"',
    ),
    xml.replace(enveloped, 'http://www.w3.org/TR/1999/REC-xslt-19991116'),
    'x'.repeat(65537),
    signed({
      extra: '<md:Extensions>' + '<x>'.repeat(34) + '</x>'.repeat(34) + '</md:Extensions>',
    }),
    signed({ extra: '<md:Extensions>' + '<x/>'.repeat(8193) + '</md:Extensions>' }),
    signed({
      extra:
        '<md:Extensions><x ' +
        Array.from({ length: 33 }, (_, index) => 'a' + index + '="x"').join(' ') +
        '/></md:Extensions>',
    }),
    signed({ extra: `<md:IDPSSODescriptor protocolSupportEnumeration="${protocol}"/>` }),
  ])
    assert.throws(() => verifySamlMetadataSignature(value as string, p, 'idp'), {
      code: 'EK_EID_FEDERATION',
    });
  assert.throws(() =>
    verifySamlMetadataSignature(
      xml,
      {
        ...p,
        protocol: 'oidc-federation',
        clientId: p.entityId,
        samlRegistration: undefined,
      } as never,
      'idp',
    ),
  );
});
