// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPublicKey, X509Certificate } from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import validator from 'validator';
import type { FederationProfileV1 } from './contracts.js';
import { captureProfile } from './settings.js';
import { failure } from './validation.js';

const metadataNs = 'urn:oasis:names:tc:SAML:2.0:metadata',
  protocolNs = 'urn:oasis:names:tc:SAML:2.0:protocol',
  signatureNs = 'http://www.w3.org/2000/09/xmldsig#',
  canonical = 'http://www.w3.org/2001/10/xml-exc-c14n#',
  enveloped = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const reject = (): never => {
  throw failure('EK_EID_FEDERATION');
};
function parse(xml: string, maximum: number): Document {
  if (
    typeof xml !== 'string' ||
    !xml ||
    Buffer.byteLength(xml) > maximum ||
    Buffer.from(xml).toString('utf8') !== xml ||
    /<!\s*(?:DOCTYPE|ENTITY)/iu.test(xml) ||
    xml.includes('\0')
  )
    reject();
  const document = new DOMParser({
    errorHandler: { warning: reject, error: reject, fatalError: reject },
  }).parseFromString(xml, 'text/xml') as unknown as Document;
  if (!document.documentElement || document.doctype) reject();
  for (const node of Array.from(document.childNodes))
    if (node.nodeType === 7 && node.nodeName !== 'xml') reject();
  const pending = [{ node: document.documentElement as Node, depth: 0 }],
    ids = new Set<string>();
  let count = 0;
  while (pending.length) {
    const { node, depth } = pending.pop()!;
    if (++count > 8192 || depth > 32 || node.nodeType === 7) reject();
    if (node.nodeType === 1) {
      const element = node as Element;
      if (element.attributes.length > 32) reject();
      for (const name of ['ID', 'Id', 'id'])
        if (element.hasAttribute(name)) {
          const id = element.getAttribute(name)!;
          if (!id || id.length > 256 || ids.has(id)) reject();
          ids.add(id);
        }
    }
    for (let child = node.lastChild; child; child = child.previousSibling)
      pending.push({ node: child, depth: depth + 1 });
  }
  return document;
}
function children(parent: Element, namespace: string, name: string): Element[] {
  return Array.from(parent.childNodes).filter(
    (node): node is Element =>
      node.nodeType === 1 &&
      (node as Element).namespaceURI === namespace &&
      (node as Element).localName === name,
  );
}
function one(parent: Element, namespace: string, name: string): Element {
  const values = children(parent, namespace, name);
  if (values.length !== 1) reject();
  return values[0]!;
}
function entity(document: Document, profile: FederationProfileV1, role: 'idp' | 'sp') {
  const root = document.documentElement;
  if (root.namespaceURI !== metadataNs || root.localName !== 'EntityDescriptor') reject();
  const issuer = root.getAttribute('entityID');
  if (
    !issuer ||
    !(role === 'sp' ? issuer === profile.entityId : profile.expectedIssuers.includes(issuer))
  )
    reject();
  const selected = role === 'sp' ? 'SPSSODescriptor' : 'IDPSSODescriptor',
    opposite = role === 'sp' ? 'IDPSSODescriptor' : 'SPSSODescriptor',
    descriptor = one(root, metadataNs, selected);
  if (
    children(root, metadataNs, opposite).length ||
    !(descriptor.getAttribute('protocolSupportEnumeration') ?? '')
      .split(/\s+/u)
      .includes(protocolNs)
  )
    reject();
  const expiry = root.getAttribute('validUntil');
  if (
    root.hasAttribute('validUntil') &&
    (!expiry ||
      !/(?:Z|[+-][0-9]{2}:[0-9]{2})$/u.test(expiry) ||
      !validator.isISO8601(expiry, { strict: true, strictSeparator: true }) ||
      Date.parse(expiry) <= Date.now())
  )
    reject();
  return { root, issuer, ...(expiry ? { validUntil: new Date(expiry).toISOString() } : {}) };
}
/** Signature evidence only: current authoritative participation must be checked independently. */
export function verifySamlMetadataSignature(
  input: string,
  configuration: FederationProfileV1,
  role: 'idp' | 'sp',
) {
  const profile = captureProfile(configuration, 'spid');
  if (profile.protocol !== 'saml2' || !['idp', 'sp'].includes(role))
    throw failure('EK_EID_PROFILE');
  try {
    const maximum = Math.min(profile.metadata.maxBytes, 65536),
      document = parse(input, maximum),
      original = entity(document, profile, role),
      signatures = document.getElementsByTagNameNS(signatureNs, 'Signature');
    if (signatures.length !== 1 || signatures[0]!.parentNode !== original.root) reject();
    const id = original.root.getAttribute('ID');
    if (!id || !/^[A-Za-z_][A-Za-z0-9_.-]{0,255}$/u.test(id)) reject();
    const signature = signatures[0]!,
      info = one(signature, signatureNs, 'SignedInfo'),
      references = children(info, signatureNs, 'Reference');
    if (
      references.length !== 1 ||
      references[0]!.getAttribute('URI') !== '#' + id ||
      one(info, signatureNs, 'CanonicalizationMethod').getAttribute('Algorithm') !== canonical ||
      ![
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
      ].includes(one(info, signatureNs, 'SignatureMethod').getAttribute('Algorithm') ?? '') ||
      ![
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2001/04/xmlenc#sha512',
      ].includes(one(references[0]!, signatureNs, 'DigestMethod').getAttribute('Algorithm') ?? '')
    )
      reject();
    const transforms = children(
      one(references[0]!, signatureNs, 'Transforms'),
      signatureNs,
      'Transform',
    ).map((value) => value.getAttribute('Algorithm'));
    if (transforms.length !== 2 || transforms[0] !== enveloped || transforms[1] !== canonical)
      reject();
    for (const anchor of profile.metadata.trustAnchors) {
      if (Date.parse(anchor.validFrom) > Date.now() || Date.parse(anchor.expiresAt) <= Date.now())
        continue;
      const key = createPublicKey(anchor.publicKeyPem);
      if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)
        continue;
      let anchorExpiry = Date.parse(anchor.expiresAt);
      if (anchor.publicKeyPem.startsWith('-----BEGIN CERTIFICATE-----')) {
        const certificate = new X509Certificate(anchor.publicKeyPem);
        const from = Date.parse(certificate.validFrom),
          to = Date.parse(certificate.validTo);
        if (!Number.isFinite(from) || !Number.isFinite(to) || from > Date.now() || to <= Date.now())
          continue;
        anchorExpiry = Math.min(anchorExpiry, to);
      }
      const verifier = new SignedXml({
        publicCert: key.export({ format: 'pem', type: 'spki' }),
        getCertFromKeyInfo: () => null,
      });
      try {
        verifier.loadSignature(signature);
        if (!verifier.checkSignature(input)) continue;
        const signed = verifier.getSignedReferences();
        if (signed.length !== 1) reject();
        const verified = entity(parse(signed[0]!, maximum), profile, role);
        if (verified.issuer !== original.issuer || verified.root.getAttribute('ID') !== id)
          reject();
        if (
          anchorExpiry <= Date.now() ||
          (verified.validUntil !== undefined && Date.parse(verified.validUntil) <= Date.now())
        )
          reject();
        return Object.freeze({
          issuer: verified.issuer,
          role,
          signerKid: anchor.kid,
          ...(verified.validUntil ? { validUntil: verified.validUntil } : {}),
          verifiedXml: signed[0]!,
          trustAnchorExpiresAt: new Date(anchorExpiry).toISOString(),
        });
      } catch {
        /* Other explicitly pinned current roots may verify the same bounded document. */
      }
    }
    return reject();
  } catch {
    return reject();
  }
}
