// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { X509Certificate } from 'node:crypto';
import type { FederationProfileV1 } from './contracts.js';
import { captureProfile } from './settings.js';
import {
  children,
  one,
  parseSamlMetadataXml,
  verifySamlMetadataSignature,
} from './saml-metadata-signature.js';
import { failure, fields, list, url } from './validation.js';

const md = 'urn:oasis:names:tc:SAML:2.0:metadata',
  ds = 'http://www.w3.org/2000/09/xmldsig#',
  post = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
function reject(): never {
  throw failure('EK_EID_FEDERATION');
}

/** Parse public DER through Node's X.509 implementation; no application key material is accepted. */
function certificate(input: unknown) {
  if (typeof input !== 'string' || input.length > 16384) reject();
  const encoded = input.replace(/[ \t\r\n]/gu, '');
  if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) reject();
  const der = Buffer.from(encoded, 'base64');
  if (der.toString('base64') !== encoded) reject();
  const value = new X509Certificate(der),
    validFrom = Date.parse(value.validFrom),
    expiresAt = Date.parse(value.validTo),
    key = value.publicKey;
  if (
    value.raw.toString('base64') !== encoded ||
    !Number.isFinite(validFrom) ||
    !Number.isFinite(expiresAt) ||
    validFrom > Date.now() ||
    expiresAt <= Date.now() ||
    key.asymmetricKeyType !== 'rsa' ||
    (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
  )
    reject();
  return { encoded, pem: value.toString(), expiresAt };
}

/** Combine authenticated XML and explicit registry state; callers must authenticate the approved HTTPS source. */
export function verifySamlRegistryDocument(
  xml: string,
  status: string,
  configuration: FederationProfileV1,
  role: 'idp' | 'sp',
) {
  const profile = captureProfile(configuration, 'spid');
  try {
    const maximum = Math.min(profile.metadata.maxBytes, 65536);
    if (
      typeof xml !== 'string' ||
      typeof status !== 'string' ||
      !status ||
      Buffer.byteLength(xml) + Buffer.byteLength(status) > maximum ||
      Buffer.from(status).toString('utf8') !== status
    )
      reject();
    const signature = verifySamlMetadataSignature(xml, profile, role),
      source = profile.samlRegistration?.registrySources?.[signature.issuer];
    if (!source || new URL(source.statusEndpoint).origin !== new URL(signature.signerIssuer).origin)
      reject();
    const current = fields(JSON.parse(status));
    if (
      Object.keys(current).length > 64 ||
      current.entity_id !== signature.issuer ||
      current._deleted !== 'N' ||
      current._disabled !== 'N' ||
      current.delete_date !== null
    )
      reject();
    const registered = list(current.signing_certificate_x509, 8).map(certificate),
      registeredIds = new Set(registered.map((item) => item.encoded));
    if (registeredIds.size !== registered.length) reject();
    const document = parseSamlMetadataXml(signature.verifiedXml, maximum),
      descriptor = one(
        document.documentElement,
        md,
        role === 'sp' ? 'SPSSODescriptor' : 'IDPSSODescriptor',
      ),
      signing = descriptor.getAttribute(
        role === 'sp' ? 'AuthnRequestsSigned' : 'WantAuthnRequestsSigned',
      );
    if (!['true', '1'].includes(signing ?? '')) reject();
    const certificates: ReturnType<typeof certificate>[] = [];
    for (const key of children(descriptor, md, 'KeyDescriptor')) {
      const use = key.getAttribute('use');
      if (use && !['signing', 'encryption'].includes(use)) reject();
      if (use === 'encryption') continue;
      const data = one(one(key, ds, 'KeyInfo'), ds, 'X509Data'),
        values = children(data, ds, 'X509Certificate');
      if (!values.length || certificates.length + values.length > 8) reject();
      for (const value of values) {
        if (Array.from(value.childNodes).some((node) => ![3, 4].includes(node.nodeType))) reject();
        certificates.push(certificate(value.textContent));
      }
    }
    const signedIds = new Set(certificates.map((item) => item.encoded));
    if (
      !certificates.length ||
      signedIds.size !== certificates.length ||
      signedIds.size !== registeredIds.size ||
      [...signedIds].some((item) => !registeredIds.has(item))
    )
      reject();
    if (role === 'sp') {
      const consumers = children(descriptor, md, 'AssertionConsumerService');
      if (!consumers.length || consumers.length > 64) reject();
      const indexes = new Set<number>();
      let matched = false;
      for (const [position, consumer] of consumers.entries()) {
        const raw = consumer.getAttribute('index'),
          index = Number(raw),
          target = url(consumer.getAttribute('Location')),
          defaultValue = consumer.getAttribute('isDefault');
        if (
          !raw ||
          !/^[0-9]+$/u.test(raw) ||
          !Number.isSafeInteger(index) ||
          index > 65535 ||
          indexes.has(index) ||
          consumer.getAttribute('Binding') !== post ||
          (position === 0
            ? index !== 0 || !['true', '1'].includes(defaultValue ?? '')
            : consumer.hasAttribute('isDefault') && !['false', '0'].includes(defaultValue ?? ''))
        )
          reject();
        indexes.add(index);
        if (target === profile.redirectUri) matched = true;
      }
      if (!matched) reject();
    }
    const expiresAt = Math.min(
      Date.parse(signature.trustAnchorExpiresAt),
      signature.validUntil === undefined ? Infinity : Date.parse(signature.validUntil),
      ...registered.map((item) => item.expiresAt),
      Date.now() + profile.metadata.refreshIntervalSeconds * 1000,
    );
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) reject();
    return Object.freeze({
      ...signature,
      certificates: Object.freeze(certificates.map((item) => item.pem)),
      expiresAt: new Date(expiresAt).toISOString(),
    });
  } catch {
    return reject();
  }
}
