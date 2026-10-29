// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, X509Certificate } from 'node:crypto';
import type { SamlSettings } from './contracts.js';
import { fields, failure, text, integer, method, property, url, list } from './validation.js';
import { parse, NS, children, one } from './xml.js';

function certificate(value: string): string {
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(value);
  } catch {
    throw failure();
  }
  const key = certificate.publicKey;
  if (
    Date.now() < Date.parse(certificate.validFrom) ||
    Date.now() >= Date.parse(certificate.validTo) ||
    key.asymmetricKeyType !== 'rsa' ||
    (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
  )
    throw failure();
  return certificate.toString();
}
/** Only explicitly pinned offline metadata supplies endpoints and verification keys. */
function metadata(xml: string, environment: string, binding: 'redirect' | 'post') {
  const document = parse(xml, 65536),
    root = document.documentElement;
  if (root.namespaceURI !== NS.metadata || root.localName !== 'EntityDescriptor') throw failure();
  const issuer = text(root.getAttribute('entityID'), 2048);
  let expiresAt: number | undefined;
  if (root.hasAttribute('validUntil')) {
    expiresAt = Date.parse(root.getAttribute('validUntil')!);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw failure();
  }
  const idp = one(root, NS.metadata, 'IDPSSODescriptor');
  const signing = idp.getAttribute('WantAuthnRequestsSigned');
  if (signing && !['true', 'false', '1', '0'].includes(signing)) throw failure();
  if (!(idp.getAttribute('protocolSupportEnumeration') ?? '').split(/\s+/).includes(NS.protocol))
    throw failure();
  const certificates: string[] = [];
  for (const descriptor of children(idp, NS.metadata, 'KeyDescriptor')) {
    const use = descriptor.getAttribute('use');
    if (use && use !== 'signing') continue;
    const data = one(one(descriptor, NS.signature, 'KeyInfo'), NS.signature, 'X509Data');
    for (const item of children(data, NS.signature, 'X509Certificate')) {
      const base64 = (item.textContent ?? '').replace(/\s/g, '');
      if (
        !/^[A-Za-z0-9+/]+={0,2}$/.test(base64) ||
        Buffer.from(base64, 'base64').toString('base64') !== base64 ||
        base64.length > 16384
      )
        throw failure();
      certificates.push(
        certificate(
          '-----BEGIN CERTIFICATE-----\n' +
            base64.match(/.{1,64}/g)!.join('\n') +
            '\n-----END CERTIFICATE-----\n',
        ),
      );
      if (certificates.length > 8) throw failure();
    }
  }
  if (!certificates.length) throw failure();
  const endpoint = (name: string, required: boolean) => {
    const matches = children(idp, NS.metadata, name).filter(
      (item) => item.getAttribute('Binding') === NS[binding],
    );
    if (!matches.length && !required) return undefined;
    if (matches.length !== 1) throw failure();
    return url(matches[0]!.getAttribute('Location'), environment);
  };
  return Object.freeze({
    issuer,
    expiresAt,
    requireSignedRequests: signing === 'true' || signing === '1',
    certificates: Object.freeze(certificates),
    loginUrl: endpoint('SingleSignOnService', true)!,
    logoutUrl: endpoint('SingleLogoutService', false),
  });
}
export function capture(input: SamlSettings) {
  const value = fields(input, [
    'entityId',
    'acsUrl',
    'expectedAudience',
    'trustedIdpMetadata',
    'signingKeyRef',
    'signingCertificateRef',
    'secretProvider',
    'replayStore',
    'clockSkewSeconds',
    'binding',
    'requestedAuthnContext',
    'authenticationRequestProfile',
    'authority',
    'environment',
  ]);
  const environment = value.environment ?? 'production';
  if (!['production', 'development', 'test'].includes(environment as string)) throw failure();
  const entityId = text(value.entityId, 2048),
    acsUrl = url(value.acsUrl, environment as string),
    audience = text(value.expectedAudience, 2048);
  const binding = value.binding ?? 'redirect';
  if (binding !== 'redirect' && binding !== 'post') throw failure();
  let requestedAuthnContext: SamlSettings['requestedAuthnContext'];
  if (value.requestedAuthnContext !== undefined) {
    const context = fields(value.requestedAuthnContext, [
      'classReferences',
      'comparison',
      'acceptedClassReferences',
    ]);
    if (!['exact', 'minimum', 'maximum', 'better'].includes(context.comparison as string))
      throw failure();
    const references = (input: unknown) => {
      const result = list(input, 8).map((entry) => {
        const value = text(entry, 2048);
        let uri: URL;
        try {
          uri = new URL(value);
        } catch {
          throw failure();
        }
        if (
          !['https:', 'urn:'].includes(uri.protocol) ||
          uri.username ||
          uri.password ||
          /\s/u.test(value)
        )
          throw failure();
        return value;
      });
      if (!result.length || new Set(result).size !== result.length) throw failure();
      return Object.freeze(result);
    };
    try {
      const classReferences = references(context.classReferences),
        acceptedClassReferences = references(context.acceptedClassReferences);
      if (
        context.comparison === 'exact' &&
        (classReferences.length !== acceptedClassReferences.length ||
          classReferences.some((value) => !acceptedClassReferences.includes(value)))
      )
        throw failure();
      requestedAuthnContext = Object.freeze({
        classReferences,
        comparison: context.comparison as NonNullable<
          SamlSettings['requestedAuthnContext']
        >['comparison'],
        acceptedClassReferences,
      });
    } catch {
      throw failure();
    }
  }
  let authenticationRequestProfile: SamlSettings['authenticationRequestProfile'];
  if (value.authenticationRequestProfile !== undefined) {
    const profile = fields(value.authenticationRequestProfile, [
      'kind',
      'attributeConsumingServiceIndex',
    ]);
    if (
      profile.kind !== 'spid' ||
      !requestedAuthnContext ||
      requestedAuthnContext.comparison !== 'exact' ||
      requestedAuthnContext.classReferences.length !== 1 ||
      ![
        'https://www.spid.gov.it/SpidL1',
        'https://www.spid.gov.it/SpidL2',
        'https://www.spid.gov.it/SpidL3',
      ].includes(requestedAuthnContext.classReferences[0]!) ||
      value.signingKeyRef === undefined ||
      value.signingCertificateRef === undefined ||
      value.signingKeyRef === value.signingCertificateRef ||
      audience !== entityId
    )
      throw failure();
    url(entityId, 'production');
    url(acsUrl, 'production');
    authenticationRequestProfile = Object.freeze({
      kind: 'spid',
      ...(profile.attributeConsumingServiceIndex === undefined
        ? {}
        : {
            attributeConsumingServiceIndex: integer(
              profile.attributeConsumingServiceIndex,
              65535,
              0,
            ),
          }),
    });
  }
  if (typeof value.trustedIdpMetadata !== 'string') throw failure();
  let trusted: ReturnType<typeof metadata>;
  try {
    trusted = metadata(value.trustedIdpMetadata, environment as string, binding);
  } catch {
    throw failure();
  }
  const secretProvider = Object.freeze({
    get: method<SamlSettings['secretProvider']['get']>(value.secretProvider, 'get'),
  });
  const store = Object.freeze({
    read: method<SamlSettings['replayStore']['read']>(value.replayStore, 'read'),
    compareAndSet: method<SamlSettings['replayStore']['compareAndSet']>(
      value.replayStore,
      'compareAndSet',
    ),
    claimOnce: method<SamlSettings['replayStore']['claimOnce']>(value.replayStore, 'claimOnce'),
  });
  let signingKeyRef: string | undefined, signingCertificateRef: string | undefined;
  if (value.signingKeyRef !== undefined) {
    signingKeyRef = text(value.signingKeyRef, 256);
    signingCertificateRef = text(value.signingCertificateRef, 256);
  } else if (value.signingCertificateRef !== undefined) throw failure();
  if (trusted.requireSignedRequests && !signingKeyRef) throw failure();
  const authority =
    value.authority === undefined
      ? undefined
      : Object.freeze({
          require: method<NonNullable<SamlSettings['authority']>['require']>(
            value.authority,
            'require',
          ),
        });
  if (
    environment !== 'test' &&
    [value.secretProvider, value.replayStore, value.authority]
      .filter((value) => value !== undefined)
      .some(
        (port) =>
          property(port, 'usage') === 'test-only' ||
          property(port, 'securityLevel') === 'test-only',
      )
  )
    throw failure();
  const profile = createHash('sha256')
    .update(
      JSON.stringify([
        entityId,
        acsUrl,
        audience,
        trusted.issuer,
        ...(requestedAuthnContext ? [requestedAuthnContext] : []),
        ...(authenticationRequestProfile ? [authenticationRequestProfile] : []),
      ]),
    )
    .digest('hex');
  return Object.freeze({
    entityId,
    acsUrl,
    audience,
    binding,
    ...(requestedAuthnContext ? { requestedAuthnContext } : {}),
    ...(authenticationRequestProfile ? { authenticationRequestProfile } : {}),
    environment: environment as 'production' | 'development' | 'test',
    clockSkewSeconds: integer(value.clockSkewSeconds ?? 0, 120, 0),
    trusted,
    secretProvider,
    store,
    signingKeyRef,
    signingCertificateRef,
    authority,
    profile,
  });
}
export type Settings = ReturnType<typeof capture>;
