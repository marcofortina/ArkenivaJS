// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPublicKey } from 'node:crypto';
import { freezeData } from '@arkenivajs/core/support';
import type {
  FederationAssurance,
  FederationProfileV1,
  FederationTrustAnchor,
  ItalianEidPluginSettings,
  ItalianIdentitySystem,
} from './contracts.js';
import { failure, fields, integer, list, method, property, text, url } from './validation.js';
import { captureRegistration } from './registration.js';
import { captureSamlRegistration } from './saml-registration.js';
import { assuranceLevels } from './assurance.js';

function strings(input: unknown, convert: (value: unknown) => string = text) {
  const result = list(input).map((value) => convert(value));
  if (new Set(result).size !== result.length) throw failure();
  return Object.freeze(result);
}
function instant(input: unknown): string {
  const value = text(input, 32),
    time = Date.parse(value);
  if (
    !Number.isSafeInteger(time) ||
    time < 0 ||
    (new Date(time).toISOString() !== value &&
      new Date(time).toISOString().replace('.000Z', 'Z') !== value)
  )
    throw failure();
  return value;
}
function anchor(input: unknown): FederationTrustAnchor {
  const value = fields(input, ['kid', 'issuer', 'publicKeyPem', 'validFrom', 'expiresAt']);
  const pem = value.publicKeyPem;
  if (
    typeof pem !== 'string' ||
    Buffer.byteLength(pem) > 16384 ||
    !/^-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END \1-----\s*$/u.test(
      pem,
    )
  )
    throw failure();
  try {
    const key = createPublicKey(pem);
    if (!(
      (key.asymmetricKeyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048) ||
      (key.asymmetricKeyType === 'ec' &&
        ['prime256v1', 'secp384r1', 'secp521r1'].includes(
          key.asymmetricKeyDetails?.namedCurve ?? '',
        ))
    ))
      throw failure();
  } catch {
    throw failure();
  }
  const validFrom = instant(value.validFrom),
    expiresAt = instant(value.expiresAt);
  if (Date.parse(validFrom) >= Date.parse(expiresAt)) throw failure();
  return Object.freeze({
    kid: text(value.kid),
    issuer: url(value.issuer),
    publicKeyPem: pem,
    validFrom,
    expiresAt,
  });
}
export function captureProfile(
  input: unknown,
  expectedSystem?: ItalianIdentitySystem,
): FederationProfileV1 {
  const value = fields(input, [
    'schemaVersion',
    'profileId',
    'system',
    'protocol',
    'entityId',
    'clientId',
    'redirectUri',
    'signingKeyRef',
    'expectedIssuers',
    'allowedAssurance',
    'metadata',
    'subjectClaim',
    'tenantMappingId',
    'identityMappingVersion',
    'sessionTtlSeconds',
    'oidcRegistration',
    'samlRegistration',
  ]);
  const system = expectedSystem === undefined ? value.system : expectedSystem;
  if (system !== 'spid' && system !== 'cie') throw failure();
  const permittedAssurance = assuranceLevels(system);
  if (
    value.schemaVersion !== '1.0.0' ||
    value.system !== system ||
    !['saml2', 'oidc-federation'].includes(value.protocol as string)
  )
    throw failure();
  const assurance = strings(value.allowedAssurance);
  if (assurance.some((item) => !permittedAssurance.includes(item as FederationAssurance)))
    throw failure('EK_EID_ASSURANCE');
  const metadata = fields(value.metadata, [
    'trustAnchors',
    'approvedMetadataEndpoints',
    'maxBytes',
    'refreshIntervalSeconds',
    'maxChainDepth',
    'revocation',
    'stalePolicy',
  ]);
  if (metadata.revocation !== 'mandatory' || metadata.stalePolicy !== 'reject') throw failure();
  const anchors = list(metadata.trustAnchors, 32).map(anchor);
  if (
    new Set(anchors.map((item) => JSON.stringify([item.issuer, item.kid]))).size !==
      anchors.length ||
    !anchors.some(
      (item) => Date.parse(item.validFrom) <= Date.now() && Date.now() < Date.parse(item.expiresAt),
    )
  )
    throw failure();
  const clientId = value.clientId === undefined ? undefined : text(value.clientId, 2048);
  if (value.protocol === 'oidc-federation' && !clientId) throw failure();
  const entityId = url(value.entityId),
    signingKeyRef = text(value.signingKeyRef),
    maxBytes = integer(metadata.maxBytes);
  if (value.protocol !== 'oidc-federation' && value.oidcRegistration !== undefined) throw failure();
  const oidcRegistration =
    value.oidcRegistration === undefined
      ? undefined
      : captureRegistration(value.oidcRegistration, entityId, signingKeyRef, maxBytes);
  if (oidcRegistration && (clientId !== entityId || new URL(entityId).search)) throw failure();
  if (system === 'spid' && oidcRegistration?.idTokenEncryption) throw failure();
  if (value.samlRegistration !== undefined && (system !== 'spid' || value.protocol !== 'saml2'))
    throw failure();
  const samlRegistration =
    value.samlRegistration === undefined
      ? undefined
      : captureSamlRegistration(value.samlRegistration, signingKeyRef);
  return freezeData({
    schemaVersion: '1.0.0',
    profileId: text(value.profileId),
    system,
    protocol: value.protocol as FederationProfileV1['protocol'],
    entityId,
    ...(clientId ? { clientId } : {}),
    redirectUri: url(value.redirectUri),
    signingKeyRef,
    expectedIssuers: strings(value.expectedIssuers, url),
    allowedAssurance: assurance as readonly FederationAssurance[],
    metadata: {
      trustAnchors: anchors,
      approvedMetadataEndpoints: strings(metadata.approvedMetadataEndpoints, url),
      maxBytes,
      refreshIntervalSeconds: integer(metadata.refreshIntervalSeconds),
      maxChainDepth: integer(metadata.maxChainDepth),
      revocation: 'mandatory',
      stalePolicy: 'reject',
    },
    subjectClaim: text(value.subjectClaim),
    tenantMappingId: text(value.tenantMappingId),
    identityMappingVersion: text(value.identityMappingVersion),
    sessionTtlSeconds: integer(value.sessionTtlSeconds),
    ...(oidcRegistration ? { oidcRegistration } : {}),
    ...(samlRegistration ? { samlRegistration } : {}),
  });
}
/** Capture immutable policy and bound provider methods without performing secret or network I/O. */
export function capture(
  input: ItalianEidPluginSettings,
  environment: 'production' | 'development' | 'test' = 'production',
  system: ItalianIdentitySystem = 'spid',
) {
  if (!['production', 'development', 'test'].includes(environment)) throw failure();
  const value = fields(input, [
    'profiles',
    'identityMappers',
    'stateStore',
    'secretProvider',
    'authority',
    'policy',
    'stateEncryptionKeyRefs',
    'stateMacKeyRefs',
  ]);
  const profiles = list(value.profiles).map((profile) => captureProfile(profile, system));
  if (new Set(profiles.map((item) => item.profileId)).size !== profiles.length) throw failure();
  const encryptionRefs =
      value.stateEncryptionKeyRefs === undefined
        ? Object.freeze([] as string[])
        : Object.freeze(list(value.stateEncryptionKeyRefs, 8).map((item) => text(item))),
    macRefs =
      value.stateMacKeyRefs === undefined
        ? Object.freeze([] as string[])
        : Object.freeze(list(value.stateMacKeyRefs, 8).map((item) => text(item)));
  if (
    (encryptionRefs.length === 0) !== (macRefs.length === 0) ||
    new Set([...encryptionRefs, ...macRefs]).size !== encryptionRefs.length + macRefs.length ||
    profiles.some((profile) =>
      [
        profile.signingKeyRef,
        ...(profile.oidcRegistration ? [profile.oidcRegistration.decryptionKeyRef] : []),
        ...(profile.samlRegistration ? [profile.samlRegistration.signingCertificateRef] : []),
      ].some((reference) => [...encryptionRefs, ...macRefs].includes(reference)),
    )
  )
    throw failure();
  const mappers = fields(value.identityMappers),
    capturedMappers: Record<
      string,
      { map: ItalianEidPluginSettings['identityMappers'][string]['map'] }
    > = Object.create(null);
  const required = new Set(profiles.map((item) => item.tenantMappingId));
  if (
    Object.keys(mappers).length !== required.size ||
    [...required].some((id) => !Object.hasOwn(mappers, id))
  )
    throw failure();
  for (const id of required)
    capturedMappers[id] = Object.freeze({
      map: method<ItalianEidPluginSettings['identityMappers'][string]['map']>(mappers[id], 'map'),
    });
  const storage = fields(value.stateStore, ['store', 'securityLevel', 'operationTimeoutMs']);
  if (
    !['production', 'test-only'].includes(storage.securityLevel as string) ||
    (environment !== 'test' && storage.securityLevel !== 'production')
  )
    throw failure();
  const store = storage.store;
  let testOnly = storage.securityLevel === 'test-only';
  for (const provider of [store, value.secretProvider, value.authority, ...Object.values(mappers)])
    for (const flag of ['usage', 'securityLevel'])
      if (property(provider, flag) === 'test-only') {
        testOnly = true;
        if (environment !== 'test') throw failure();
      }
  type Store = ItalianEidPluginSettings['stateStore']['store'];
  const capturedStore: Store = Object.freeze({
    read: method<Store['read']>(store, 'read'),
    claimOnce: method<Store['claimOnce']>(store, 'claimOnce'),
    compareAndSet: method<Store['compareAndSet']>(store, 'compareAndSet'),
    atomicBatch: method<Store['atomicBatch']>(store, 'atomicBatch'),
    listByOwner: method<Store['listByOwner']>(store, 'listByOwner'),
    bumpOwnerEpoch: method<Store['bumpOwnerEpoch']>(store, 'bumpOwnerEpoch'),
    currentOwnerEpoch: method<Store['currentOwnerEpoch']>(store, 'currentOwnerEpoch'),
  });
  const policy = fields(value.policy, [
    'maxConcurrent',
    'timeoutMs',
    'maxInputBytes',
    'maxOutputBytes',
  ]);
  return Object.freeze({
    profiles: Object.freeze(profiles),
    encryptionRefs,
    macRefs,
    identityMappers: Object.freeze(capturedMappers),
    stateStore: Object.freeze({
      store: capturedStore,
      securityLevel: storage.securityLevel as 'production' | 'test-only',
      operationTimeoutMs: integer(storage.operationTimeoutMs),
    }),
    secretProvider: Object.freeze({
      get: method<ItalianEidPluginSettings['secretProvider']['get']>(value.secretProvider, 'get'),
    }),
    authority: Object.freeze({
      require: method<ItalianEidPluginSettings['authority']['require']>(value.authority, 'require'),
    }),
    policy: Object.freeze({
      maxConcurrent: integer(policy.maxConcurrent),
      timeoutMs: integer(policy.timeoutMs),
      ...(policy.maxInputBytes === undefined
        ? {}
        : { maxInputBytes: integer(policy.maxInputBytes) }),
      ...(policy.maxOutputBytes === undefined
        ? {}
        : { maxOutputBytes: integer(policy.maxOutputBytes) }),
    }),
    environment,
    testOnly,
  });
}
export type Settings = ReturnType<typeof capture>;
