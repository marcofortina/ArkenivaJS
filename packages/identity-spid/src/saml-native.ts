// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { X509Certificate } from 'node:crypto';
import { types } from 'node:util';
import { createManagedSamlAdapter } from '@arkenivajs/security-saml/support';
import type { SamlService } from '@arkenivajs/security-saml';
import type { FederationAssurance, FederationProfileV1 } from './contracts.js';
import type { Settings } from './settings.js';
import type { FederationCall } from './runtime.js';
import type { FederationSamlRegistry } from './saml-registry.js';
import { assuranceContext, assuranceLevels } from './assurance.js';
import { failure, fields } from './validation.js';

type Receipt = ReturnType<FederationSamlRegistry['result']>;
const arrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object,
  byteLength = Object.getOwnPropertyDescriptor(arrayPrototype, 'byteLength')!.get!,
  storage = Object.getOwnPropertyDescriptor(arrayPrototype, 'buffer')!.get!;
function certificateBytes(input: unknown): Buffer {
  if (!types.isUint8Array(input) || types.isProxy(input)) throw failure('EK_EID_FEDERATION');
  const length = byteLength.call(input) as number;
  if (!(storage.call(input) instanceof ArrayBuffer) || length < 1 || length > 32768)
    throw failure('EK_EID_FEDERATION');
  const copy = Buffer.alloc(length);
  Uint8Array.prototype.set.call(copy, input);
  return copy;
}

/** Compose the approved native backend while its physical drain remains owned by the parent call. */
export async function withFederationSaml<T>(
  call: FederationCall,
  settings: Settings,
  profile: FederationProfileV1,
  registry: FederationSamlRegistry,
  rpInput: Receipt,
  idpInput: Receipt,
  assurance: FederationAssurance,
  work: (service: SamlService) => Promise<T>,
): Promise<T> {
  call.check();
  if (settings.environment !== 'test' && settings.testOnly) throw failure('EK_EID_PROFILE');
  const rp = registry.result(rpInput),
    idp = registry.result(idpInput),
    reference = profile.samlRegistration?.signingCertificateRef,
    context = assuranceContext('spid', assurance);
  if (
    !reference ||
    rp.role !== 'sp' ||
    rp.issuer !== profile.entityId ||
    idp.role !== 'idp' ||
    !profile.expectedIssuers.includes(idp.issuer) ||
    !profile.allowedAssurance.includes(assurance)
  )
    throw failure('EK_EID_FEDERATION');
  const certificates = new Set(
      rp.certificates.map((pem) => new X509Certificate(pem).raw.toString('base64')),
    ),
    snapshots = new Set<Buffer>(),
    adapter = createManagedSamlAdapter(
      {
        entityId: profile.entityId,
        acsUrl: profile.redirectUri,
        expectedAudience: profile.entityId,
        trustedIdpMetadata: idp.verifiedXml,
        signingKeyRef: profile.signingKeyRef,
        signingCertificateRef: reference,
        secretProvider: {
          async get(selected, options) {
            if (selected !== reference && selected !== profile.signingKeyRef)
              throw failure('EK_EID_FEDERATION');
            const input = await settings.secretProvider.get(selected, options);
            if (selected !== reference) return input;
            const value = fields(input, ['bytes', 'keyVersion', 'expiresAt']),
              copy = certificateBytes(value.bytes);
            snapshots.add(copy);
            try {
              registry.result(rpInput);
              registry.result(idpInput);
              if (!certificates.has(new X509Certificate(copy).raw.toString('base64')))
                throw failure('EK_EID_FEDERATION');
              return Object.freeze({
                bytes: copy,
                keyVersion: value.keyVersion as string,
                ...(value.expiresAt === undefined ? {} : { expiresAt: value.expiresAt as string }),
              });
            } catch {
              copy.fill(0);
              throw failure('EK_EID_FEDERATION');
            }
          },
        },
        replayStore: settings.stateStore.store,
        requestedAuthnContext: {
          classReferences: [context],
          acceptedClassReferences: profile.allowedAssurance
            .filter(
              (level) =>
                assuranceLevels('spid').indexOf(level) >=
                assuranceLevels('spid').indexOf(assurance),
            )
            .map((level) => assuranceContext('spid', level)),
          comparison: 'minimum',
        },
        authenticationRequestProfile: { kind: 'spid' },
        environment: settings.environment,
      },
      call.signal,
      () => true,
    );
  try {
    await call.step(() => adapter.bootstrap());
    const result = await work(adapter.service);
    registry.result(rpInput);
    registry.result(idpInput);
    call.check();
    return result;
  } finally {
    const drained = adapter.drain().finally(() => {
      for (const copy of snapshots) copy.fill(0);
      snapshots.clear();
    });
    call.track(drained);
    await drained;
  }
}
