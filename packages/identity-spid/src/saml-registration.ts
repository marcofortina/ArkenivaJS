// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FederationSamlRegistration, FederationSamlRegistrySource } from './contracts.js';
import { fields, text, failure, url } from './validation.js';

/** Capture only deployment-owned references; certificate parsing belongs to the native SAML backend. */
export function captureSamlRegistration(
  input: unknown,
  signingKeyRef: string,
  policy: Readonly<{
    entityId: string;
    expectedIssuers: readonly string[];
    approvedMetadataEndpoints: readonly string[];
  }>,
): FederationSamlRegistration {
  const value = fields(input, ['signingCertificateRef', 'registrySources']),
    signingCertificateRef = text(value.signingCertificateRef);
  if (signingCertificateRef === signingKeyRef) throw failure();
  let registrySources: Readonly<Record<string, FederationSamlRegistrySource>> | undefined;
  if (value.registrySources !== undefined) {
    const entities = [policy.entityId, ...policy.expectedIssuers];
    if (new Set(entities).size !== entities.length) throw failure();
    const sources = fields(value.registrySources, entities);
    if (Object.keys(sources).length !== entities.length) throw failure();
    const output: Record<string, FederationSamlRegistrySource> = Object.create(null);
    const metadataLocations = new Set<string>(),
      statusLocations = new Set<string>();
    for (const entity of entities) {
      const source = fields(sources[entity], ['metadataEndpoint', 'statusEndpoint']),
        metadataEndpoint = url(source.metadataEndpoint),
        statusEndpoint = url(source.statusEndpoint),
        metadataLocation = new URL(metadataEndpoint).href,
        statusLocation = new URL(statusEndpoint).href;
      if (
        !policy.approvedMetadataEndpoints.includes(metadataEndpoint) ||
        !policy.approvedMetadataEndpoints.includes(statusEndpoint) ||
        metadataLocations.has(metadataLocation) ||
        statusLocations.has(statusLocation)
      )
        throw failure();
      metadataLocations.add(metadataLocation);
      statusLocations.add(statusLocation);
      output[entity] = Object.freeze({ metadataEndpoint, statusEndpoint });
    }
    registrySources = Object.freeze(output);
  }
  return Object.freeze({ signingCertificateRef, ...(registrySources ? { registrySources } : {}) });
}
