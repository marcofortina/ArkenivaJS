// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import type {
  FederationProfileV1,
  ItalianEidPluginSettings,
  SecurityStoreSettings,
} from '@arkenivajs/identity-cie';

const publicKeyPem = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  .publicKey.export({ format: 'pem', type: 'spki' })
  .toString();
export async function transactionFixture() {
  const rows = new Map<string, Readonly<Record<string, unknown>>>(),
    claims = new Map<string, number>(),
    epochs = new Map<string, number>(),
    state = { storage: true, secrets: true, ambiguousCreate: false, ambiguousClaim: false },
    key = (namespace: string, id: string) => JSON.stringify([namespace, id]);
  const live = (namespace: string, id: string) => {
    if (!state.storage) throw new Error('The fixture storage is unavailable');
    const row = rows.get(key(namespace, id));
    return row && (row.expiresAt === undefined || Date.parse(String(row.expiresAt)) > Date.now())
      ? row
      : null;
  };
  const store: SecurityStoreSettings['store'] = {
    async read(namespace, id) {
      return live(namespace, id);
    },
    async compareAndSet(namespace, id, expected, next) {
      const row = live(namespace, id);
      if ((row?.version ?? null) !== expected) return { committed: false };
      const version = randomUUID();
      if (next === null) rows.delete(key(namespace, id));
      else rows.set(key(namespace, id), Object.freeze({ ...next, version }));
      if (state.ambiguousCreate) throw new Error('The fixture write acknowledgement was lost');
      return { committed: true, version };
    },
    async claimOnce(namespace, id, expiresAt) {
      if (!state.storage) throw new Error('The fixture claim storage is unavailable');
      const k = key(namespace, id);
      if ((claims.get(k) ?? 0) > Date.now()) return false;
      claims.set(k, Date.parse(expiresAt));
      if (state.ambiguousClaim) throw new Error('The fixture claim acknowledgement was lost');
      return true;
    },
    async atomicBatch(mutations) {
      if (
        mutations.some((mutation) => {
          const row = live(mutation.namespace, mutation.id);
          return (
            (row?.version ?? null) !== mutation.expectedVersion ||
            (row !== null && row.ownerKey !== mutation.ownerKey)
          );
        })
      )
        return { committed: false };
      const version = randomUUID();
      for (const mutation of mutations) {
        if (mutation.next === null) rows.delete(key(mutation.namespace, mutation.id));
        else
          rows.set(
            key(mutation.namespace, mutation.id),
            Object.freeze({ ...mutation.next, ownerKey: mutation.ownerKey, version }),
          );
      }
      return { committed: true, version };
    },
    async listByOwner(namespace, ownerKey, limit) {
      const selected = [...rows]
        .filter(
          ([encoded, row]) =>
            JSON.parse(encoded)[0] === namespace &&
            row.ownerKey === ownerKey &&
            live(namespace, JSON.parse(encoded)[1]),
        )
        .map(([encoded, row]) => {
          const { version, ...fields } = row;
          return {
            id: JSON.parse(encoded)[1] as string,
            ownerKey,
            version: String(version),
            fields,
            ...(row.expiresAt ? { expiresAt: String(row.expiresAt) } : {}),
          };
        });
      if (selected.length > limit) throw new Error('The fixture owner result exceeds its bound');
      return selected;
    },
    async currentOwnerEpoch(namespace, owner) {
      if (!state.storage) throw new Error('The fixture epoch storage is unavailable');
      return epochs.get(key(namespace, owner)) ?? 0;
    },
    async bumpOwnerEpoch(namespace, owner) {
      if (!state.storage) throw new Error('The fixture epoch storage is unavailable');
      const k = key(namespace, owner),
        next = (epochs.get(k) ?? 0) + 1;
      epochs.set(k, next);
      return next;
    },
  };
  const material = new Map<string, { bytes: Buffer; keyVersion: string }>(
    ['state-encryption-current', 'state-encryption-old', 'state-mac-current', 'state-mac-old'].map(
      (reference) => [reference, { bytes: randomBytes(32), keyVersion: randomUUID() }],
    ),
  );
  const secrets = {
    usage: 'test-only' as const,
    async get(reference: string) {
      const value = material.get(reference);
      if (!state.secrets || !value) throw new Error('The fixture secret provider is unavailable');
      return value;
    },
  };
  const profile: FederationProfileV1 = {
    schemaVersion: '1.0.0',
    profileId: 'transactions-profile',
    system: 'cie',
    protocol: 'oidc-federation',
    entityId: 'https://service.example.test',
    clientId: 'https://service.example.test',
    redirectUri: 'https://service.example.test/callback',
    signingKeyRef: 'signing-ref',
    expectedIssuers: ['https://idp.example.test'],
    allowedAssurance: ['cie-l2'],
    metadata: {
      trustAnchors: [
        {
          issuer: 'https://anchor.example.test',
          kid: 'public-root',
          publicKeyPem,
          validFrom: new Date(Date.now() - 60000).toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      ],
      approvedMetadataEndpoints: ['https://anchor.example.test/fetch'],
      maxBytes: 65536,
      maxChainDepth: 4,
      refreshIntervalSeconds: 60,
      revocation: 'mandatory',
      stalePolicy: 'reject',
    },
    subjectClaim: 'sub',
    tenantMappingId: 'approved-accounts',
    identityMappingVersion: '1',
    sessionTtlSeconds: 300,
  };
  const unavailable = async (): Promise<never> => {
    throw new Error('The unused fixture authority is unavailable');
  };
  const settings: ItalianEidPluginSettings = {
    profiles: [profile],
    identityMappers: { 'approved-accounts': { map: unavailable } },
    stateStore: { store, securityLevel: 'test-only', operationTimeoutMs: 1000 },
    secretProvider: secrets,
    authority: { require: unavailable },
    policy: { maxConcurrent: 8, timeoutMs: 3000, maxInputBytes: 32768 },
    stateEncryptionKeyRefs: ['state-encryption-current', 'state-encryption-old'],
    stateMacKeyRefs: ['state-mac-current', 'state-mac-old'],
  };
  return {
    settings,
    profile,
    rows,
    claims,
    state,
    material,
    async close() {
      for (const value of material.values()) value.bytes.fill(0);
    },
  };
}
