// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type {
  KeyedDigestProvider,
  SecurityTransactionalStore,
} from '@arkenivajs/security-magiclink';

/** Ephemeral test keys only; applications must resolve versioned keys through their secret provider. */
export function nativeFixtureHmac(key: Buffer): KeyedDigestProvider & { usage: 'test-only' } {
  const mac = (domain: string, parts: readonly string[]) =>
    createHmac('sha256', key)
      .update(JSON.stringify([domain, parts]))
      .digest();
  return {
    usage: 'test-only',
    algorithm: 'HMAC-SHA256',
    async digest(domain, parts, ref) {
      if (ref !== 'fixture/magiclink') throw new Error('Unknown test secret reference');
      return 'fixture-v1:' + mac(domain, parts).toString('hex');
    },
    async verify(domain, parts, digest, ref) {
      if (ref !== 'fixture/magiclink') throw new Error('Unknown test secret reference');
      const encoded = digest.startsWith('fixture-v1:') ? digest.slice(11) : '';
      const expected = /^[a-f0-9]{64}$/.test(encoded)
        ? Buffer.from(encoded, 'hex')
        : Buffer.alloc(32);
      return timingSafeEqual(mac(domain, parts), expected);
    },
  };
}

/** Single-process unit model only; PostgreSQL integration proves actual shared durability. */
export function memoryFixtureStore(): SecurityTransactionalStore & { securityLevel: 'test-only' } {
  const rows = new Map<string, Readonly<Record<string, unknown>>>();
  const key = (namespace: string, id: string) => JSON.stringify([namespace, id]);
  const read = async (namespace: string, id: string) => rows.get(key(namespace, id)) ?? null;
  const unused = async (): Promise<never> => {
    throw new Error('This unit model does not implement the unused storage operation');
  };
  return {
    securityLevel: 'test-only',
    read,
    claimOnce: unused,
    compareAndSet: unused,
    listByOwner: unused,
    bumpOwnerEpoch: unused,
    currentOwnerEpoch: unused,
    async atomicBatch(mutations) {
      for (const mutation of mutations) {
        const previous = rows.get(key(mutation.namespace, mutation.id));
        if (
          (previous?.version ?? null) !== mutation.expectedVersion ||
          (previous && previous.ownerKey !== mutation.ownerKey)
        )
          return { committed: false };
      }
      const version = randomUUID();
      for (const mutation of mutations) {
        const id = key(mutation.namespace, mutation.id);
        if (mutation.next === null) rows.delete(id);
        else
          rows.set(id, Object.freeze({ ...mutation.next, ownerKey: mutation.ownerKey, version }));
      }
      return { committed: true, version };
    },
  };
}
