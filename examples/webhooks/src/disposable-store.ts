// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import type { SecurityTransactionalStore } from '@arkenivajs/webhooks';

/** Bounded single-process demonstration only; production and cross-pod use are explicitly rejected. */
export function disposableStore(): SecurityTransactionalStore & { securityLevel: 'test-only' } {
  const claims = new Map<string, number>(),
    records = new Map<string, Readonly<Record<string, unknown>>>(),
    epochs = new Map<string, number>();
  const key = (namespace: string, id: string) => JSON.stringify([namespace, id]);
  const read = (namespace: string, id: string) => {
    const name = key(namespace, id),
      value = records.get(name);
    if (typeof value?.expiresAt === 'string' && Date.parse(value.expiresAt) <= Date.now()) {
      records.delete(name);
      return null;
    }
    return value ?? null;
  };
  const store: SecurityTransactionalStore & { securityLevel: 'test-only' } = {
    securityLevel: 'test-only',
    async claimOnce(namespace, id, expiresAt) {
      const now = Date.now(),
        name = key(namespace, id);
      for (const [item, expiry] of claims) if (expiry <= now) claims.delete(item);
      if ((claims.get(name) ?? 0) > now) return false;
      if (
        claims.size >= 1024 ||
        !Number.isFinite(Date.parse(expiresAt)) ||
        Date.parse(expiresAt) <= now
      )
        throw new Error('Disposable claim capacity exceeded');
      claims.set(name, Date.parse(expiresAt));
      return true;
    },
    async read(namespace, id) {
      return read(namespace, id);
    },
    async compareAndSet(namespace, id, expected, next) {
      if ((read(namespace, id)?.version ?? null) !== expected) return { committed: false };
      const version = randomUUID();
      if (next === null) records.delete(key(namespace, id));
      else {
        if (records.size >= 1024) throw new Error('Disposable record capacity exceeded');
        records.set(key(namespace, id), Object.freeze({ ...next, version }));
      }
      return { committed: true, version };
    },
    async atomicBatch(mutations) {
      if (
        mutations.length > 32 ||
        new Set(mutations.map((item) => key(item.namespace, item.id))).size !== mutations.length
      )
        throw new Error('Invalid disposable transaction');
      if (
        mutations.some(
          (item) => (read(item.namespace, item.id)?.version ?? null) !== item.expectedVersion,
        )
      )
        return { committed: false };
      if (
        records.size +
          mutations.filter((item) => item.next !== null && !read(item.namespace, item.id)).length >
        1024
      )
        throw new Error('Disposable transaction capacity exceeded');
      const version = randomUUID();
      for (const item of mutations) {
        if (item.next === null) records.delete(key(item.namespace, item.id));
        else
          records.set(
            key(item.namespace, item.id),
            Object.freeze({ ...item.next, ownerKey: item.ownerKey, version }),
          );
      }
      return { committed: true, version };
    },
    async listByOwner(namespace, ownerKey, limit) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024)
        throw new Error('Invalid disposable page limit');
      const result = [];
      for (const [encoded, value] of records) {
        const [ns, id] = JSON.parse(encoded) as [string, string];
        if (ns === namespace && value.ownerKey === ownerKey && read(ns, id))
          result.push({
            id,
            ownerKey,
            version: String(value.version),
            fields: value,
            ...(typeof value.expiresAt === 'string' ? { expiresAt: value.expiresAt } : {}),
          });
      }
      if (result.length > limit) throw new Error('Disposable owner page limit exceeded');
      return result;
    },
    async bumpOwnerEpoch(namespace, ownerKey) {
      const name = key(namespace, ownerKey),
        value = (epochs.get(name) ?? 0) + 1;
      if (epochs.size >= 1024 && !epochs.has(name))
        throw new Error('Disposable epoch capacity exceeded');
      epochs.set(name, value);
      return value;
    },
    async currentOwnerEpoch(namespace, ownerKey) {
      return epochs.get(key(namespace, ownerKey)) ?? 0;
    },
  };
  return store;
}
