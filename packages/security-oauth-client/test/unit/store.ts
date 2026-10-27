// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import type { SecurityTransactionalStore } from '../../dist/index.js';

/** Complete unit-only state model; shared SQL conformance is verified separately. */
export function unitStore() {
  const rows = new Map<string, Readonly<Record<string, unknown>>>(),
    claims = new Map<string, number>(),
    epochs = new Map<string, number>(),
    state = { storeAvailable: true },
    key = (ns: string, id: string) => JSON.stringify([ns, id]);
  const live = (ns: string, id: string) => {
    if (!state.storeAvailable) throw new Error('Private fixture storage diagnostic');
    const row = rows.get(key(ns, id));
    return row && (row.expiresAt === undefined || Date.parse(String(row.expiresAt)) > Date.now())
      ? row
      : null;
  };
  const store: SecurityTransactionalStore & { securityLevel: 'test-only' } = {
    securityLevel: 'test-only',
    async read(ns, id) {
      return live(ns, id);
    },
    async compareAndSet(ns, id, expected, next) {
      const before = live(ns, id);
      if ((before?.version ?? null) !== expected) return { committed: false };
      const revision = randomUUID();
      if (next === null) rows.delete(key(ns, id));
      else rows.set(key(ns, id), Object.freeze({ ...next, version: revision }));
      return { committed: true, version: revision };
    },
    async atomicBatch(mutations) {
      if (
        mutations.some((m) => {
          const row = live(m.namespace, m.id);
          return (
            (row?.version ?? null) !== m.expectedVersion || (row && row.ownerKey !== m.ownerKey)
          );
        })
      )
        return { committed: false };
      const revision = randomUUID();
      for (const m of mutations) {
        if (m.next === null) rows.delete(key(m.namespace, m.id));
        else
          rows.set(
            key(m.namespace, m.id),
            Object.freeze({ ...m.next, ownerKey: m.ownerKey, version: revision }),
          );
      }
      return { committed: true, version: revision };
    },
    async claimOnce(ns, id, expiry) {
      if (!state.storeAvailable) throw new Error('Private fixture claim failure');
      const k = key(ns, id);
      if ((claims.get(k) ?? 0) > Date.now()) return false;
      claims.set(k, Date.parse(expiry));
      return true;
    },
    async listByOwner(ns, ownerKey, limit) {
      const found = [...rows]
        .filter(
          ([k, row]) =>
            JSON.parse(k)[0] === ns && row.ownerKey === ownerKey && live(ns, JSON.parse(k)[1]),
        )
        .map(([k, row]) => {
          const { version, ...fields } = row;
          return {
            id: JSON.parse(k)[1] as string,
            ownerKey,
            version: String(version),
            fields,
            ...(row.expiresAt ? { expiresAt: String(row.expiresAt) } : {}),
          };
        });
      if (found.length > limit) throw new Error('Fixture owner index overflow');
      return found;
    },
    async currentOwnerEpoch(ns, id) {
      if (!state.storeAvailable) throw new Error('Private epoch diagnostic');
      return epochs.get(key(ns, id)) ?? 0;
    },
    async bumpOwnerEpoch(ns, id) {
      if (!state.storeAvailable) throw new Error('Private epoch diagnostic');
      const next = (epochs.get(key(ns, id)) ?? 0) + 1;
      epochs.set(key(ns, id), next);
      return next;
    },
  };

  return { store, rows, state, epochs };
}
