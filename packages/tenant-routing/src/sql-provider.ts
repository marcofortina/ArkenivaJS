// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { types } from 'node:util';
import type { SqlProvider, SqlTransaction } from '@arkenivajs/core';
import type { TenantRegistryProvider, TenantRegistrySqlOptions } from './contracts.js';
import { registryFailure } from './errors.js';
import { ActivationHistory, captureMethod, data, registryOperation } from './provider-support.js';

const maximumBytes = 8388608;
const keyPattern = /^[a-z][a-z0-9._-]{0,127}$/;
const prefixPattern = /^(?:[a-z][a-z0-9_]{0,62}\.)?[a-z][a-z0-9_]{0,47}$/;

function generation(value: unknown): number {
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value) && value > 0) return value;
  } else if (
    typeof value === 'bigint' ||
    (typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value))
  ) {
    const result = BigInt(value);
    if (result > 0n && result <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(result);
  }
  throw registryFailure();
}
function instant(value: unknown): string {
  if (types.isDate(value)) return Date.prototype.toISOString.call(value);
  if (typeof value === 'string' && value.length <= 64) {
    // Native adapters may preserve UTC SQL timestamps as text instead of truncating submilliseconds.
    const match =
      /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00(?::?00)?)$/.exec(value);
    if (!match) throw registryFailure();
    const milliseconds = `${match[1]}T${match[2]}.${(match[3] ?? '').padEnd(3, '0').slice(0, 3)}Z`;
    const parsed = Date.parse(milliseconds);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== milliseconds)
      throw registryFailure();
    return `${match[1]}T${match[2]}${match[3] ? '.' + match[3] : ''}Z`;
  }
  throw registryFailure();
}

/** Existing application SQL pools own all I/O, transactions and cancellation. No driver is initialized here. */
export function tenantRegistrySqlProvider(input: TenantRegistrySqlOptions): TenantRegistryProvider {
  try {
    const fields = data(input, [
      'connectionName',
      'sql',
      'storageKey',
      'storagePrefixes',
      'activationCheckpoint',
    ]);
    const connectionName = fields.connectionName,
      storageKey = fields.storageKey;
    if (
      typeof connectionName !== 'string' ||
      !/^[a-z][a-z0-9_-]{0,62}$/.test(connectionName) ||
      typeof storageKey !== 'string' ||
      !keyPattern.test(storageKey)
    )
      throw registryFailure();
    const prefixes =
      fields.storagePrefixes === undefined
        ? { tenant_registry: 'tenant_registry' }
        : data(fields.storagePrefixes);
    if (Object.keys(prefixes).length > 128) throw registryFailure();
    for (const [key, prefix] of Object.entries(prefixes)) {
      if (!keyPattern.test(key) || typeof prefix !== 'string' || !prefixPattern.test(prefix))
        throw registryFailure();
    }
    if (!Object.hasOwn(prefixes, storageKey)) throw registryFailure();
    const prefix = prefixes[storageKey];
    const sql = fields.sql as SqlProvider;
    for (const name of ['query', 'queryOne', 'execute', 'ping', 'stats', 'native'])
      captureMethod(sql, name);
    const transaction = captureMethod<SqlProvider['transaction']>(sql, 'transaction');
    const history = new ActivationHistory(
      fields.activationCheckpoint as TenantRegistrySqlOptions['activationCheckpoint'],
    );
    const scope =
      'sql:' +
      createHash('sha256')
        .update(JSON.stringify([connectionName, storageKey, prefix]))
        .digest('hex');
    // Only the allowlisted identifier is compiled. All query values use native named bindings.
    // The server caps text materialization; the final validator also enforces exact UTF-8 byte size.
    const text = `SELECT a.activation_generation, a.revision_key, a.activated_at, s.content_checksum, CASE WHEN OCTET_LENGTH(s.body) <= :max_bytes THEN s.body ELSE NULL END AS body FROM ${prefix}_active a JOIN ${prefix}_snapshot s ON s.revision_key = a.revision_key WHERE a.registry_key = :registry_key`;
    let loading = false;
    return Object.freeze({
      async loadSnapshot(options) {
        if (loading) throw registryFailure();
        loading = true;
        let started = false;
        try {
          return await registryOperation(async (operation, check) => {
            started = true;
            try {
              check();
              const row = await transaction(
                connectionName,
                async (input: SqlTransaction) => {
                  check();
                  const query = captureMethod<SqlTransaction['query']>(input, 'query');
                  const result = await query(
                    { text, bindings: { registry_key: 'active', max_bytes: maximumBytes } },
                    { ...operation, maxRows: 2 },
                  );
                  check();
                  const clean = data(result, ['rows', 'rowCount', 'metadata']);
                  if (
                    types.isProxy(clean.rows) ||
                    !Array.isArray(clean.rows) ||
                    clean.rows.length !== 1
                  )
                    throw registryFailure();
                  const item = Object.getOwnPropertyDescriptor(clean.rows, '0');
                  if (!item || !('value' in item)) throw registryFailure();
                  return data(item.value, [
                    'activation_generation',
                    'revision_key',
                    'activated_at',
                    'content_checksum',
                    'body',
                  ]);
                },
                operation,
              );
              check();
              if (
                typeof row.revision_key !== 'string' ||
                row.revision_key.length > 128 ||
                typeof row.content_checksum !== 'string' ||
                row.content_checksum.length !== 71 ||
                typeof row.body !== 'string'
              )
                throw registryFailure();
              const { parseRegistryJson, validateRegistry } = await import('./registry.js');
              check();
              const body = data(parseRegistryJson(row.body, maximumBytes), [
                'schemaVersion',
                'operations',
                'implementations',
                'bindings',
              ]);
              const snapshot = validateRegistry(
                {
                  ...body,
                  revision: row.revision_key,
                  activationGeneration: generation(row.activation_generation),
                  activatedAt: instant(row.activated_at),
                  contentChecksum: row.content_checksum,
                },
                maximumBytes,
              );
              check();
              await history.accept(snapshot, scope, operation, check);
              return snapshot;
            } finally {
              loading = false;
            }
          }, options);
        } catch {
          throw registryFailure();
        } finally {
          if (!started) loading = false;
        }
      },
    } satisfies TenantRegistryProvider);
  } catch {
    throw registryFailure();
  }
}
