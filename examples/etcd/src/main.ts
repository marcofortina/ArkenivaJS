// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import type { EtcdValue, EtcdWatchHandle, EtcdLease } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { etcdPlugin } from '@arkenivajs/database-etcd';

/** Application JSON conversion is explicit; exact revision metadata is represented as decimal text. */
export function modeDTO(value: EtcdValue) {
  const decoded: unknown = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(value.value),
  );
  if (
    !decoded ||
    typeof decoded !== 'object' ||
    !('mode' in decoded) ||
    typeof decoded.mode !== 'string'
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Stored mode requires a string field',
    });
  return Object.freeze({
    mode: decoded.mode,
    revision: value.revision.toString(),
    version: value.version.toString(),
  });
}

/** Operate only on randomly owned keys of an explicitly disposable authenticated endpoint. */
export async function runEtcdExample() {
  if (process.env.ARKENIVA_ETCD_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The etcd example requires an explicitly disposable server',
    });
  if (!process.env.ARKENIVA_ETCD_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_ETCD_URL is required' });
  const app = await createApplication({
    service: { name: 'etcd-configuration-example', version: '1.0.0', environment: 'development' },
    plugins: [etcdPlugin()],
    databases: { configuration: { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_URL' } },
  });
  const base = 'example:' + randomBytes(12).toString('hex') + ':',
    key = base + 'mode',
    leased = base + 'presence';
  let ready = false,
    watch: EtcdWatchHandle | undefined,
    lease: EtcdLease | undefined;
  let result:
    | (ReturnType<typeof modeDTO> & {
        firstAccepted: boolean;
        secondAccepted: boolean;
        leaseDeleted: boolean;
      })
    | undefined;
  const failures: unknown[] = [];
  try {
    await app.start();
    ready = true;
    const etcd = app.etcd!;
    assert.equal(await etcd.get(key), null);
    watch = await etcd.watch(base);
    const iterator = watch[Symbol.asyncIterator]();
    const value = new TextEncoder().encode(JSON.stringify({ mode: 'enabled' }));
    const firstAccepted = await etcd.compareAndSwap({ key, expectedRevision: 0n, value });
    const secondAccepted = await etcd.compareAndSwap({ key, expectedRevision: 0n, value });
    assert.equal(firstAccepted, true);
    assert.equal(secondAccepted, false);
    const changed = await within(() => iterator.next(), { timeoutMs: 5000 });
    assert.equal(changed.value.type, 'put');
    assert.equal(changed.value.key, key);
    assert.deepEqual(changed.value.value, value);
    const mode = modeDTO((await etcd.get(key))!);
    assert.equal(mode.mode, 'enabled');
    assert.equal(mode.version, '1');
    lease = await etcd.grantLease(30);
    lease.keepAlive();
    await etcd.put(leased, Uint8Array.from([0, 255]), { leaseId: lease.id });
    const presence = await within(() => iterator.next(), { timeoutMs: 5000 });
    assert.equal(presence.value.key, leased);
    assert.deepEqual(presence.value.value, Uint8Array.from([0, 255]));
    await lease.revoke();
    const removed = await within(() => iterator.next(), { timeoutMs: 5000 });
    assert.equal(removed.value.type, 'delete');
    assert.equal(removed.value.key, leased);
    const leaseDeleted = (await etcd.get(leased)) === null;
    assert.equal(leaseDeleted, true);
    assert.equal(await etcd.delete(key), true);
    result = { firstAccepted, secondAccepted, ...mode, leaseDeleted };
  } catch (cause) {
    failures.push(cause);
  } finally {
    try {
      const cleanups = await Promise.allSettled([
        ...(watch ? [watch.close()] : []),
        ...(lease ? [lease.revoke()] : []),
        ...(ready ? [app.etcd!.delete(key), app.etcd!.delete(leased)] : []),
      ]);
      failures.push(
        ...cleanups.flatMap((result) => (result.status === 'rejected' ? [result.reason] : [])),
      );
    } finally {
      try {
        await app.stop();
      } catch (cause) {
        failures.push(cause);
      }
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, 'The etcd example and cleanup failed');
  assert.ok(result);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runEtcdExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The etcd example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
