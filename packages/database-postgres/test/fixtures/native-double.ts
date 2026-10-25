// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { EventEmitter } from 'node:events';
import type { Pool, PoolClient, QueryResult } from 'pg';
import type Cursor from 'pg-cursor';
import type { SqlObservationPorts } from '@arkenivajs/database/support';
import { PostgresConnection } from '../../dist/connection.js';

type Row = Record<string, unknown>;
/** Test-only native boundary faults; real server compatibility is checked separately. */
export interface NativePlan {
  rows?: Row[];
  command?: string;
  count?: number | null;
  fail?: boolean;
  error?: unknown;
  closeFails?: boolean;
  closeError?: unknown;
  hold?: boolean;
}
export function nativeDouble(observation: SqlObservationPorts = {}) {
  const connection = new PostgresConnection('test', { max: 1 }, observation);
  const pool = connection.native();
  const plans: NativePlan[] = [];
  const releases: boolean[] = [],
    reads: number[] = [],
    controls: string[] = [],
    submissions: { text: string; values: unknown }[] = [];
  const clients: PoolClient[] = [];
  const cleanupErrors = new Map<string, unknown>();
  let acquisition: Promise<void> = Promise.resolve();
  let acquireFailure: unknown,
    acquireFails = false,
    releaseFailure: unknown,
    releaseFails = false;
  let commitTag = 'COMMIT';
  pool.connect = (async () => {
    await acquisition;
    if (acquireFails) throw acquireFailure;
    const client = new EventEmitter() as unknown as PoolClient;
    Object.defineProperty(client, 'connection', { value: new EventEmitter() });
    const waiting: (() => void)[] = [];
    client.release = (discard?: Error | boolean) => {
      releases.push(Boolean(discard));
      for (const reject of waiting.splice(0)) reject();
      if (releaseFails) throw releaseFailure;
    };
    client.query = ((input: string | Cursor<Row>) => {
      if (typeof input === 'string') {
        controls.push(input);
        if (cleanupErrors.has(input)) return Promise.reject(cleanupErrors.get(input));
        const command = input === 'COMMIT' ? commitTag : input.split(' ')[0]!;
        client.connection.emit('readyForQuery', { status: input === 'BEGIN' ? 'T' : 'I' });
        return Promise.resolve({ rows: [], rowCount: 0, fields: [], oid: 0, command });
      }
      const cursor = input;
      const plan = plans.shift() ?? { rows: [{ healthy: 1 }] };
      const rows = plan.rows ?? [];
      let at = 0;
      submissions.push({
        text: (cursor as unknown as { text: string }).text,
        values: (cursor as unknown as { values: unknown }).values,
      });
      cursor.read = ((
        count: number,
        callback: (error: unknown, rows?: Row[], result?: QueryResult) => void,
      ) => {
        reads.push(count);
        const finish = () => {
          if (plan.fail) callback(plan.error);
          else {
            const page = rows.slice(at, at + count);
            at += page.length;
            callback(undefined, page, {
              rows: page,
              rowCount: plan.count === undefined ? rows.length : plan.count,
              command: plan.command ?? 'SELECT',
              fields: [],
              oid: 0,
            });
          }
        };
        if (plan.hold) waiting.push(() => callback(new Error('Native socket closed')));
        else globalThis.queueMicrotask(finish);
        return undefined;
      }) as Cursor<Row>['read'];
      cursor.close = (() =>
        plan.closeFails
          ? Promise.reject(plan.closeError)
          : Promise.resolve()) as Cursor<Row>['close'];
      return cursor;
    }) as PoolClient['query'];
    clients.push(client);
    pool.emit('connect', client);
    return client;
  }) as Pool['connect'];
  return {
    connection,
    pool,
    plans,
    releases,
    reads,
    controls,
    submissions,
    clients,
    cleanupErrors,
    gate(promise: Promise<void>) {
      acquisition = promise;
    },
    failAcquisition(error: unknown) {
      acquireFails = true;
      acquireFailure = error;
    },
    failRelease(error: unknown) {
      releaseFails = true;
      releaseFailure = error;
    },
    commitAs(command: string) {
      commitTag = command;
    },
  };
}
