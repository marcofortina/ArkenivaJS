// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import type { Pool, PoolConnection } from 'mysql2';
import type { SqlObservationPorts } from '@arkenivajs/database/support';
import { MysqlConnection } from '../../dist/connection.js';

type Row = Record<string, unknown>;
/** Test-only native boundary faults; real compatibility is checked with disposable MySQL servers. */
export interface NativePlan {
  rows?: Row[];
  header?: Row;
  error?: Error;
  hold?: boolean;
  multiple?: boolean;
  mode?: string;
  encoding?: string;
  zone?: string;
}

export function nativeDouble(observation: SqlObservationPorts = {}, minimum = 0) {
  const connection = new MysqlConnection(
    'test',
    { pool: { connectionLimit: 1 }, minimum },
    observation,
  );
  const pool = connection.native();
  const plans: NativePlan[] = [];
  const releases: boolean[] = [];
  const controls: string[] = [];
  const clients: PoolConnection[] = [];
  const submissions: { text: string; values: unknown }[] = [];
  const failures = new Map<string, Error>();
  let sessionResult: unknown;
  let acquisition = Promise.resolve();
  let acquireFailure: Error | undefined,
    releaseFailure: unknown,
    releaseFails = false,
    endFailure: Error | undefined;
  pool.getConnection = ((callback: (error: Error | null, client?: PoolConnection) => void) => {
    void acquisition.then(() => {
      if (acquireFailure) {
        callback(acquireFailure);
        return;
      }
      const client = new EventEmitter() as PoolConnection;
      let state = {
        mode: 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
        encoding: 'utf8mb4',
        zone: '+00:00',
      };
      const streams = new Set<Readable>();
      client.reset = ((done: (error: Error | null) => void) => {
        state = {
          mode: 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
          encoding: 'utf8mb4',
          zone: '+00:00',
        };
        globalThis.queueMicrotask(() => done(failures.get('RESET') ?? null));
      }) as PoolConnection['reset'];
      client.query = ((text: string, done: (error: Error | null, result?: unknown) => void) => {
        controls.push(text);
        globalThis.queueMicrotask(() =>
          done(
            failures.get(text) ?? null,
            text.startsWith('SELECT @@session')
              ? sessionResult === undefined
                ? [{ ...state }]
                : sessionResult
              : {},
          ),
        );
        return new EventEmitter();
      }) as PoolConnection['query'];
      client.execute = ((text: string, values: unknown) => {
        submissions.push({ text, values });
        const plan = plans.shift() ?? { rows: [{ healthy: '1' }] };
        const command = new EventEmitter() as EventEmitter & { stream(): Readable };
        command.stream = () => {
          let began = false,
            at = 0;
          const rows = plan.header ? [plan.header] : (plan.rows ?? []);
          const source = new Readable({
            objectMode: true,
            highWaterMark: 1,
            read() {
              if (!began) {
                began = true;
                if (plan.mode !== undefined) state.mode = plan.mode;
                if (plan.encoding !== undefined) state.encoding = plan.encoding;
                if (plan.zone !== undefined) state.zone = plan.zone;
                this.emit('fields', plan.header ? undefined : []);
                if (plan.multiple) this.emit('fields', []);
                if (plan.error) {
                  command.emit('error', plan.error);
                  this.destroy(plan.error);
                  return;
                }
              }
              if (plan.hold || this.destroyed) return;
              while (at < rows.length) {
                if (!this.push(rows[at++])) return;
              }
              this.push(null);
            },
          });
          streams.add(source);
          source.once('close', () => streams.delete(source));
          return source;
        };
        return command;
      }) as PoolConnection['execute'];
      client.release = () => {
        releases.push(false);
        if (releaseFails) throw releaseFailure;
      };
      client.destroy = () => {
        releases.push(true);
        for (const source of streams) source.destroy(new Error('Native socket closed'));
        if (releaseFails) throw releaseFailure;
      };
      clients.push(client);
      pool.emit('connection', client);
      callback(null, client);
    });
  }) as Pool['getConnection'];
  pool.end = ((callback: (error: Error | null) => void) =>
    globalThis.queueMicrotask(() => callback(endFailure ?? null))) as Pool['end'];
  return {
    connection,
    pool,
    plans,
    releases,
    controls,
    clients,
    submissions,
    failures,
    gate(promise: Promise<void>) {
      acquisition = promise;
    },
    failAcquisition(error: Error) {
      acquireFailure = error;
    },
    failRelease(error: unknown) {
      releaseFails = true;
      releaseFailure = error;
    },
    failEnd(error: Error) {
      endFailure = error;
    },
    sessionResult(value: unknown) {
      sessionResult = value;
    },
  };
}
