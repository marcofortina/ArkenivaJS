// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import type { PoolConnection, Prepare } from 'mariadb';
import type { SqlObservationPorts } from '@arkenivajs/database/support';
import { MariadbConnection } from '../../dist/connection.js';

type Row = Record<string, unknown>;
/** Native Promise/stream boundary faults; real compatibility has an independent server suite. */
export interface NativePlan {
  rows?: Row[];
  header?: Row;
  error?: Error;
  hold?: boolean;
  multiple?: boolean;
  mode?: string;
  encoding?: string;
  zone?: string;
  status?: number;
  prepareGate?: Promise<void>;
  prepareFails?: boolean;
  prepareError?: unknown;
  closeFails?: boolean;
  closeError?: unknown;
  streamCloseFails?: boolean;
}

export function nativeDouble(observation: SqlObservationPorts = {}, minimum = 0) {
  const connection = new MariadbConnection(
    'test',
    { pool: { connectionLimit: 1, minimumIdle: 0 }, minimum },
    observation,
  );
  const pool = connection.native();
  const nativeEnd = pool.end.bind(pool);
  const plans: NativePlan[] = [],
    releases: boolean[] = [],
    controls: string[] = [],
    clients: PoolConnection[] = [];
  const submissions: { text: string; values: unknown }[] = [];
  const failures = new Map<string, unknown>();
  const statementCloses: number[] = [];
  let acquisition = Promise.resolve();
  let acquireFailure: Error | undefined,
    releaseFailure: unknown,
    releaseFails = false,
    endFailure: Error | undefined;
  let sessionResult: unknown;
  pool.getConnection = async () => {
    await acquisition;
    if (acquireFailure) throw acquireFailure;
    const client = new EventEmitter() as PoolConnection;
    client.on('error', () => undefined);
    let state = {
      mode: 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
      encoding: 'utf8mb4',
      zone: '+00:00',
    };
    Object.defineProperty(client, 'info', { value: { status: 2 }, configurable: true });
    const status = (value: number) =>
      Object.defineProperty(client, 'info', { value: { status: value }, configurable: true });
    const streams = new Set<Readable>();
    client.reset = async () => {
      if (failures.has('RESET')) throw failures.get('RESET');
      state = {
        mode: 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION',
        encoding: 'utf8mb4',
        zone: '+00:00',
      };
      status(2);
    };
    client.query = (async (text: string) => {
      controls.push(text);
      if (failures.has(text)) throw failures.get(text);
      if (text === 'START TRANSACTION') status(3);
      if (text === 'COMMIT' || text === 'ROLLBACK') status(2);
      return text.startsWith('SELECT @@session')
        ? sessionResult === undefined
          ? [{ ...state }]
          : sessionResult
        : {};
    }) as PoolConnection['query'];
    client.prepare = (async (text: string) => {
      const plan = plans.shift() ?? { rows: [{ healthy: 1 }] };
      if (plan.prepareGate) await plan.prepareGate;
      if (plan.prepareFails) throw plan.prepareError;
      const prepared: Prepare<unknown[]> = {
        id: 1,
        async execute() {
          throw new Error('The portable adapter must use bounded prepared streams');
        },
        executeStream(values) {
          submissions.push({ text, values });
          let began = false,
            at = 0;
          const rows = plan.header ? [plan.header] : (plan.rows ?? []);
          const source = new Readable({
            objectMode: true,
            highWaterMark: 16,
            read() {
              if (!began) {
                began = true;
                if (plan.mode !== undefined) state.mode = plan.mode;
                if (plan.encoding !== undefined) state.encoding = plan.encoding;
                if (plan.zone !== undefined) state.zone = plan.zone;
                if (plan.status !== undefined) status(plan.status);
                if (!plan.header) this.emit('fields', []);
                if (plan.multiple) this.emit('fields', []);
                if (plan.error) {
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
          }) as Readable & { close(): void };
          source.close = () => {
            if (plan.streamCloseFails) throw new Error('Native stream cleanup failed');
          };
          streams.add(source);
          source.once('close', () => streams.delete(source));
          return source;
        },
        close() {
          statementCloses.push(1);
          if (plan.closeFails) throw plan.closeError;
        },
      };
      return prepared;
    }) as PoolConnection['prepare'];
    client.release = async () => {
      releases.push(false);
      if (releaseFails) throw releaseFailure;
    };
    client.destroy = () => {
      releases.push(true);
      for (const source of streams) source.destroy(new Error('Native socket closed'));
      if (releaseFails) throw releaseFailure;
    };
    clients.push(client);
    return client;
  };
  pool.end = async () => {
    await nativeEnd();
    if (endFailure) throw endFailure;
  };
  return {
    connection,
    pool,
    plans,
    releases,
    controls,
    clients,
    submissions,
    failures,
    statementCloses,
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
