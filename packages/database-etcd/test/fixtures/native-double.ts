// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { TestContext } from 'node:test';
import { noop } from 'cockatiel';
import { EtcdConnection } from '../../dist/connection.js';
import type { EtcdObservationPorts } from '../../dist/connection.js';

export interface Plan {
  readonly value?: unknown;
  readonly error?: unknown;
  readonly fail?: boolean;
  readonly gate?: Promise<void>;
}
export const header = { cluster_id: '1', member_id: '2', revision: '10', raft_term: '3' };

/** The SDK's documented callable mock isolates fault boundaries; real-server suites verify semantics. */
export function nativeDouble(context: TestContext, observation: EtcdObservationPorts = {}) {
  const connection = new EtcdConnection(
    'test',
    {
      prefix: '/scope/',
      native: { hosts: ['http://127.0.0.1:1'], faultHandling: { global: noop, host: () => noop } },
    },
    observation,
  );
  const calls: { method: string; payload: unknown }[] = [],
    plans = new Map<string, Plan[]>();
  connection.native().mock({
    async exec<T>(_service: string, method: string, payload: unknown): Promise<T> {
      calls.push({ method, payload });
      const plan = plans.get(method)?.shift();
      if (plan?.gate) await plan.gate;
      if (plan?.fail) throw plan.error;
      if (plan && 'value' in plan) return plan.value as T;
      const defaults: Record<string, unknown> = {
        range: { header, kvs: [], count: '0', more: false },
        put: { header },
        deleteRange: { header, deleted: '1' },
        txn: { header, succeeded: true, responses: [] },
      };
      if (!(method in defaults))
        throw new Error('The native test boundary received an unexpected operation');
      return defaults[method] as T;
    },
  });
  let expectedCleanupFailure = false;
  context.after(async () => {
    try {
      await connection.close();
    } catch (cause) {
      if (!expectedCleanupFailure) throw cause;
    }
  });
  return {
    connection,
    calls,
    allowCloseFailure() {
      expectedCleanupFailure = true;
    },
    plan(method: string, plan: Plan) {
      const queue = plans.get(method) ?? [];
      queue.push(plan);
      plans.set(method, queue);
    },
    row(value: Buffer = Buffer.from([0, 255])) {
      return {
        header,
        count: '1',
        more: false,
        kvs: [
          {
            key: Buffer.from('/scope/key'),
            value,
            mod_revision: '9007199254740993',
            version: '9007199254740995',
            create_revision: '1',
            lease: '0',
          },
        ],
      };
    },
  };
}

export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
