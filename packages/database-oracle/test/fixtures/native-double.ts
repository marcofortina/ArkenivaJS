import type { TestContext } from 'node:test';
import oracledb from 'oracledb';
import type {
  Pool,
  Connection,
  ExecuteOptions,
  BindParameters,
  Metadata,
  ResultSet,
} from 'oracledb';
import type { SqlObservationPorts } from '@arkenivajs/database/support';
import { OracleConnection } from '../../dist/connection.js';

type Row = Record<string, unknown>;
/** Public native boundaries are fault-injected without an Oracle Client or server. */
export interface Plan {
  rows?: Row[];
  count?: number;
  types?: Metadata<unknown>[];
  error?: unknown;
  fails?: boolean;
  hold?: Promise<void>;
  fetchFails?: boolean;
  cursorCloseFails?: boolean;
  transaction?: boolean | undefined;
}

export async function nativeDouble(context: TestContext, observation: SqlObservationPorts = {}) {
  const plans: Plan[] = [],
    controls: string[] = [],
    releases: boolean[] = [],
    fetches: number[] = [];
  const submissions: { text: string; binds: BindParameters; options: ExecuteOptions }[] = [];
  const clients: Connection[] = [];
  const faults = new Map<string, unknown>();
  let gate: Promise<void> = Promise.resolve(),
    calls = 0,
    commits = 0,
    rollbacks = 0,
    cursorCloses = 0,
    breaks = 0,
    poolCloses = 0;
  const pool = {
    poolMax: 1,
    connectionsOpen: 0,
    connectionsInUse: 0,
    async getConnection() {
      calls++;
      await gate;
      if (faults.has('acquire')) throw faults.get('acquire');
      pool.connectionsOpen++;
      pool.connectionsInUse++;
      const client = {
        callTimeout: 0,
        transactionInProgress: false,
        async execute(text: string, binds: BindParameters, options: ExecuteOptions) {
          if (text.startsWith('ALTER SESSION') || text === 'SET TRANSACTION READ WRITE') {
            controls.push(text);
            if (faults.has(text)) throw faults.get(text);
            if (text.startsWith('SET TRANSACTION')) client.transactionInProgress = true;
            return {};
          }
          submissions.push({ text, binds, options });
          const plan = plans.shift() ?? { rows: [{ healthy: '1' }] };
          if (plan.hold) await plan.hold;
          if (plan.fails) throw plan.error;
          if (plan.types)
            for (const metadata of plan.types) options.fetchTypeHandler!(metadata, plan.types);
          if ('transaction' in plan) client.transactionInProgress = plan.transaction as boolean;
          if (!plan.rows) return plan.count === undefined ? {} : { rowsAffected: plan.count };
          let offset = 0;
          const cursor = {
            async getRows(count: number) {
              fetches.push(count);
              if (plan.fetchFails) throw new Error('Native fetch failed');
              const rows = plan.rows!.slice(offset, offset + count);
              offset += rows.length;
              return rows;
            },
            async close() {
              cursorCloses++;
              if (plan.cursorCloseFails) throw new Error('Native cursor close failed');
            },
          } as ResultSet<Row>;
          return { resultSet: cursor };
        },
        async rollback() {
          rollbacks++;
          if (faults.has('rollback')) throw faults.get('rollback');
          client.transactionInProgress = false;
        },
        async commit() {
          commits++;
          client.transactionInProgress = false;
          if (faults.has('commitGate')) await faults.get('commitGate');
          if (faults.has('commit')) throw faults.get('commit');
        },
        async break() {
          breaks++;
          if (faults.has('break')) throw faults.get('break');
        },
        async close(options: { drop: boolean }) {
          releases.push(options.drop);
          pool.connectionsInUse--;
          if (options.drop) pool.connectionsOpen--;
          if (faults.has('release')) throw faults.get('release');
        },
      };
      if (faults.has('callTimeout'))
        Object.defineProperty(client, 'callTimeout', {
          set() {
            throw faults.get('callTimeout');
          },
        });
      clients.push(client as unknown as Connection);
      return client as unknown as Connection;
    },
    async close() {
      poolCloses++;
      if (faults.has('poolClose')) throw faults.get('poolClose');
    },
  };
  context.mock.method(oracledb, 'createPool', async () => {
    if (faults.has('createPool')) throw faults.get('createPool');
    return pool as unknown as Pool;
  });
  const connection = await OracleConnection.create(
    'test',
    { poolMin: 0, poolMax: 1 },
    observation,
    'thin',
  );
  return {
    connection,
    pool,
    plans,
    controls,
    releases,
    fetches,
    submissions,
    clients,
    faults,
    gate(value: Promise<void>) {
      gate = value;
    },
    get counts() {
      return { calls, commits, rollbacks, cursorCloses, breaks, poolCloses };
    },
  };
}
