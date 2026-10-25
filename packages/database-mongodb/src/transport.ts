import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { MongoClient, MongoServerError, BSON } from 'mongodb';
import type { ClientSession } from 'mongodb';
import { KitError } from '@arkenivajs/core';
import type { MongoConfiguration } from './config.js';
import type { MongoOutcome } from './errors.js';

/** Native writes use CSOT; cursor operations additionally accept the SDK's public AbortSignal. */
export interface MongoCallScope extends MongoOutcome {
  readonly signal: AbortSignal;
  readonly timeoutMs: number;
  readonly began: number;
  session?: ClientSession;
  commitSubmitted?: boolean;
  commitAcknowledged?: boolean;
  abortSubmitted?: boolean;
  abortAcknowledged?: boolean;
  transactionUsed?: boolean;
  closingCursor?: boolean;
  readonly cleanupFailures: unknown[];
}

/** Keep native CSOT inside the remaining monotonic budget, without overflowing Node timers. */
export function mongoNativeBudget(scope: MongoCallScope): number {
  if (scope.signal.aborted) {
    if (scope.signal.reason instanceof KitError && scope.signal.reason.code === 'EK_TIMEOUT')
      throw scope.signal.reason;
    throw new KitError({
      code: 'EK_ABORTED',
      message: 'MongoDB operation aborted',
      cause: scope.signal.reason,
    });
  }
  const remaining = Math.ceil(scope.timeoutMs - (performance.now() - scope.began));
  if (remaining <= 0)
    throw new KitError({ code: 'EK_TIMEOUT', message: 'MongoDB operation timed out' });
  // Zero disables native CSOT for very large budgets; the framework still owns its monotonic deadline.
  return remaining > 2_147_483_647 ? 0 : remaining;
}

interface Tracked {
  readonly scope: MongoCallScope;
  readonly kind: 'commitTransaction' | 'abortTransaction' | 'killCursors';
}

/** The actual MongoClient owns TLS, authentication, BSON, server selection and pooled connections. */
export class MongoTransport {
  readonly client: MongoClient;
  private readonly calls = new AsyncLocalStorage<MongoCallScope>();
  private readonly cleanupCommands = new Map<number, Tracked>();

  private remember(scope: MongoCallScope, cause: unknown, onOverflow: () => void): void {
    if (scope.cleanupFailures.length < 16) scope.cleanupFailures.push(cause);
    else {
      try {
        onOverflow();
      } catch {
        /* Cleanup evidence remains bounded even when its diagnostic sink fails. */
      }
    }
  }

  constructor(configuration: MongoConfiguration, diagnosticFault: () => void) {
    this.client = new MongoClient(configuration.url, configuration.native);
    this.client.on('error', () => {
      try {
        diagnosticFault();
      } catch {
        /* Native error events remain observed. */
      }
    });
    this.client.on('commandStarted', (event) => {
      try {
        const scope = this.calls.getStore();
        if (!scope) return;
        scope.submitted = true;
        const kind = event.commandName;
        if (scope.session) {
          const expected = scope.session.id?.id,
            actual = event.command.lsid?.id;
          if (
            !(expected instanceof BSON.Binary) ||
            !(actual instanceof BSON.Binary) ||
            !Buffer.from(expected.buffer).equals(Buffer.from(actual.buffer))
          )
            return;
          if (
            event.command.autocommit === false &&
            !['commitTransaction', 'abortTransaction'].includes(kind)
          )
            scope.transactionUsed = true;
        }
        if (kind === 'killCursors' && !scope.closingCursor) return;
        if (!['commitTransaction', 'abortTransaction', 'killCursors'].includes(kind)) return;
        if (this.cleanupCommands.size >= 256)
          throw new Error('MongoDB cleanup observation capacity exceeded');
        if (kind === 'commitTransaction') scope.commitSubmitted = true;
        if (kind === 'abortTransaction') scope.abortSubmitted = true;
        this.cleanupCommands.set(event.requestId, { scope, kind: kind as Tracked['kind'] });
      } catch {
        try {
          diagnosticFault();
        } catch {
          /* Diagnostics cannot alter native submission. */
        }
      }
    });
    this.client.on('commandSucceeded', (event) => {
      try {
        const tracked = this.cleanupCommands.get(event.requestId);
        if (!tracked) return;
        this.cleanupCommands.delete(event.requestId);
        // A successful command envelope can still contain a write-concern failure.
        const reply = event.reply;
        if (
          reply &&
          typeof reply === 'object' &&
          'writeConcernError' in reply &&
          reply.writeConcernError
        ) {
          this.remember(
            tracked.scope,
            new Error('MongoDB cleanup write concern was not acknowledged'),
            diagnosticFault,
          );
          return;
        }
        if (tracked.kind === 'commitTransaction') tracked.scope.commitAcknowledged = true;
        if (tracked.kind === 'abortTransaction') tracked.scope.abortAcknowledged = true;
      } catch {
        try {
          diagnosticFault();
        } catch {
          /* Diagnostics cannot replace an acknowledged native result. */
        }
      }
    });
    this.client.on('commandFailed', (event) => {
      try {
        const tracked = this.cleanupCommands.get(event.requestId);
        if (!tracked) return;
        this.cleanupCommands.delete(event.requestId);
        if (
          tracked.kind === 'abortTransaction' &&
          event.failure instanceof MongoServerError &&
          event.failure.code === 251
        )
          tracked.scope.abortAcknowledged = true;
        else if (tracked.kind !== 'commitTransaction')
          this.remember(tracked.scope, event.failure, diagnosticFault);
      } catch {
        try {
          diagnosticFault();
        } catch {
          /* The native failure retains its original outcome. */
        }
      }
    });
  }

  /** Async-local ownership changes neither global instrumentation nor another call's cancellation. */
  run<T>(scope: MongoCallScope, work: () => Promise<T>): Promise<T> {
    return this.calls.run(scope, work);
  }
}
