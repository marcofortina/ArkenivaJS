// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import type { Writable } from 'node:stream';
import { pino } from 'pino';
import type { Logger as PinoLogger } from 'pino';
import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type {
  Logger,
  LogLevel,
  OperationOptions,
  ApplicationOptions,
  Plugin,
} from '@arkenivajs/core';
import { freezeData, within } from '@arkenivajs/core/support';

export type { Logger, LogLevel } from '@arkenivajs/core';
/** Structured fields are explicit diagnostic data, never an identity assertion. */
export type LogFields = Readonly<Record<string, unknown>>;
/** Low-cardinality local transport counters; write acknowledgement is not fsync durability. */
export interface LogStats {
  readonly emitted: number;
  readonly dropped: number;
  readonly failedWrites: number;
  readonly flushFailures: number;
  readonly pendingBytes: number;
}
/** A logger owns its context scope and may explicitly own its destination lifetime. */
export interface ManagedLogger extends Logger {
  child(fields: LogFields): ManagedLogger;
  run<T>(fields: LogFields, work: () => T): T;
  /** Background resources must not inherit an unrelated request's log fields. */
  withoutScope<T>(work: () => T): T;
  stats(): LogStats;
  close(options?: OperationOptions): Promise<void>;
}
/** Controls for the Pino adapter; all transports receive redacted bounded JSON lines. */
export interface LoggerOptions {
  service: ApplicationOptions['service'];
  level?: LogLevel;
  destination?: Writable;
  ownDestination?: boolean;
  bufferLimitBytes?: number;
  redactPaths?: readonly string[];
  redactValues?: readonly string[];
  onDiagnostic?: (event: Readonly<{ code: 'EK_BACKEND_UNAVAILABLE'; message: string }>) => void;
}
const EMPTY_FIELDS: LogFields = Object.freeze({});
const levels = new Set<LogLevel>(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']);
const protectedKeys = new Set([
  'service',
  'serviceVersion',
  'environment',
  'traceId',
  'spanId',
  'requestId',
]);
const sensitiveKey =
  /^(password|passwd|authorization|proxy-authorization|cookie|set-cookie|token|accessToken|refreshToken|clientSecret|secret|apiKey|x-api-key|connectionString)$/i;

/** EK-LOG-001: create an isolated logger without opening network connections. */
export function createLogger(options: LoggerOptions): ManagedLogger {
  if (!options || typeof options !== 'object')
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Logger options are required' });
  const level = options.level ?? 'info';
  const limit = options.bufferLimitBytes ?? 1_048_576;
  if (
    !levels.has(level) ||
    !Number.isSafeInteger(limit) ||
    limit <= 0 ||
    !options.service ||
    typeof options.service.name !== 'string' ||
    !/^[a-z][a-z0-9-]{0,62}$/.test(options.service.name) ||
    options.service.name.includes('\n') ||
    typeof options.service.version !== 'string' ||
    options.service.version.length === 0 ||
    !['development', 'test', 'production'].includes(options.service.environment) ||
    (options.redactValues?.length ?? 0) > 128 ||
    (options.redactValues ?? []).some((value) => typeof value !== 'string' || value.length === 0)
  ) {
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid logger options' });
  }
  const secrets = [...(options.redactValues ?? [])];
  const destination = options.destination ?? process.stdout;
  const context = new AsyncLocalStorage<LogFields>();
  const counters = { emitted: 0, dropped: 0, failedWrites: 0, flushFailures: 0, pendingBytes: 0 };
  const waiters = new Set<() => void>();
  let state: 'open' | 'closing' | 'closed' = 'open';
  let failure: unknown,
    failed = false,
    diagnosticSent = false;
  let closing: Promise<void> | undefined;
  const notify = (): void => {
    for (const waiter of [...waiters]) waiter();
  };
  const diagnostic = (): void => {
    if (diagnosticSent) return;
    diagnosticSent = true;
    const event = Object.freeze({
      code: 'EK_BACKEND_UNAVAILABLE' as const,
      message: 'A log transport operation did not complete',
    });
    try {
      if (options.onDiagnostic) options.onDiagnostic(event);
      else process.stderr.write(JSON.stringify(event) + '\n');
    } catch {
      /* A diagnostic callback cannot replace an application outcome. */
    }
  };
  const fail = (error: unknown, writeFailure = false): void => {
    failed = true;
    failure = error;
    if (writeFailure) counters.failedWrites++;
    diagnostic();
    notify();
  };
  if (
    typeof destination.write !== 'function' ||
    typeof destination.on !== 'function' ||
    typeof destination.off !== 'function'
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Logger destination must be a writable stream',
    });
  destination.on('error', fail);
  const text = (value: string): string => {
    let safe = value
      .replace(/\bbearer\s+\S+/gi, 'Bearer [REDACTED]')
      .replace(
        /\b(password|token|clientSecret|authorization|cookie|apiKey)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
        '$1=[REDACTED]',
      )
      .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, '$1[REDACTED]@');
    for (const secret of secrets) safe = safe.split(secret).join('[REDACTED]');
    return safe.slice(0, 8192);
  };
  const fields = (input: LogFields): Record<string, unknown> => {
    if (!input || typeof input !== 'object' || Array.isArray(input))
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Log fields must be an object' });
    const seen = new Set<unknown>();
    let remaining = 256;
    const visit = (value: unknown, depth: number): unknown => {
      if (--remaining < 0 || depth > 12) return '[Truncated]';
      if (typeof value === 'string') return text(value);
      if (typeof value === 'bigint') return value.toString();
      if (
        value === null ||
        typeof value === 'number' ||
        typeof value === 'boolean' ||
        value === undefined
      )
        return value;
      if (typeof value !== 'object') return '[Unsupported]';
      if (value instanceof KitError) return KitError.prototype.toSafeJSON.call(value);
      if (value instanceof Error) return { name: 'Error', message: 'An operation failed' };
      if (value instanceof Uint8Array) return '[Binary]';
      if (value instanceof Date) {
        const stamp = Date.prototype.getTime.call(value);
        return Number.isFinite(stamp) ? new Date(stamp).toISOString() : '[InvalidDate]';
      }
      if (seen.has(value)) return '[Circular]';
      seen.add(value);
      try {
        const result: Record<string, unknown> | unknown[] = Array.isArray(value) ? [] : {};
        for (const key in value) {
          if (remaining-- <= 0) break;
          if (!Object.hasOwn(value, key)) continue;
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          if (
            ['__proto__', 'constructor', 'prototype'].includes(key) ||
            (depth === 0 && ['level', 'time', 'msg', 'pid', 'hostname'].includes(key))
          )
            continue;
          Object.defineProperty(result, key, {
            enumerable: true,
            value: sensitiveKey.test(key)
              ? '[REDACTED]'
              : descriptor && 'value' in descriptor
                ? visit(descriptor.value, depth + 1)
                : '[Unavailable]',
          });
        }
        return result;
      } catch {
        return '[Unserializable]';
      } finally {
        seen.delete(value);
      }
    };
    try {
      const safe = visit(input, 0);
      return safe && typeof safe === 'object' && !Array.isArray(safe)
        ? (safe as Record<string, unknown>)
        : { serialization: safe };
    } catch {
      return { serialization: '[Unserializable]' };
    }
  };
  const merge = (parent: LogFields, next: LogFields): Record<string, unknown> => {
    const result = { ...parent, ...next };
    for (const key of protectedKeys) if (Object.hasOwn(parent, key)) result[key] = parent[key];
    return result;
  };
  const transport = {
    write(line: string): void {
      const bytes = Buffer.byteLength(line);
      if (failed || counters.pendingBytes + bytes > limit) {
        counters.dropped++;
        diagnostic();
        return;
      }
      counters.pendingBytes += bytes;
      counters.emitted++;
      try {
        destination.write(line, (error) => {
          counters.pendingBytes -= bytes;
          if (error) fail(error, true);
          notify();
        });
      } catch (error) {
        counters.pendingBytes -= bytes;
        fail(error, true);
      }
    },
  };
  let native: PinoLogger;
  const base = freezeData({
    service: options.service.name,
    serviceVersion: options.service.version,
    environment: options.service.environment,
  });
  try {
    native = pino(
      {
        level,
        base,
        timestamp: pino.stdTimeFunctions.isoTime,
        redact: { paths: [...(options.redactPaths ?? [])], censor: '[REDACTED]' },
      },
      transport,
    );
  } catch (cause) {
    destination.off('error', fail);
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Logger could not be configured',
      cause,
    });
  }
  const open = (): void => {
    if (state !== 'open')
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Logger is closed' });
  };
  const flush = async (operation: OperationOptions = {}): Promise<void> => {
    if (state === 'closed')
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'Logger is closed' });
    let waiter: (() => void) | undefined;
    try {
      await within(
        () =>
          new Promise<void>((resolve, reject) => {
            waiter = () => {
              if (failed)
                reject(
                  new KitError({
                    code: 'EK_BACKEND_UNAVAILABLE',
                    message: 'Log transport failed',
                    cause: failure,
                  }),
                );
              else if (counters.pendingBytes === 0) resolve();
            };
            waiters.add(waiter);
            waiter();
          }),
        operation,
      );
    } catch (error) {
      counters.flushFailures++;
      diagnostic();
      throw error;
    } finally {
      if (waiter) waiters.delete(waiter);
    }
  };
  const make = (logger: PinoLogger, bound: LogFields): ManagedLogger => {
    const emit = (
      severity: Exclude<LogLevel, 'silent'>,
      message: string,
      data: LogFields = EMPTY_FIELDS,
    ): void => {
      open();
      if (typeof message !== 'string')
        throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Log message must be a string' });
      if (!data || typeof data !== 'object' || Array.isArray(data))
        throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Log fields must be an object' });
      if (!logger.isLevelEnabled(severity)) return;
      const scoped = merge(bound, context.getStore() ?? EMPTY_FIELDS);
      const emitted = merge(scoped, fields(data));
      // Pino already emits these immutable base bindings in its own JSON prefix.
      for (const key of Object.keys(base)) delete emitted[key];
      logger[severity](emitted, text(message));
    };
    return Object.freeze({
      trace: (message: string, data?: LogFields) => emit('trace', message, data),
      debug: (message: string, data?: LogFields) => emit('debug', message, data),
      info: (message: string, data?: LogFields) => emit('info', message, data),
      warn: (message: string, data?: LogFields) => emit('warn', message, data),
      error: (message: string, data?: LogFields) => emit('error', message, data),
      fatal: (message: string, data?: LogFields) => emit('fatal', message, data),
      child(data: LogFields): ManagedLogger {
        open();
        const child = freezeData(merge(bound, fields(data)));
        return make(logger.child({}), child);
      },
      setLevel(next: LogLevel): void {
        open();
        if (!levels.has(next))
          throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid log level' });
        logger.level = next;
      },
      flush,
      run<T>(data: LogFields, work: () => T): T {
        open();
        if (typeof work !== 'function')
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Log context requires a callback',
          });
        return context.run(
          freezeData(merge(merge(bound, context.getStore() ?? {}), fields(data))),
          work,
        );
      },
      withoutScope<T>(work: () => T): T {
        open();
        if (typeof work !== 'function')
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Log scope requires a callback',
          });
        return context.exit(work);
      },
      stats(): LogStats {
        return Object.freeze({ ...counters });
      },
      close(operation: OperationOptions = {}): Promise<void> {
        if (state === 'closed') return Promise.resolve();
        if (closing) return closing;
        state = 'closing';
        closing = (async () => {
          try {
            await flush(operation);
          } finally {
            state = 'closed';
            context.disable();
            if (options.ownDestination) {
              destination.once('close', () => destination.off('error', fail));
              destination.destroy();
            } else if (counters.pendingBytes === 0) destination.off('error', fail);
            else {
              const release = () => {
                if (counters.pendingBytes === 0) {
                  destination.off('error', fail);
                  waiters.delete(release);
                }
              };
              waiters.add(release);
            }
          }
        })();
        return closing;
      },
    });
  };
  return make(native, base);
}

/** Install one logger per application, initialized before ordinary resource plugins. */
export function loggingPlugin(options: Omit<LoggerOptions, 'service' | 'level'> = {}): Plugin {
  const loggers = new WeakMap<object, ManagedLogger>();
  return {
    id: 'logging',
    version: '0.1.0',
    capabilities: new Set(['logger']),
    async init(context) {
      const logger = createLogger({
        ...options,
        service: context.options.service,
        level: context.options.logging?.level ?? 'info',
      });
      try {
        context.provide(COMPONENTS.logger, logger);
        loggers.set(context, logger);
      } catch (error) {
        await logger.close();
        throw error;
      }
    },
    async close(context) {
      await loggers
        .get(context)
        ?.close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      loggers.delete(context);
    },
  };
}
