import { Ajv } from 'ajv';
import type { AnySchema } from 'ajv';
import { isDeepStrictEqual } from 'node:util';
import { performance } from 'node:perf_hooks';
import { KitError } from './errors.js';
import type { ConfigService, OperationOptions } from './contracts.js';
export { PREPARE_PLUGIN, ACTIVATE_PLUGIN, DRAIN_PLUGIN } from './composition.js';
export type { ComposablePlugin, PreparationContext } from './composition.js';

/** EK-CONF-001: reject objects whose accessors or prototypes could execute code. */
export function copyData<T>(input: T, seen = new Set<unknown>()): T {
  if (input === null || typeof input !== 'object') {
    if (
      typeof input === 'function' ||
      typeof input === 'symbol' ||
      typeof input === 'bigint' ||
      (typeof input === 'number' && !Number.isFinite(input))
    ) {
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Unsupported data value' });
    }
    return input;
  }
  if (
    seen.size >= 64 ||
    seen.has(input) ||
    (!Array.isArray(input) &&
      Object.getPrototypeOf(input) !== Object.prototype &&
      Object.getPrototypeOf(input) !== null)
  ) {
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid data object' });
  }
  seen.add(input);
  const output: Record<string, unknown> | unknown[] = Array.isArray(input) ? [] : {};
  for (const key of Object.keys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      !descriptor ||
      !('value' in descriptor)
    ) {
      throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Unsafe data property' });
    }
    Object.defineProperty(output, key, {
      value: copyData(descriptor.value, seen),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  seen.delete(input);
  return output as T;
}

/** Deep-freeze plain validated data without invoking accessors. */
export function freezeData<T>(input: T): T {
  if (input && typeof input === 'object' && !Object.isFrozen(input)) {
    for (const value of Object.values(input)) freezeData(value);
    Object.freeze(input);
  }
  return input;
}

/** Merge plain records; arrays and explicit null replace rather than delete. */
export function mergeData<T extends Record<string, unknown>>(base: T, update: Partial<T>): T {
  const result = copyData(base);
  for (const [key, value] of Object.entries(copyData(update))) {
    const before = result[key];
    (result as Record<string, unknown>)[key] =
      before &&
      value &&
      typeof before === 'object' &&
      typeof value === 'object' &&
      !Array.isArray(before) &&
      !Array.isArray(value)
        ? mergeData(before as Record<string, unknown>, value as Record<string, unknown>)
        : value;
  }
  return result;
}

const secretKey =
  /^(password|authorization|cookie|token|clientSecret|secret|accessToken|refreshToken|apiKey|connectionString)$/i;

/** Remove secret fields at every nesting level, including explicit schema paths. */
export function redactData<T>(input: T, paths: readonly string[] = [], prefix = ''): T {
  if (!input || typeof input !== 'object') return input;
  const out: Record<string, unknown> | unknown[] = Array.isArray(input) ? [] : {};
  for (const [key, value] of Object.entries(input)) {
    const path = prefix ? `${prefix}.${key}` : key;
    Object.defineProperty(out, key, {
      value:
        secretKey.test(key) || paths.includes(path) ? '[REDACTED]' : redactData(value, paths, path),
      enumerable: true,
    });
  }
  return out as T;
}

/** Compile strict JSON Schema once; coercion and silent defaults are disabled. */
export function compileSchema(schema: object): (input: unknown) => boolean {
  try {
    return new Ajv({ allErrors: true, strict: true, ownProperties: true }).compile(
      schema as AnySchema,
    );
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid configuration schema',
      cause,
    });
  }
}

/** Bounded audit metadata excludes configuration paths, values and native errors. */
export interface ConfigurationDiagnostic {
  readonly event: 'configuration.override.applied' | 'configuration.reload.applied';
  readonly source: 'yaml' | 'environment' | 'runtime' | 'reload';
  readonly keyCount: number;
}

/** Emit bounded metadata only; a failing custom sink falls back to standard error. */
export function reportConfigurationDiagnostic(
  event: ConfigurationDiagnostic,
  sink?: (event: ConfigurationDiagnostic) => void,
): void {
  const safe = Object.freeze({
    event: event.event,
    source: event.source,
    keyCount: event.keyCount,
  });
  if (sink) {
    try {
      sink(safe);
      return;
    } catch {
      // Preserve the configuration outcome and exclude the sink's error from logs.
    }
  }
  try {
    process.stderr.write(JSON.stringify(safe) + '\n');
  } catch {
    // A closed fallback stream cannot roll back an already committed generation.
  }
}

/** Options for the configuration store shared by core and its config adapter. */
export interface StoreOptions<T extends Record<string, unknown>> {
  schema: object;
  dynamicPaths?: readonly string[];
  secretPaths?: readonly string[];
  preflightTimeoutMs?: number;
  preflight?: (next: Readonly<T>, previous: Readonly<T>) => Promise<void> | void;
  onDiagnostic?: (event: ConfigurationDiagnostic) => void;
}

/** EK-CONF-001: immutable generations with serialized, preflighted atomic reload. */
export class ConfigStore<T extends Record<string, unknown>> implements ConfigService<T> {
  private current: T;
  private view: Readonly<T>;
  private readonly validate: (input: unknown) => boolean;
  private readonly options: StoreOptions<T>;
  private pending: Promise<unknown> = Promise.resolve();

  constructor(initial: T, options: StoreOptions<T>) {
    if (options.onDiagnostic !== undefined && typeof options.onDiagnostic !== 'function')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Invalid configuration diagnostic sink',
      });
    if (
      options.preflightTimeoutMs !== undefined &&
      (!Number.isSafeInteger(options.preflightTimeoutMs) || options.preflightTimeoutMs <= 0)
    )
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Preflight timeout must be a positive integer',
      });
    this.options = {
      ...options,
      dynamicPaths: [...(options.dynamicPaths ?? [])],
      secretPaths: [...(options.secretPaths ?? [])],
    };
    this.validate = compileSchema(options.schema);
    this.current = this.checked(initial);
    this.view = freezeData(redactData(this.current, this.options.secretPaths));
  }

  private checked(value: T): T {
    const data = copyData(value);
    if (!this.validate(data))
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Configuration schema validation failed',
      });
    return freezeData(data);
  }

  /** Select a top-level key without exposing inherited properties. */
  get<K extends keyof T>(key: K): T[K] | undefined {
    return Object.hasOwn(this.current, key) ? this.current[key] : undefined;
  }
  /** Return a non-null value or identify the missing key without printing its value. */
  require<K extends keyof T>(key: K): NonNullable<T[K]> {
    const value = this.get(key);
    if (value === undefined || value === null)
      throw new KitError({
        code: 'EK_CONFIG_MISSING',
        message: `Required configuration key: ${String(key)}`,
      });
    return value;
  }
  /** Report presence, including an explicit schema-permitted null. */
  has<K extends keyof T>(key: K): boolean {
    return this.get(key) !== undefined;
  }
  /** Return the current deeply immutable and redacted display view. */
  snapshot(): Readonly<T> {
    return this.view;
  }

  /** Validate and preflight one serialized atomic configuration replacement. */
  reload(updates: Partial<T>): Promise<Readonly<T>> {
    // Capture caller data now; queued reloads must not observe later mutations.
    let captured: Partial<T>;
    try {
      captured = copyData(updates);
    } catch (cause) {
      return Promise.reject(
        new KitError({ code: 'EK_CONFIG_RELOAD_REJECTED', message: 'Invalid reload data', cause }),
      );
    }
    const operation = this.pending.then(async () => {
      try {
        const next = this.checked(mergeData(this.current, captured));
        // Check sensitive descendants before accepting a dynamic parent object.
        const protect = (before: unknown, after: unknown, path: string): void => {
          if (isDeepStrictEqual(before, after)) return;
          if (
            path
              .split('.')
              .some((key) => secretKey.test(key) || key === 'security' || key === 'databases') ||
            this.options.secretPaths?.some(
              (secret) => path === secret || path.startsWith(`${secret}.`),
            )
          ) {
            throw new KitError({
              code: 'EK_CONFIG_RELOAD_REJECTED',
              message: 'Sensitive configuration requires reconstruction',
            });
          }
          const left =
            before && typeof before === 'object' ? (before as Record<string, unknown>) : {};
          const right =
            after && typeof after === 'object' ? (after as Record<string, unknown>) : {};
          for (const key of new Set([...Object.keys(left), ...Object.keys(right)])) {
            protect(left[key], right[key], path ? `${path}.${key}` : key);
          }
        };
        protect(this.current, next, '');
        const compare = (before: unknown, after: unknown, path: string): void => {
          if (isDeepStrictEqual(before, after)) return;
          if (
            path
              .split('.')
              .some((key) => secretKey.test(key) || key === 'security' || key === 'databases') ||
            this.options.secretPaths?.some(
              (secret) => path === secret || path.startsWith(`${secret}.`),
            )
          ) {
            throw new KitError({
              code: 'EK_CONFIG_RELOAD_REJECTED',
              message: 'Sensitive configuration requires reconstruction',
            });
          }
          if (this.options.dynamicPaths?.includes(path)) return;
          if (
            before &&
            after &&
            typeof before === 'object' &&
            typeof after === 'object' &&
            !Array.isArray(before) &&
            !Array.isArray(after)
          ) {
            for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
              compare(
                (before as Record<string, unknown>)[key],
                (after as Record<string, unknown>)[key],
                path ? `${path}.${key}` : key,
              );
            }
            return;
          }
          throw new KitError({
            code: 'EK_CONFIG_RELOAD_REJECTED',
            message: 'Static configuration cannot change',
          });
        };
        compare(this.current, next, '');
        if (this.options.preflight) {
          await within(
            () => this.options.preflight!(next, this.current),
            this.options.preflightTimeoutMs === undefined
              ? {}
              : { timeoutMs: this.options.preflightTimeoutMs },
          );
        }
        const view = freezeData(redactData(next, this.options.secretPaths));
        this.current = next;
        this.view = view;
        reportConfigurationDiagnostic(
          {
            event: 'configuration.reload.applied',
            source: 'reload',
            keyCount: Object.keys(captured).length,
          },
          this.options.onDiagnostic,
        );
        return view;
      } catch (cause) {
        throw new KitError({
          code: 'EK_CONFIG_RELOAD_REJECTED',
          message: 'Configuration reload rejected',
          cause,
        });
      }
    });
    this.pending = operation.catch(() => undefined);
    return operation;
  }
}

/** EK-CORE-001: bounded wait, with cancellation and timer/listener cleanup. */
export async function within<T>(
  work: () => Promise<T> | T,
  options: OperationOptions = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Timeout must be a positive integer',
    });
  if (options.signal?.aborted)
    throw new KitError({
      code: 'EK_ABORTED',
      message: 'Operation aborted',
      cause: options.signal.reason,
    });
  let timer: ReturnType<typeof setTimeout> | undefined;
  let aborted: (() => void) | undefined;
  try {
    const limit = new Promise<never>((_, reject) => {
      const deadline = performance.now() + timeoutMs;
      const schedule = (): void => {
        const remaining = Math.ceil(deadline - performance.now());
        if (remaining <= 0) {
          reject(new KitError({ code: 'EK_TIMEOUT', message: 'Operation timed out' }));
          return;
        }
        // Node reduces overflowing timer delays to one millisecond; rearm bounded chunks.
        timer = setTimeout(schedule, Math.min(remaining, 2_147_483_647));
      };
      schedule();
      aborted = () =>
        reject(
          new KitError({
            code: 'EK_ABORTED',
            message: 'Operation aborted',
            cause: options.signal?.reason,
          }),
        );
      options.signal?.addEventListener('abort', aborted, { once: true });
    });
    return await Promise.race([Promise.resolve().then(work), limit]);
  } finally {
    if (timer) clearTimeout(timer);
    if (aborted) options.signal?.removeEventListener('abort', aborted);
  }
}
