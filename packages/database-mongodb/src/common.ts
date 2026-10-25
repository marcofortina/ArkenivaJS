import { BSON } from 'mongodb';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { MONGODB_LIMITS } from './limits.js';

/** Capture caller-controlled budgets before asynchronous native work begins. */
export function mongoOptions(
  input?: OperationOptions,
  defaultMs: number = MONGODB_LIMITS.timeoutMs,
) {
  if (input !== undefined && (!input || typeof input !== 'object' || Array.isArray(input)))
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MongoDB operation options require an object',
    });
  const timeoutMs = input?.timeoutMs ?? defaultMs,
    signal = input?.signal;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    (signal !== undefined && !(signal instanceof AbortSignal))
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MongoDB operations require positive integer milliseconds and an AbortSignal',
    });
  return Object.freeze({ timeoutMs, ...(signal ? { signal } : {}) });
}

/** Collection validation preserves Unicode and dots while excluding reserved or ambiguous namespaces. */
export function mongoCollection(name: string, prefix: string, database: string): string {
  if (
    typeof name !== 'string' ||
    !name ||
    name.includes('$') ||
    /[\0\r\n]/.test(name) ||
    name.startsWith('system.') ||
    (prefix + name).startsWith('system.') ||
    Buffer.from(name).toString('utf8') !== name ||
    Buffer.byteLength(database + '.' + prefix + name) > 235
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MongoDB requires a valid bounded collection namespace',
    });
  return prefix + name;
}

const nativePrototypes = new Set(
  [
    BSON.Binary,
    BSON.UUID,
    BSON.ObjectId,
    BSON.Long,
    BSON.Int32,
    BSON.Double,
    BSON.Decimal128,
    BSON.Timestamp,
    BSON.BSONRegExp,
    BSON.BSONSymbol,
    BSON.Code,
    BSON.DBRef,
    BSON.MinKey,
    BSON.MaxKey,
  ].map((type) => type.prototype),
);

/** Capture BSON, rather than JSON: preserve native binary, decimal, int64, identifier and date values. */
export function mongoDocument(input: unknown): Record<string, unknown> {
  const seen = new Set<object>();
  let nodes = 0;
  function inspect(value: unknown, depth: number): void {
    if (++nodes > 50_000 || depth > MONGODB_LIMITS.depth)
      throw new Error('MongoDB document structure exceeds its bound');
    if (typeof value === 'string') {
      if (
        Buffer.byteLength(value) > MONGODB_LIMITS.documentBytes ||
        Buffer.from(value).toString('utf8') !== value
      )
        throw new Error('MongoDB strings require bounded valid UTF-8');
      return;
    }
    if (value === null || ['number', 'boolean'].includes(typeof value)) return;
    if (typeof value === 'bigint') {
      if (value < -9_223_372_036_854_775_808n || value > 9_223_372_036_854_775_807n)
        throw new Error('MongoDB bigint must fit signed int64');
      return;
    }
    if (typeof value !== 'object' || !value)
      throw new Error('MongoDB document values must be explicit BSON data');
    if (seen.has(value)) throw new Error('MongoDB documents cannot contain cycles');
    if (Object.hasOwn(value, 'toBSON'))
      throw new Error('MongoDB portable documents cannot execute custom serializers');
    if (value instanceof Uint8Array) {
      if (
        ['buffer', 'byteOffset', 'byteLength', 'length', '_bsontype', 'constructor'].some((key) =>
          Object.hasOwn(value, key),
        ) ||
        Object.getOwnPropertySymbols(value).length
      )
        throw new Error('MongoDB binary data cannot override its native representation');
      if (value.byteLength > MONGODB_LIMITS.documentBytes)
        throw new Error('MongoDB binary value exceeds its bound');
      return;
    }
    if (value instanceof Date) {
      if (Object.getOwnPropertyNames(value).length || Object.getOwnPropertySymbols(value).length)
        throw new Error('MongoDB dates cannot override their native representation');
      if (!Number.isFinite(Date.prototype.getTime.call(value)))
        throw new Error('MongoDB date is invalid');
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (value instanceof RegExp) {
      if (
        Object.getOwnPropertyNames(value).some((key) => key !== 'lastIndex') ||
        Object.getOwnPropertySymbols(value).length
      )
        throw new Error('MongoDB regular expressions cannot override their native representation');
      return;
    }
    if (Array.isArray(value)) {
      if (value.length > 50_000) throw new Error('MongoDB arrays exceed their structural bound');
      for (let index = 0; index < value.length; index++)
        if (!Object.hasOwn(value, index)) throw new Error('MongoDB arrays must be dense');
    }
    if (
      !Array.isArray(value) &&
      prototype !== Object.prototype &&
      prototype !== null &&
      !nativePrototypes.has(prototype)
    )
      throw new Error(
        'MongoDB portable documents require plain objects or selected native BSON classes',
      );
    seen.add(value);
    try {
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (
          key === '__proto__' ||
          key === 'constructor' ||
          key === 'prototype' ||
          key.includes('\0') ||
          Buffer.from(key).toString('utf8') !== key ||
          !('value' in descriptor)
        )
          throw new Error('MongoDB portable documents reject unsafe keys and accessors');
        // Optional internal BSON fields retain the selected SDK's representation; custom callbacks remain forbidden.
        if (descriptor.value === undefined && nativePrototypes.has(prototype)) continue;
        inspect(descriptor.value, depth + 1);
      }
      if (Object.getOwnPropertySymbols(value).length)
        throw new Error('MongoDB portable documents cannot contain symbol fields');
    } finally {
      seen.delete(value);
    }
  }
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    )
      throw new Error('MongoDB document requires a plain object');
    inspect(input, 0);
    const size = BSON.calculateObjectSize(input);
    if (size > MONGODB_LIMITS.documentBytes)
      throw new Error('MongoDB document exceeds the portable byte bound');
    const encoded = BSON.serialize(input);
    if (encoded.length > MONGODB_LIMITS.documentBytes)
      throw new Error('MongoDB encoded document exceeds the portable byte bound');
    return BSON.deserialize(encoded, {
      promoteValues: false,
      promoteLongs: false,
      bsonRegExp: true,
    });
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid or oversized MongoDB BSON document',
      cause,
    });
  }
}

/** Prove the supplied pipeline's output cardinality without appending or rewriting stages. */
export function mongoPipeline(input: readonly Record<string, unknown>[]): {
  readonly pipeline: Record<string, unknown>[];
  readonly maximum: number;
  readonly writes: boolean;
} {
  if (!Array.isArray(input) || input.length === 0 || input.length > MONGODB_LIMITS.pipelineStages)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MongoDB aggregation requires an explicit bounded pipeline',
    });
  const captured = mongoDocument({ pipeline: input }).pipeline as Record<string, unknown>[];
  let writes = false;
  const preserving = new Set([
    '$match',
    '$project',
    '$set',
    '$addFields',
    '$unset',
    '$replaceRoot',
    '$replaceWith',
    '$sort',
    '$skip',
    '$group',
    '$lookup',
    '$graphLookup',
    '$setWindowFields',
  ]);
  function integer(value: unknown, zero = false): bigint {
    const scalar =
      value instanceof BSON.Int32 || value instanceof BSON.Double ? value.valueOf() : value;
    const number =
      value instanceof BSON.Long
        ? value.toBigInt()
        : typeof scalar === 'number' && Number.isFinite(scalar) && Number.isInteger(scalar)
          ? BigInt(scalar)
          : undefined;
    if (number === undefined || number < (zero ? 0n : 1n) || number > 9_223_372_036_854_775_807n)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'MongoDB cardinality bounds require valid int64 integers',
      });
    return number;
  }
  function proof(pipeline: readonly Record<string, unknown>[]): bigint | undefined {
    if (pipeline.length > MONGODB_LIMITS.pipelineStages)
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'MongoDB nested pipeline exceeds its stage bound',
      });
    let maximum: bigint | undefined;
    for (const stage of pipeline) {
      if (
        !stage ||
        typeof stage !== 'object' ||
        Array.isArray(stage) ||
        Object.keys(stage).length !== 1
      )
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'MongoDB aggregation stages require one explicit operator',
        });
      const [operator] = Object.keys(stage),
        value = stage[operator!];
      if (!operator!.startsWith('$') || operator!.length < 2)
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'MongoDB aggregation requires native stage operators',
        });
      if (operator === '$limit') {
        const bound = integer(value);
        maximum = maximum === undefined || bound < maximum ? bound : maximum;
      } else if (operator === '$count' || operator === '$facet') maximum = 1n;
      else if (operator === '$out' || operator === '$merge') {
        maximum = 0n;
        writes = true;
      } else if (operator === '$sample' || operator === '$bucketAuto' || operator === '$bucket') {
        if (!value || typeof value !== 'object' || Array.isArray(value))
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'MongoDB bounded stage parameters require an object',
          });
        const parameters = value as Record<string, unknown>;
        let bound: bigint;
        if (operator === '$bucket') {
          if (!Array.isArray(parameters.boundaries) || parameters.boundaries.length < 2)
            throw new KitError({
              code: 'EK_CONFIG_INVALID',
              message: 'MongoDB buckets require explicit boundary values',
            });
          bound = BigInt(
            parameters.boundaries.length - 1 + (Object.hasOwn(parameters, 'default') ? 1 : 0),
          );
        } else
          bound = integer(
            operator === '$sample' ? parameters.size : parameters.buckets,
            operator === '$sample',
          );
        maximum = maximum === undefined || bound < maximum ? bound : maximum;
      } else if (operator === '$unionWith') {
        const nested =
          value && typeof value === 'object' && !Array.isArray(value)
            ? (value as Record<string, unknown>).pipeline
            : undefined;
        const extra = Array.isArray(nested)
          ? proof(nested as Record<string, unknown>[])
          : undefined;
        maximum = maximum === undefined || extra === undefined ? undefined : maximum + extra;
      } else if (!preserving.has(operator!)) maximum = undefined;
    }
    return maximum;
  }
  const maximum = proof(captured);
  if (maximum === undefined || maximum > BigInt(MONGODB_LIMITS.maximumRows))
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'MongoDB aggregation must prove at most 1000 returned documents',
    });
  return Object.freeze({ pipeline: captured, maximum: Number(maximum), writes });
}

/** Every inserted BSON ID has a typed, lossless opaque canonical EJSON representation. */
export function mongoInsertedId(id: unknown): string {
  try {
    if (id === undefined) throw new Error('MongoDB did not return an inserted identity');
    const encoded = BSON.EJSON.stringify(id, { relaxed: false });
    if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > MONGODB_LIMITS.documentBytes)
      throw new Error('MongoDB inserted identity is unavailable or oversized');
    return encoded;
  } catch (cause) {
    throw new KitError({
      code: 'EK_DOCUMENT_OPERATION',
      message: 'MongoDB returned an invalid inserted identity',
      cause,
    });
  }
}
