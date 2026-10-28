// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import protobuf from 'protobufjs';
import { toUSVString, types } from 'node:util';
import { fields } from './settings.js';
import { failure } from './errors.js';

/** Validate native field domains before proto-loader can coerce or discard application data. */
export function ownMessage(
  type: protobuf.Type,
  input: unknown,
  maximum: number,
): Record<string, unknown> {
  const seen = new Set<object>();
  let count = 0,
    bytes = 0;
  function charge(size: number): void {
    bytes += size;
    if (bytes > maximum || ++count > 16384) throw failure('EK_GRPC_STATUS');
  }
  function scalar(field: protobuf.Field, value: unknown, depth: number): unknown {
    charge(1);
    if (field.resolvedType instanceof protobuf.Type)
      return message(field.resolvedType, value, depth + 1);
    if (field.resolvedType instanceof protobuf.Enum) {
      if (typeof value === 'string' && Object.hasOwn(field.resolvedType.values, value))
        return value;
      if (
        typeof value === 'number' &&
        Number.isInteger(value) &&
        value >= -2147483648 &&
        value <= 2147483647
      )
        return value;
      throw failure('EK_GRPC_STATUS');
    }
    if (field.type === 'string') {
      if (typeof value !== 'string' || toUSVString(value) !== value)
        throw failure('EK_GRPC_STATUS');
      charge(Buffer.byteLength(value));
      return value;
    }
    if (field.type === 'bytes') {
      if (types.isProxy(value) || !(value instanceof Uint8Array)) throw failure('EK_GRPC_STATUS');
      charge(value.byteLength);
      return Buffer.from(value);
    }
    if (field.type === 'bool') {
      if (typeof value !== 'boolean') throw failure('EK_GRPC_STATUS');
      return value;
    }
    if (['int64', 'uint64', 'sint64', 'fixed64', 'sfixed64'].includes(field.type)) {
      if (typeof value === 'number' && Number.isSafeInteger(value)) value = String(value);
      if (typeof value !== 'string' || value.length > 20 || !/^(0|-?[1-9][0-9]*)$/.test(value))
        throw failure('EK_GRPC_STATUS');
      const number = BigInt(value),
        unsigned = ['uint64', 'fixed64'].includes(field.type);
      if (
        number < (unsigned ? 0n : -9223372036854775808n) ||
        number > (unsigned ? 18446744073709551615n : 9223372036854775807n)
      )
        throw failure('EK_GRPC_STATUS');
      return value;
    }
    if (typeof value !== 'number' || !Number.isFinite(value)) throw failure('EK_GRPC_STATUS');
    if (field.type === 'double') return value;
    if (field.type === 'float') {
      if (!Number.isFinite(Math.fround(value))) throw failure('EK_GRPC_STATUS');
      return value;
    }
    const unsigned = ['uint32', 'fixed32'].includes(field.type);
    if (
      !Number.isInteger(value) ||
      value < (unsigned ? 0 : -2147483648) ||
      value > (unsigned ? 4294967295 : 2147483647)
    )
      throw failure('EK_GRPC_STATUS');
    return value;
  }
  function message(schema: protobuf.Type, value: unknown, depth: number): Record<string, unknown> {
    if (depth > 32 || !value || typeof value !== 'object' || seen.has(value))
      throw failure('EK_GRPC_STATUS');
    seen.add(value);
    try {
      const data = fields(value),
        result: Record<string, unknown> = Object.create(null);
      for (const [key, item] of Object.entries(data)) {
        const field = Object.hasOwn(schema.fields, key) ? schema.fields[key] : undefined;
        const discriminator =
          schema.oneofs && Object.hasOwn(schema.oneofs, key) ? schema.oneofs[key] : undefined;
        if (discriminator) {
          if (
            typeof item !== 'string' ||
            !discriminator.oneof.includes(item) ||
            !Object.hasOwn(data, item)
          )
            throw failure('EK_GRPC_STATUS');
          continue;
        }
        if (!field) throw failure('EK_GRPC_STATUS');
        if (field instanceof protobuf.MapField) {
          const map = fields(item),
            owned: Record<string, unknown> = Object.create(null);
          if (Object.keys(map).length > 4096) throw failure('EK_GRPC_STATUS');
          for (const [mapKey, mapValue] of Object.entries(map)) {
            charge(Buffer.byteLength(mapKey));
            const keyType = field.keyType;
            if (!['string', 'bool'].includes(keyType) && !/^(0|-?[1-9][0-9]*)$/.test(mapKey))
              throw failure('EK_GRPC_STATUS');
            if (keyType === 'bool' && !['true', 'false'].includes(mapKey))
              throw failure('EK_GRPC_STATUS');
            if (!['string', 'bool'].includes(keyType))
              scalar(
                new protobuf.Field('key', 1, keyType),
                mapKey.length < 11 && !keyType.endsWith('64') ? Number(mapKey) : mapKey,
                depth,
              );
            owned[mapKey] = scalar(field, mapValue, depth);
          }
          result[key] = owned;
        } else if (field.repeated) {
          if (
            !Array.isArray(item) ||
            types.isProxy(item) ||
            item.length > 4096 ||
            Reflect.ownKeys(item).length !== item.length + 1
          )
            throw failure('EK_GRPC_STATUS');
          result[key] = Array.from({ length: item.length }, (_, index) => {
            const property = Object.getOwnPropertyDescriptor(item, String(index));
            if (!property || !('value' in property)) throw failure('EK_GRPC_STATUS');
            return scalar(field, property.value, depth);
          });
        } else result[key] = scalar(field, item, depth);
      }
      for (const oneof of schema.oneofsArray)
        if (oneof.oneof.filter((key) => Object.hasOwn(result, key)).length > 1)
          throw failure('EK_GRPC_STATUS');
      for (const field of schema.fieldsArray)
        if (field.required && !Object.hasOwn(result, field.name)) throw failure('EK_GRPC_STATUS');
      return result;
    } finally {
      seen.delete(value);
    }
  }
  try {
    return message(type, input, 0);
  } catch {
    throw failure('EK_GRPC_STATUS');
  }
}
