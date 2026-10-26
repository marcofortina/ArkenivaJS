// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { validate, version, v7 } from 'uuid';
import { KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';

/** Supported RFC 9562 identifier versions. */
export type UuidVersion = 4 | 7;
/** Canonical lowercase UUID and its supported version. */
export interface ParsedUuid {
  readonly canonical: string;
  readonly version: UuidVersion;
}
/** Explicit policy applies to generation and validation. */
export interface DataIdentifiersPluginSettings {
  readonly allowVersions: readonly UuidVersion[];
}
/** Pure identifier operations do not convey authentication or distributed ordering. */
export interface IdentifiersService {
  /** Generate UUIDv4 through Node's cryptographic UUID generator. */
  uuidV4(): string;
  /** Generate UUIDv7 through the approved library without a shared sequence counter. */
  uuidV7(): string;
  /** Reject noncanonical text and versions excluded by the captured policy. */
  parseUuid(value: string): ParsedUuid;
  /** Validate syntax and the optional requested supported version without coercion. */
  isUuid(value: string, version?: UuidVersion): boolean;
}
const invalid = () =>
  new KitError({
    code: 'EK_IDENTIFIER_INVALID',
    message: 'The identifier is invalid or outside the configured version policy',
  });
const closed = () =>
  new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'The identifier service is closed' });
function capture(input: DataIdentifiersPluginSettings): ReadonlySet<UuidVersion> {
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      Reflect.ownKeys(input).length !== 1
    )
      throw invalid();
    const field = Object.getOwnPropertyDescriptor(input, 'allowVersions');
    if (
      !field ||
      !('value' in field) ||
      !Array.isArray(field.value) ||
      field.value.length < 1 ||
      field.value.length > 2 ||
      Reflect.ownKeys(field.value).length !== field.value.length + 1
    )
      throw invalid();
    const allowed = new Set<UuidVersion>();
    for (let index = 0; index < field.value.length; index++) {
      const item = Object.getOwnPropertyDescriptor(field.value, String(index));
      if (
        !item ||
        !('value' in item) ||
        (item.value !== 4 && item.value !== 7) ||
        allowed.has(item.value)
      )
        throw invalid();
      allowed.add(item.value);
    }
    return allowed;
  } catch {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Identifier settings require distinct supported UUID versions',
    });
  }
}
function service(allowed: ReadonlySet<UuidVersion>, ready: () => void): IdentifiersService {
  const kind = (value: unknown): UuidVersion | undefined => {
    if (
      typeof value !== 'string' ||
      value.length !== 36 ||
      value !== value.toLowerCase() ||
      !validate(value)
    )
      return undefined;
    const found = version(value);
    return (found === 4 || found === 7) && allowed.has(found) ? found : undefined;
  };
  return Object.freeze({
    uuidV4() {
      ready();
      if (!allowed.has(4)) throw invalid();
      return randomUUID();
    },
    uuidV7() {
      ready();
      if (!allowed.has(7)) throw invalid();
      // Explicit options keep the upstream generator stateless between application instances.
      return v7({});
    },
    parseUuid(value: string) {
      ready();
      const found = kind(value);
      if (found === undefined) throw invalid();
      return Object.freeze({ canonical: value, version: found });
    },
    isUuid(value: string, requested?: UuidVersion) {
      ready();
      if (requested !== undefined && requested !== 4 && requested !== 7) return false;
      const found = kind(value);
      return found !== undefined && (requested === undefined || requested === found);
    },
  });
}
/** Construct a pure, isolated facade without listeners, provider state or required plugins. */
export function createIdentifiersService(
  settings: DataIdentifiersPluginSettings,
): IdentifiersService {
  return service(capture(settings), () => undefined);
}
/** Stable optional capability, installed only by its explicit factory. */
export const IDENTIFIERS_CAPABILITY: unique symbol = Symbol('arkenivajs.identifiers');
/** Register an application-owned pure facade and invalidate its handle during shutdown. */
export function dataIdentifiersPlugin(settings: DataIdentifiersPluginSettings): Plugin {
  const allowed = capture(settings),
    instances = new WeakMap<object, { close(): void }>();
  return {
    id: 'data-identifiers',
    version: '0.1.0',
    capabilities: new Set(['identifiers']),
    init(context) {
      let active = true;
      context.provide(
        IDENTIFIERS_CAPABILITY,
        service(allowed, () => {
          if (!active) throw closed();
        }),
      );
      instances.set(context, {
        close() {
          active = false;
        },
      });
    },
    close(context) {
      instances.get(context)?.close();
      instances.delete(context);
    },
  };
}
