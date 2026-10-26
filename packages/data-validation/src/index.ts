// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { toUSVString } from 'node:util';
import { performance } from 'node:perf_hooks';
import { Ajv } from 'ajv';
import type { ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import ipaddr from 'ipaddr.js';
import traverse from 'json-schema-traverse';
import validator from 'validator';
import { KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { createIdentifiersService } from '@arkenivajs/data-identifiers';
import type { UuidVersion } from '@arkenivajs/data-identifiers';

export type { UuidVersion } from '@arkenivajs/data-identifiers';
/** Safe validation metadata never includes the rejected input. */
export interface SchemaValidationError {
  readonly path: string;
  readonly code: string;
  readonly message: string;
}
/** A successful result has a normalized value; a rejected result has only safe errors. */
export type ValidationResult<T> =
  | Readonly<{ valid: true; value: T; errors: readonly [] }>
  | Readonly<{ valid: false; errors: readonly SchemaValidationError[] }>;
/** Internationalized local parts require explicit permission; domains use IDNA. */
export interface EmailPolicy {
  readonly allowInternationalized?: boolean;
  readonly maxLength?: number;
}
/** Exact hostname allowlists do not replace connection-time DNS and egress checks. */
export interface UrlPolicy {
  readonly schemes: readonly ('https:' | 'http:')[];
  readonly allowedHosts?: readonly string[];
  readonly denyPrivateNetworks?: boolean;
}
/** Mapped addresses are rejected unless explicitly permitted. */
export interface IpPolicy {
  readonly version?: 4 | 6;
  readonly allowMappedIPv4?: boolean;
}
/** Positive finite resource limits; synchronous work has no pending queue. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Schemas are trusted deployment configuration, captured and compiled before use. */
export interface DataValidationPluginSettings {
  readonly schemas: Readonly<Record<string, object>>;
  readonly policy: BoundedRuntimePolicy;
}
/** Pure syntax validation performs no DNS, mailbox, storage or network operations. */
export interface ValidationService {
  /** Preserve the local part and return the lowercase IDNA domain after syntax validation. */
  email(value: string, options?: EmailPolicy): ValidationResult<string>;
  /** Parse an absolute HTTP(S) URL under the explicit protocol/hostname policy. */
  url(value: string, policy: UrlPolicy): ValidationResult<URL>;
  /** Parse strict IPv4/IPv6 syntax and return the upstream canonical representation. */
  ip(value: string, policy?: IpPolicy): ValidationResult<string>;
  /** Apply the identifier package's canonical UUIDv4/v7 policy. */
  uuid(value: string, version?: UuidVersion): ValidationResult<string>;
  /** Validate bounded JSON data against a registered schema without mutating the caller. */
  assertSchema(data: unknown, schemaId: string): void;
}
const empty = Object.freeze([]) as readonly [];
const fail = (): ValidationResult<never> =>
  Object.freeze({
    valid: false,
    errors: Object.freeze([
      Object.freeze({
        path: '',
        code: 'EK_VALIDATION_INVALID',
        message: 'The value does not satisfy validation',
      }),
    ]),
  });
const pass = <T>(value: T): ValidationResult<T> =>
  Object.freeze({ valid: true, value, errors: empty });
const error = (code: 'EK_CONFIG_INVALID' | 'EK_VALIDATION_POLICY' | 'EK_VALIDATION_INVALID') =>
  new KitError({
    code,
    message:
      code === 'EK_VALIDATION_INVALID'
        ? 'The value does not satisfy the registered schema'
        : 'The validation policy is invalid',
  });
function fields(input: unknown, allowed: readonly string[]): Record<string, unknown> {
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    )
      throw error('EK_VALIDATION_POLICY');
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key !== 'string' || !allowed.includes(key)) throw error('EK_VALIDATION_POLICY');
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !('value' in descriptor)) throw error('EK_VALIDATION_POLICY');
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw error('EK_VALIDATION_POLICY');
  }
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw error('EK_VALIDATION_POLICY');
  return value as number;
}
function flag(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw error('EK_VALIDATION_POLICY');
  return value;
}
function strings(value: unknown, maximum: number): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw error('EK_VALIDATION_POLICY');
  const output: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (
      !descriptor ||
      !('value' in descriptor) ||
      typeof descriptor.value !== 'string' ||
      descriptor.value.length > 253 ||
      output.includes(descriptor.value)
    )
      throw error('EK_VALIDATION_POLICY');
    output.push(descriptor.value);
  }
  return output;
}
/** Bound and snapshot JSON data before invoking the native schema validator. */
function jsonData(input: unknown, maximum: number): unknown {
  const seen = new Set<object>();
  let nodes = 0,
    bytes = 0;
  const walk = (value: unknown, depth: number): unknown => {
    if (++nodes > 4096 || depth > 32 || bytes > maximum) throw error('EK_VALIDATION_INVALID');
    if (
      value === null ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value))
    ) {
      bytes += JSON.stringify(value).length;
      if (bytes > maximum) throw error('EK_VALIDATION_INVALID');
      return value;
    }
    if (typeof value === 'string') {
      if (value.length > maximum) throw error('EK_VALIDATION_INVALID');
      bytes += Buffer.byteLength(JSON.stringify(value));
      if (bytes > maximum) throw error('EK_VALIDATION_INVALID');
      return value;
    }
    if (
      !value ||
      typeof value !== 'object' ||
      seen.has(value) ||
      (!Array.isArray(value) &&
        Object.getPrototypeOf(value) !== Object.prototype &&
        Object.getPrototypeOf(value) !== null)
    )
      throw error('EK_VALIDATION_INVALID');
    seen.add(value);
    const keys = Reflect.ownKeys(value);
    if (keys.length > 4096 || (Array.isArray(value) && keys.length !== value.length + 1))
      throw error('EK_VALIDATION_INVALID');
    const result: Record<string, unknown> | unknown[] = Array.isArray(value) ? [] : {};
    bytes += 2;
    let entries = 0;
    for (const key of keys) {
      if (Array.isArray(value) && key === 'length') continue;
      if (
        typeof key !== 'string' ||
        ['__proto__', 'constructor', 'prototype', 'valueOf', 'toString'].includes(key) ||
        key.length > maximum ||
        (Array.isArray(value) && String(entries) !== key)
      )
        throw error('EK_VALIDATION_INVALID');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable)
        throw error('EK_VALIDATION_INVALID');
      if (entries++) bytes++;
      if (!Array.isArray(value)) bytes += Buffer.byteLength(JSON.stringify(key)) + 1;
      Object.defineProperty(result, key, {
        value: walk(descriptor.value, depth + 1),
        enumerable: true,
      });
    }
    seen.delete(value);
    if (bytes > maximum) throw error('EK_VALIDATION_INVALID');
    return result;
  };
  return walk(input, 0);
}
function capture(input: DataValidationPluginSettings) {
  try {
    const settings = fields(input, ['schemas', 'policy']);
    const policy = fields(settings.policy, [
      'maxConcurrent',
      'timeoutMs',
      'maxInputBytes',
      'maxOutputBytes',
    ]);
    const limits = Object.freeze({
      maxConcurrent: integer(policy.maxConcurrent, 1024),
      timeoutMs: integer(policy.timeoutMs, 120000),
      maxInputBytes: integer(
        policy.maxInputBytes === undefined ? 65536 : policy.maxInputBytes,
        8388608,
      ),
      maxOutputBytes: integer(
        policy.maxOutputBytes === undefined ? 65536 : policy.maxOutputBytes,
        8388608,
      ),
    });
    // Remote schema resolution and asynchronous validation are never enabled.
    const ajv = new Ajv({
      strict: true,
      allErrors: false,
      ownProperties: true,
      coerceTypes: false,
      useDefaults: false,
      removeAdditional: false,
      messages: false,
      logger: false,
    });
    addFormats.default(ajv);
    const source = jsonData(settings.schemas, 262144);
    if (!source || typeof source !== 'object' || Array.isArray(source))
      throw error('EK_CONFIG_INVALID');
    const entries = Object.entries(source);
    if (entries.length > 128) throw error('EK_CONFIG_INVALID');
    const schemas = new Map<string, ValidateFunction>();
    for (const [id, schema] of entries) {
      if (
        !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(id) ||
        !schema ||
        typeof schema !== 'object' ||
        Array.isArray(schema)
      )
        throw error('EK_CONFIG_INVALID');
      // The upstream visitor distinguishes schema keywords from literal enum/default data.
      traverse(schema, (node: Record<string, unknown>) => {
        if (
          Object.hasOwn(node, '$async') ||
          (Object.hasOwn(node, '$ref') &&
            (typeof node.$ref !== 'string' || !node.$ref.startsWith('#')))
        )
          throw error('EK_CONFIG_INVALID');
      });
      schemas.set(id, ajv.compile(schema));
    }
    return { limits, schemas };
  } catch {
    throw error('EK_CONFIG_INVALID');
  }
}
type Captured = ReturnType<typeof capture>;
function hostname(value: string): string {
  if (!value || value.length > 253 || /[\s/\\?#@*]/u.test(value))
    throw error('EK_VALIDATION_POLICY');
  if (value.startsWith('[') ? !value.endsWith(']') : value.includes(':'))
    throw error('EK_VALIDATION_POLICY');
  const url = new URL('https://' + value);
  if (
    url.port ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.hostname.endsWith('.')
  )
    throw error('EK_VALIDATION_POLICY');
  return url.hostname;
}
function unsafeUrlText(value: string): boolean {
  if (/[\s\\]/u.test(value)) return true;
  for (let index = 0; index < value.length; index++) {
    const point = value.charCodeAt(index);
    if (point < 32 || point === 127) return true;
  }
  return false;
}
function service(settings: Captured, ready: () => void): ValidationService {
  const ids = createIdentifiersService({ allowVersions: [4, 7] });
  let active = 0;
  const invoke = <T>(action: () => T): T => {
    ready();
    if (active >= settings.limits.maxConcurrent) throw error('EK_VALIDATION_POLICY');
    const start = performance.now();
    active++;
    try {
      const result = action();
      if (performance.now() - start > settings.limits.timeoutMs)
        throw new KitError({ code: 'EK_TIMEOUT', message: 'The validation deadline expired' });
      return result;
    } finally {
      active--;
    }
  };
  const text = (value: unknown): value is string =>
    typeof value === 'string' &&
    value.length <= settings.limits.maxInputBytes &&
    Buffer.byteLength(value) <= settings.limits.maxInputBytes &&
    toUSVString(value) === value;
  const output = (value: string) => Buffer.byteLength(value) <= settings.limits.maxOutputBytes;
  return Object.freeze({
    email(value: string, options?: EmailPolicy) {
      return invoke(() => {
        const policy = fields(options === undefined ? {} : options, [
          'allowInternationalized',
          'maxLength',
        ]);
        const international = flag(policy.allowInternationalized, false),
          maximum = integer(policy.maxLength === undefined ? 254 : policy.maxLength, 254);
        if (!text(value) || Buffer.byteLength(value) > maximum) return fail();
        const separator = value.lastIndexOf('@'),
          domain = domainToASCII(value.slice(separator + 1));
        const normalized = value.slice(0, separator + 1) + domain.toLowerCase();
        if (
          separator < 1 ||
          !domain ||
          (!international && /[\u0080-\u{10ffff}]/u.test(value)) ||
          Buffer.byteLength(normalized) > maximum ||
          !output(normalized) ||
          !validator.isEmail(normalized, {
            allow_utf8_local_part: international,
            require_tld: true,
            allow_ip_domain: false,
            allow_display_name: false,
          })
        )
          return fail();
        return pass(normalized);
      });
    },
    url(value: string, input: UrlPolicy) {
      return invoke(() => {
        let schemes: readonly string[], hosts: Set<string> | undefined, deny: boolean;
        try {
          const policy = fields(input, ['schemes', 'allowedHosts', 'denyPrivateNetworks']);
          schemes = strings(policy.schemes, 2);
          if (schemes.some((scheme) => scheme !== 'https:' && scheme !== 'http:'))
            throw error('EK_VALIDATION_POLICY');
          if (policy.allowedHosts !== undefined) {
            const names = strings(policy.allowedHosts, 256).map(hostname);
            hosts = new Set(names);
            if (hosts.size !== names.length) throw error('EK_VALIDATION_POLICY');
          }
          deny = flag(policy.denyPrivateNetworks, true);
        } catch {
          throw error('EK_VALIDATION_POLICY');
        }
        if (!text(value) || unsafeUrlText(value)) return fail();
        let parsed: URL;
        try {
          parsed = new URL(value);
        } catch {
          return fail();
        }
        if (
          !value.startsWith(parsed.protocol + '//') ||
          !schemes.includes(parsed.protocol) ||
          parsed.username ||
          parsed.password ||
          !parsed.hostname ||
          parsed.hostname.endsWith('.') ||
          !output(parsed.href) ||
          (hosts && !hosts.has(parsed.hostname))
        )
          return fail();
        const host = parsed.hostname.replace(/^\[|\]$/g, '');
        if (deny) {
          if (
            host === 'localhost' ||
            host.endsWith('.localhost') ||
            host.endsWith('.local') ||
            (!isIP(host) && !host.includes('.'))
          )
            return fail();
          if (isIP(host)) {
            let address = ipaddr.parse(host);
            if (address instanceof ipaddr.IPv6 && address.isIPv4MappedAddress())
              address = address.toIPv4Address();
            if (address.range() !== 'unicast') return fail();
          }
        }
        return pass(parsed);
      });
    },
    ip(value: string, options?: IpPolicy) {
      return invoke(() => {
        const policy = fields(options === undefined ? {} : options, ['version', 'allowMappedIPv4']);
        if (policy.version !== undefined && policy.version !== 4 && policy.version !== 6)
          throw error('EK_VALIDATION_POLICY');
        const mapped = flag(policy.allowMappedIPv4, false);
        if (!text(value) || value.length > 45 || value.includes('%')) return fail();
        const kind = isIP(value);
        if (!kind || (policy.version !== undefined && policy.version !== kind)) return fail();
        const parsed = ipaddr.parse(value);
        if (parsed instanceof ipaddr.IPv6 && parsed.isIPv4MappedAddress() && !mapped) return fail();
        const normalized = parsed.toString();
        return output(normalized) ? pass(normalized) : fail();
      });
    },
    uuid(value: string, version?: UuidVersion) {
      return invoke(() =>
        text(value) && output(value) && ids.isUuid(value, version) ? pass(value) : fail(),
      );
    },
    assertSchema(data: unknown, schemaId: string) {
      invoke(() => {
        if (typeof schemaId !== 'string' || !settings.schemas.has(schemaId))
          throw error('EK_VALIDATION_POLICY');
        const validate = settings.schemas.get(schemaId)!;
        try {
          if (!validate(jsonData(data, settings.limits.maxInputBytes)))
            throw error('EK_VALIDATION_INVALID');
        } catch {
          throw error('EK_VALIDATION_INVALID');
        }
      });
    },
  });
}
/** Construct a pure validator with an isolated, startup-compiled schema catalog. */
export function createValidationService(settings: DataValidationPluginSettings): ValidationService {
  return service(capture(settings), () => undefined);
}
/** Stable optional application capability. */
export const VALIDATION_CAPABILITY: unique symbol = Symbol('arkenivajs.validation');
/** Register an application-owned validator without listeners, storage or implicit services. */
export function dataValidationPlugin(settings: DataValidationPluginSettings): Plugin {
  const captured = capture(settings),
    instances = new WeakMap<object, { close(): void }>();
  return {
    id: 'data-validation',
    version: '0.1.0',
    capabilities: new Set(['validation']),
    init(context) {
      let open = true;
      context.provide(
        VALIDATION_CAPABILITY,
        service(captured, () => {
          if (!open)
            throw new KitError({
              code: 'EK_RESOURCE_CLOSED',
              message: 'The validation service is closed',
            });
        }),
      );
      instances.set(context, {
        close() {
          open = false;
        },
      });
    },
    close(context) {
      instances.get(context)?.close();
      instances.delete(context);
    },
  };
}
