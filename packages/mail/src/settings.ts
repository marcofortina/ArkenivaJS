// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
import { types, toUSVString } from 'node:util';
import validator from 'validator';
import { KitError } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type {
  MailPluginSettings,
  MailTransportProfile,
  MailOperationOptions,
  SecretProvider,
} from './contracts.js';

export type FailureCode =
  | 'EK_MAIL_CONFIG'
  | 'EK_MAIL_SEND'
  | 'EK_MAIL_REJECTED'
  | 'EK_ABORTED'
  | 'EK_TIMEOUT'
  | 'EK_RESOURCE_CLOSED';
const messages: Record<FailureCode, string> = {
  EK_MAIL_CONFIG: 'The mail configuration or message is invalid',
  EK_MAIL_SEND: 'The mail operation could not complete',
  EK_MAIL_REJECTED: 'The mail operation was explicitly rejected',
  EK_ABORTED: 'The mail operation was cancelled',
  EK_TIMEOUT: 'The mail operation deadline expired',
  EK_RESOURCE_CLOSED: 'The mail service is closed',
};
export const failure = (code: FailureCode, unknown = false) =>
  new KitError({
    code,
    message: messages[code],
    ...(unknown ? { details: { outcome: 'unknown' } } : {}),
  });
export function fields(
  input: unknown,
  allowed: readonly PropertyKey[],
): Record<PropertyKey, unknown> {
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
    )
      throw failure('EK_MAIL_CONFIG');
    const result: Record<PropertyKey, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(input)) {
      if (!allowed.includes(key)) throw failure('EK_MAIL_CONFIG');
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !('value' in descriptor)) throw failure('EK_MAIL_CONFIG');
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    throw failure('EK_MAIL_CONFIG');
  }
}
export function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw failure('EK_MAIL_CONFIG');
  return value as number;
}
export function text(value: unknown, maximum: number, header = false, empty = false): string {
  if (
    typeof value !== 'string' ||
    (!empty && !value.length) ||
    value.length > maximum ||
    Buffer.byteLength(value, 'utf8') > maximum ||
    toUSVString(value) !== value ||
    (header &&
      [...value].some(
        (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
      ))
  )
    throw failure('EK_MAIL_CONFIG');
  return value;
}
export function array(value: unknown, maximum: number): unknown[] {
  if (
    !Array.isArray(value) ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw failure('EK_MAIL_CONFIG');
  return Array.from({ length: value.length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !('value' in descriptor)) throw failure('EK_MAIL_CONFIG');
    return descriptor.value;
  });
}
export function name(value: unknown): string {
  const result = text(value, 63, true);
  if (!/^[a-z][a-z0-9_-]*$/.test(result)) throw failure('EK_MAIL_CONFIG');
  return result;
}
export function address(input: unknown): string {
  const value = text(input, 320, true);
  if (
    !validator.isEmail(value, {
      allow_utf8_local_part: true,
      allow_display_name: false,
      require_tld: true,
      allow_ip_domain: false,
      ignore_max_length: false,
    })
  )
    throw failure('EK_MAIL_CONFIG');
  const at = value.lastIndexOf('@'),
    domain = domainToASCII(value.slice(at + 1));
  if (!domain) throw failure('EK_MAIL_CONFIG');
  return value.slice(0, at) + '@' + domain.toLowerCase();
}
const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
  bufferGetter = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!,
  offsetGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset')!.get!,
  lengthGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
export function bytes(input: unknown, maximum: number): Uint8Array {
  try {
    if (!types.isUint8Array(input)) throw failure('EK_MAIL_CONFIG');
    const buffer = bufferGetter.call(input) as ArrayBuffer,
      offset = offsetGetter.call(input) as number,
      length = lengthGetter.call(input) as number;
    if (types.isSharedArrayBuffer(buffer) || length > maximum) throw failure('EK_MAIL_CONFIG');
    return new Uint8Array(buffer, offset, length).slice();
  } catch {
    throw failure('EK_MAIL_CONFIG');
  }
}
export interface Captured {
  readonly profiles: readonly MailTransportProfile[];
  readonly getSecret: SecretProvider['get'];
  readonly templates: ReadonlyMap<string, string>;
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
}
export function capture(settings: MailPluginSettings): Captured {
  const root = fields(settings, ['transports', 'secretProvider', 'templates', 'policy']),
    policy = fields(root.policy, ['maxConcurrent', 'timeoutMs', 'maxInputBytes', 'maxOutputBytes']);
  let getSecret: SecretProvider['get'];
  try {
    const provider = root.secretProvider as SecretProvider;
    if (!provider || typeof provider.get !== 'function') throw failure('EK_MAIL_CONFIG');
    getSecret = provider.get.bind(provider);
  } catch {
    throw failure('EK_MAIL_CONFIG');
  }
  const profiles = array(root.transports, 16).map((value): MailTransportProfile => {
    const data = fields(value, [
        'name',
        'host',
        'port',
        'requireTls',
        'usernameRef',
        'passwordRef',
        'allowedFromAddresses',
        'maxAttachmentBytes',
      ]),
      configuredHost = text(data.host, 253, true),
      host = isIP(configuredHost) ? configuredHost : domainToASCII(configuredHost).toLowerCase(),
      allowedFromAddresses = Object.freeze(array(data.allowedFromAddresses, 64).map(address));
    if (
      !host ||
      (!isIP(host) &&
        !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(
          host,
        )) ||
      data.requireTls !== true ||
      !allowedFromAddresses.length ||
      new Set(allowedFromAddresses).size !== allowedFromAddresses.length ||
      (data.usernameRef === undefined) !== (data.passwordRef === undefined)
    )
      throw failure('EK_MAIL_CONFIG');
    return Object.freeze({
      name: name(data.name),
      host,
      port: integer(data.port, 65535),
      requireTls: true,
      allowedFromAddresses,
      maxAttachmentBytes: integer(data.maxAttachmentBytes, 33554432),
      ...(data.usernameRef === undefined
        ? {}
        : {
            usernameRef: text(data.usernameRef, 256, true),
            passwordRef: text(data.passwordRef, 256, true),
          }),
    });
  });
  if (!profiles.length || new Set(profiles.map((profile) => profile.name)).size !== profiles.length)
    throw failure('EK_MAIL_CONFIG');
  const templateFields = fields(
    root.templates === undefined ? {} : root.templates,
    Reflect.ownKeys(root.templates ?? {}),
  );
  if (Reflect.ownKeys(templateFields).length > 64) throw failure('EK_MAIL_CONFIG');
  const templates = new Map<string, string>();
  let templateBytes = 0;
  for (const key of Reflect.ownKeys(templateFields)) {
    if (typeof key !== 'string') throw failure('EK_MAIL_CONFIG');
    const template = text(templateFields[key], 65536);
    templateBytes += Buffer.byteLength(template);
    if (templateBytes > 1048576) throw failure('EK_MAIL_CONFIG');
    templates.set(name(key), template);
  }
  return Object.freeze({
    profiles: Object.freeze(profiles),
    getSecret,
    templates,
    maxConcurrent: integer(policy.maxConcurrent, 8),
    timeoutMs: integer(policy.timeoutMs, 120000),
    maxInputBytes:
      policy.maxInputBytes === undefined ? 10485760 : integer(policy.maxInputBytes, 67108864),
    maxOutputBytes:
      policy.maxOutputBytes === undefined ? 16777216 : integer(policy.maxOutputBytes, 67108864),
  });
}
export function operation(input: MailOperationOptions | undefined, setting: Captured) {
  const data = fields(input === undefined ? {} : input, ['transport', 'signal', 'timeoutMs']),
    selected =
      data.transport === undefined
        ? setting.profiles.length === 1
          ? setting.profiles[0]
          : undefined
        : setting.profiles.find((profile) => profile.name === name(data.transport));
  if (!selected) throw failure('EK_MAIL_CONFIG');
  return {
    profile: selected,
    timeoutMs:
      data.timeoutMs === undefined
        ? setting.timeoutMs
        : Math.min(setting.timeoutMs, integer(data.timeoutMs, 120000)),
    signal: data.signal === undefined ? undefined : captureAbortSignal(data.signal),
  };
}
