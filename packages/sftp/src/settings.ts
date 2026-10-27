// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { posix } from 'node:path';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import type { SecretProvider, SftpPluginSettings } from './contracts.js';
import { array, fields, integer, method, property, text, failure } from './validation.js';

export function identifier(input: unknown): string {
  const value = text(input, 64);
  if (!/^[A-Za-z][A-Za-z0-9_.-]*$/.test(value)) throw failure();
  return value;
}
export function remotePath(input: unknown): string {
  const value = text(input, 4096);
  if (
    !value.startsWith('/') ||
    value.includes('\\') ||
    [...value].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw failure();
  return posix.normalize(value).replace(/\/$/, '') || '/';
}
export function within(path: string, root: string): boolean {
  return root === '/' || path === root || path.startsWith(root + '/');
}
function fingerprint(input: unknown): string {
  const value = text(input, 64);
  if (!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(value)) throw failure();
  const raw = value.slice(7),
    bytes = Buffer.from(raw, 'base64');
  if (bytes.length !== 32 || bytes.toString('base64').replace(/=+$/, '') !== raw.replace(/=+$/, ''))
    throw failure();
  return 'SHA256:' + bytes.toString('base64').replace(/=+$/, '');
}
export function capture(input: SftpPluginSettings) {
  try {
    const value = fields(input, ['connections', 'secretProvider', 'policy', 'allowedCommands']),
      policy = fields(value.policy, [
        'maxConcurrent',
        'timeoutMs',
        'maxInputBytes',
        'maxOutputBytes',
      ]);
    const names = new Set<string>();
    const connections = array(value.connections, 16).map((raw) => {
      const value = fields(raw, [
          'name',
          'host',
          'port',
          'username',
          'privateKeyRef',
          'knownHostSha256',
          'allowedRemoteRoots',
        ]),
        name = identifier(value.name);
      if (names.has(name)) throw failure();
      names.add(name);
      const suppliedHost = text(value.host, 253),
        host = isIP(suppliedHost) ? suppliedHost : domainToASCII(suppliedHost).toLowerCase();
      if (
        !host ||
        (!isIP(host) &&
          (host.length > 253 ||
            host.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))))
      )
        throw failure();
      const pins = array(value.knownHostSha256, 16).map(fingerprint),
        roots = array(value.allowedRemoteRoots, 16).map(remotePath),
        username = text(value.username, 256),
        reference = text(value.privateKeyRef, 256);
      if (
        !pins.length ||
        !roots.length ||
        new Set(pins).size !== pins.length ||
        new Set(roots).size !== roots.length ||
        [...(username + reference)].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
      )
        throw failure();
      return Object.freeze({
        name,
        host,
        port: integer(value.port, 65535),
        username,
        privateKeyRef: reference,
        pins: Object.freeze(pins),
        roots: Object.freeze(roots),
      });
    });
    if (!connections.length) throw failure();
    const commands: Record<
      string,
      Readonly<{ executable: string; arguments: readonly string[]; parameters: readonly string[] }>
    > = Object.create(null);
    for (const [name, raw] of Object.entries(fields(value.allowedCommands ?? {}))) {
      identifier(name);
      const data = fields(raw, ['executable', 'arguments']),
        executable = text(data.executable, 4096);
      if (
        !executable.startsWith('/') ||
        posix.normalize(executable) !== executable ||
        !/^\/[A-Za-z0-9_./-]+$/.test(executable) ||
        executable.split('/').includes('..')
      )
        throw failure();
      const parameters = new Set<string>(),
        arguments_ = array(data.arguments, 64).map((raw) => {
          const token = text(raw, 4096, true),
            placeholder = /^\{([A-Za-z][A-Za-z0-9_]{0,63})\}$/.exec(token);
          if (
            [...token].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127) ||
            (!placeholder && /[{}]/.test(token))
          )
            throw failure();
          if (placeholder) parameters.add(placeholder[1]!);
          return token;
        });
      commands[name] = Object.freeze({
        executable,
        arguments: Object.freeze(arguments_),
        parameters: Object.freeze([...parameters]),
      });
    }
    const usage = property(value.secretProvider, 'usage');
    if (usage !== undefined && !['production', 'test-only'].includes(usage as string))
      throw failure();
    return Object.freeze({
      connections: Object.freeze(connections),
      commands: Object.freeze(commands),
      getSecret: method<SecretProvider['get']>(value.secretProvider, 'get'),
      providerUsage: usage as 'production' | 'test-only' | undefined,
      maxConcurrent: integer(policy.maxConcurrent, 8),
      timeoutMs: integer(policy.timeoutMs, 120000),
      maxInputBytes: integer(policy.maxInputBytes ?? 64 * 1024 * 1024, 1024 ** 4),
      maxOutputBytes: integer(policy.maxOutputBytes ?? 64 * 1024 * 1024, 1024 ** 4),
    });
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Settings = ReturnType<typeof capture>;
export type Profile = Settings['connections'][number];
