import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { createSecureContext, rootCertificates, DEFAULT_MIN_VERSION } from 'node:tls';
import { ConnectionString } from 'mongodb-connection-string-url';
import type { MongoClientOptions } from 'mongodb';
import { KitError } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';

/** The selected SDK's official URI parser handles multi-host and SRV syntax. */
export interface MongoConfiguration {
  readonly url: string;
  readonly database: string;
  readonly prefix: string;
  readonly native: Readonly<MongoClientOptions>;
}

function controls(value: string): boolean {
  return Array.from(value).some(
    (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
  );
}

function material(path: string): Buffer {
  if (!isAbsolute(path) || controls(path))
    throw new Error('MongoDB TLS material requires an absolute path');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 1_048_576)
      throw new Error('Invalid MongoDB TLS material');
    const buffer = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(fd, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    if (used !== stat.size) throw new Error('MongoDB TLS material changed during capture');
    return buffer.subarray(0, used);
  } finally {
    closeSync(fd);
  }
}

function databaseName(name: string): string {
  if (
    !name ||
    Buffer.byteLength(name) > 63 ||
    controls(name) ||
    /[\\/. "$*<>:|?]/.test(name) ||
    Buffer.from(name).toString('utf8') !== name
  )
    throw new Error('MongoDB requires an explicit valid database name');
  return name;
}

/** Validate and capture configuration without constructing a MongoClient or resolving SRV records. */
export function mongoConfiguration(
  definition: DatabaseDefinition,
  environment: Environment,
): MongoConfiguration {
  const variable = definition.connectionStringEnv;
  if (
    typeof variable !== 'string' ||
    !/^[A-Z_][A-Z0-9_]*(?![\s\S])/.test(variable) ||
    !process.env[variable]
  )
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'A declared MongoDB connection environment is required',
    });
  try {
    if (
      definition.driver !== 'mongodb' ||
      definition.endpoints !== undefined ||
      definition.poolMin !== undefined ||
      definition.poolMax !== undefined
    )
      throw new Error('MongoDB requires its native connection URI');
    const value = process.env[variable]!;
    if (Buffer.byteLength(value) > 65_536 || controls(value) || value.includes('#'))
      throw new Error('Invalid MongoDB connection URI syntax');
    const parsed = new ConnectionString(value);
    if (parsed.hosts.length < 1 || parsed.hosts.length > 8)
      throw new Error('MongoDB requires bounded seed hosts');
    const hosts = parsed.hosts.map((host) => {
      const url = new URL('tcp://' + host);
      const name = url.hostname.replace(/^\[|\]$/g, '');
      if (
        !name ||
        url.username ||
        url.password ||
        (url.pathname !== '' && url.pathname !== '/') ||
        url.search ||
        url.hash ||
        (url.port !== '' &&
          (!/^\d+$/.test(url.port) || Number(url.port) < 1 || Number(url.port) > 65535)) ||
        (isIP(name) === 0 &&
          (name.length > 253 ||
            !name
              .split('.')
              .every((label) =>
                /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?![\s\S])/.test(label),
              )))
      )
        throw new Error('MongoDB seed hosts require explicit valid TCP or SRV names');
      return name;
    });
    const parameters = new Map<string, string>();
    const allowed = new Set([
      'tls',
      'tlscafile',
      'authsource',
      'authmechanism',
      'directconnection',
      'replicaset',
      'prefix',
    ]);
    for (const [key, content] of parsed.searchParams) {
      const normalized = key.toLowerCase();
      if (!allowed.has(normalized) || parameters.has(normalized) || !content || controls(content))
        throw new Error('Unsupported, duplicate or empty MongoDB URI option');
      parameters.set(normalized, content);
    }
    for (const key of ['tls', 'directconnection']) {
      const option = parameters.get(key);
      if (option !== undefined && option !== 'true' && option !== 'false')
        throw new Error('MongoDB boolean options require true or false');
    }
    const local =
      environment !== 'production' &&
      !parsed.isSRV &&
      hosts.every((host) => ['localhost', '127.0.0.1', '::1'].includes(host));
    const tls =
      parameters.get('tls') === 'true' || (parsed.isSRV && parameters.get('tls') !== 'false');
    if (!tls && !local)
      throw new Error('MongoDB remote and production connections require verified TLS');
    if ((!parsed.username || !parsed.password) && !local)
      throw new Error('MongoDB remote and production connections require scoped credentials');
    if (Boolean(parsed.username) !== Boolean(parsed.password))
      throw new Error('MongoDB credentials must include both username and password');
    if (parameters.has('authmechanism') && parameters.get('authmechanism') !== 'SCRAM-SHA-256')
      throw new Error('The portable MongoDB profile requires SCRAM-SHA-256');
    const database = databaseName(decodeURIComponent(parsed.pathname.slice(1)));
    if (parameters.has('authsource')) databaseName(parameters.get('authsource')!);
    const prefix = parameters.get('prefix') ?? '';
    if (!/^[A-Za-z0-9_-]{0,64}(?![\s\S])/.test(prefix))
      throw new Error('MongoDB collection prefix must be bounded ASCII');
    if (
      parameters.has('directconnection') &&
      parameters.get('directconnection') === 'true' &&
      (parsed.isSRV || hosts.length !== 1)
    )
      throw new Error('MongoDB direct connections require one non-SRV seed');
    if (
      parameters.has('replicaset') &&
      !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(parameters.get('replicaset')!)
    )
      throw new Error('Invalid MongoDB replica-set name');
    if (!tls && parameters.has('tlscafile')) throw new Error('MongoDB CA material requires TLS');
    if (tls && !['TLSv1.2', 'TLSv1.3'].includes(DEFAULT_MIN_VERSION))
      throw new Error('The process TLS policy must require TLS 1.2 or newer');
    const ca = tls
      ? parameters.has('tlscafile')
        ? material(parameters.get('tlscafile')!)
        : [...rootCertificates]
      : undefined;
    // The SDK receives captured trust material, rather than reopening a mutable CA path on reconnect.
    for (const key of [...parsed.searchParams.keys()])
      if (['prefix', 'tlscafile'].includes(key.toLowerCase())) parsed.searchParams.delete(key);
    return Object.freeze({
      url: parsed.toString(),
      database,
      prefix,
      native: Object.freeze({
        tls,
        ...(tls
          ? {
              secureContext: createSecureContext({ ca, minVersion: DEFAULT_MIN_VERSION }),
              rejectUnauthorized: true,
            }
          : {}),
        ...(parsed.username ? { authMechanism: 'SCRAM-SHA-256' as const } : {}),
        minPoolSize: 0,
        maxPoolSize: 8,
        maxConnecting: 2,
        waitQueueTimeoutMS: 5000,
        connectTimeoutMS: 5000,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 0,
        retryReads: false,
        retryWrites: false,
        maxAdaptiveRetries: 0,
        enableOverloadRetargeting: false,
        monitorCommands: true,
        promoteLongs: false,
        mongodbLogComponentSeverities: {
          default: 'off',
          command: 'off',
          topology: 'off',
          serverSelection: 'off',
          connection: 'off',
          client: 'off',
        },
      } satisfies MongoClientOptions),
    });
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid MongoDB connection configuration',
      cause,
    });
  }
}
