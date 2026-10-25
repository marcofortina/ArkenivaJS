import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isIP } from 'node:net';
import { rootCertificates, DEFAULT_MIN_VERSION } from 'node:tls';
import { noop } from 'cockatiel';
import type { IOptions } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import type { DatabaseDefinition, Environment } from '@arkenivajs/core';

/** Only the native client's supported transport and fault-policy configuration is captured. */
export interface EtcdConfiguration {
  readonly native: Pick<IOptions, 'hosts' | 'credentials' | 'grpcOptions' | 'faultHandling'>;
  readonly prefix: string;
}

function material(path: string): Buffer {
  if (!isAbsolute(path) || /[\0\r\n]/.test(path))
    throw new Error('etcd TLS files require absolute paths');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 1_048_576)
      throw new Error('Invalid etcd TLS file');
    const value = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < value.length) {
      const count = readSync(fd, value, used, value.length - used, null);
      if (!count) break;
      used += count;
    }
    if (used !== stat.size) throw new Error('etcd TLS file changed during capture');
    return value.subarray(0, used);
  } finally {
    closeSync(fd);
  }
}

function endpoint(value: string, query: boolean): URL {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value) > 65_536 ||
    Array.from(value).some(
      (character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127,
    ) ||
    value.includes('#')
  )
    throw new Error('Invalid etcd endpoint syntax');
  const url = new URL(value),
    host = url.hostname.replace(/^\[|\]$/g, '');
  const validHost =
    isIP(host) !== 0 ||
    (host.length <= 253 &&
      host
        .split('.')
        .every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?![\s\S])/.test(label)));
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    !validHost ||
    url.username ||
    url.password ||
    !['', '/'].includes(url.pathname) ||
    (url.port !== '' && Number(url.port) < 1) ||
    (!query && url.search !== '')
  )
    throw new Error(
      'etcd endpoints require explicit HTTP(S) origins without credentials or resource paths',
    );
  return url;
}

/** Capture explicit origins and mTLS identity; only local development may omit authentication. */
export function etcdConfiguration(
  definition: DatabaseDefinition,
  environment: Environment,
): EtcdConfiguration {
  const variable = definition.connectionStringEnv;
  if (variable !== undefined && !/^[A-Z_][A-Z0-9_]*(?![\s\S])/.test(variable))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'Invalid etcd connectionStringEnv name',
    });
  const value = variable === undefined ? undefined : process.env[variable];
  if ((variable !== undefined && !value) || (!value && definition.endpoints === undefined))
    throw new KitError({
      code: 'EK_CONFIG_MISSING',
      message: 'Explicit etcd endpoints or connection environment are required',
    });
  try {
    if (
      definition.driver !== 'etcd' ||
      definition.poolMin !== undefined ||
      definition.poolMax !== undefined ||
      (definition.endpoints !== undefined && !Array.isArray(definition.endpoints))
    )
      throw new Error('etcd requires its native client rather than SQL pool options');
    const configured = value === undefined ? undefined : endpoint(value, true);
    const source = definition.endpoints ?? (configured ? [configured.origin] : []);
    if (!Array.isArray(source) || source.length < 1 || source.length > 8)
      throw new Error('etcd requires one to eight explicit endpoints');
    const urls = source.map((item) => endpoint(item, false));
    if (configured && configured.origin !== urls[0]!.origin)
      throw new Error('The first etcd endpoint must match the connection environment origin');
    const secure = urls[0]!.protocol === 'https:';
    if (urls.some((url) => (url.protocol === 'https:') !== secure))
      throw new Error('etcd cannot mix TLS and plaintext endpoints');
    const local =
      environment !== 'production' &&
      urls.every((url) => {
        const host = url.hostname.replace(/^\[|\]$/g, '');
        return (
          host === 'localhost' || host === '::1' || (isIP(host) === 4 && host.startsWith('127.'))
        );
      });
    if (!secure && !local) throw new Error('etcd network connections require authenticated TLS');
    const parameters = configured?.searchParams ?? new URLSearchParams();
    for (const key of parameters.keys())
      if (
        !['sslca', 'sslcert', 'sslkey', 'prefix'].includes(key) ||
        parameters.getAll(key).length !== 1
      )
        throw new Error('Unsupported or duplicate etcd connection option');
    const ca = parameters.get('sslca'),
      cert = parameters.get('sslcert'),
      key = parameters.get('sslkey');
    if (
      (!secure && [ca, cert, key].some((item) => item !== null)) ||
      (cert === null) !== (key === null) ||
      (!local && cert === null)
    )
      throw new Error('etcd mTLS requires an explicit client certificate and private key');
    if (secure && !['TLSv1.2', 'TLSv1.3'].includes(DEFAULT_MIN_VERSION))
      throw new Error('The native etcd TLS context requires a process minimum of TLS 1.2 or later');
    const prefix = parameters.get('prefix') ?? '';
    if (prefix !== '' && !/^\/(?:[A-Za-z0-9/_:-]{0,254}\/)?(?![\s\S])/.test(prefix))
      throw new Error('etcd namespace must be a bounded absolute prefix ending with a slash');
    return {
      prefix,
      native: {
        hosts: urls.map(
          (url) => `${url.protocol}//${url.hostname}:${url.port || (secure ? 443 : 80)}`,
        ),
        ...(secure
          ? {
              credentials: {
                rootCertificate:
                  ca === null ? Buffer.from(rootCertificates.join('\n')) : material(ca),
                ...(cert === null ? {} : { certChain: material(cert), privateKey: material(key!) }),
              },
            }
          : {}),
        grpcOptions: {
          'grpc.enable_retries': 0,
          'grpc.max_receive_message_length': 2_097_152,
          'grpc.max_send_message_length': 2_097_152,
          'grpc.initial_reconnect_backoff_ms': 100,
          'grpc.min_reconnect_backoff_ms': 100,
          'grpc.max_reconnect_backoff_ms': 1000,
        },
        // Transport reconnection and watch resumption never authorize replay of a unary write.
        faultHandling: { global: noop, host: () => noop },
      },
    };
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid etcd endpoint, namespace or mutual TLS policy',
      cause,
    });
  }
}
