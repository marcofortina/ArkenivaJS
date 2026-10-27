// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute, normalize } from 'node:path';
import { isIP } from 'node:net';
import type { Options } from 'amqplib';
import type { AmqpPluginSettings, SecretRefResolver } from './contracts.js';
import { outgoing } from './headers.js';
import { ensureNativeCodec } from './native-codec.js';
import { array, fields, integer, text, failure } from './validation.js';

export function identifier(input: unknown): string {
  const value = text(input, 64);
  if (!/^[A-Za-z][A-Za-z0-9_.-]*$/.test(value)) throw failure('EK_AMQP_CONFIG');
  return value;
}
export function protocolText(input: unknown, maximum: number, empty = false): string {
  const value = text(input, maximum, empty);
  if ([...value].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127))
    throw failure('EK_AMQP_CONFIG');
  return value;
}
function resource(input: unknown): string {
  const value = protocolText(input, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value) || value.startsWith('amq.'))
    throw failure('EK_AMQP_CONFIG');
  return value;
}
function boolean(input: unknown, defaultValue = false): boolean {
  if (input === undefined) return defaultValue;
  if (typeof input !== 'boolean') throw failure('EK_AMQP_CONFIG');
  return input;
}
function unique<T>(values: readonly T[], name: (value: T) => string): readonly T[] {
  if (new Set(values.map(name)).size !== values.length) throw failure('EK_AMQP_CONFIG');
  return Object.freeze(values);
}
export function capture(input: AmqpPluginSettings) {
  try {
    ensureNativeCodec();
    const value = fields(input, ['connections', 'resolveSecret']);
    if (typeof value.resolveSecret !== 'function') throw failure();
    let prototype: object | null = value.resolveSecret,
      usage: unknown;
    for (let i = 0; prototype && i < 64; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(prototype, 'usage');
      if (descriptor) {
        if (!('value' in descriptor)) throw failure();
        usage = descriptor.value;
        break;
      }
      prototype = Object.getPrototypeOf(prototype) as object | null;
    }
    if (usage !== undefined && usage !== 'production' && usage !== 'test-only') throw failure();
    const connections = unique(
      array(value.connections, 8).map((raw) => {
        const value = fields(raw, [
            'name',
            'connectionUriSecretRef',
            'tlsCaFile',
            'maxInFlightPublishes',
            'maxMessageBytes',
            'allowTopologyProvisioning',
            'topology',
          ]),
          topology = fields(value.topology, ['exchanges', 'queues', 'bindings']);
        const exchanges = unique(
            array(topology.exchanges, 32).map((raw) => {
              const value = fields(raw, ['name', 'type', 'routingKeys', 'durable']);
              if (!['direct', 'topic', 'fanout', 'headers'].includes(value.type as string))
                throw failure();
              const routingKeys = unique(
                array(value.routingKeys, 128).map((key) => protocolText(key, 255, true)),
                (key) => key,
              );
              if (!routingKeys.length) throw failure();
              return Object.freeze({
                name: resource(value.name),
                type: value.type as 'direct' | 'topic' | 'fanout' | 'headers',
                routingKeys,
                durable: boolean(value.durable, true),
              });
            }),
            (entry) => entry.name,
          ),
          queues = unique(
            array(topology.queues, 32).map((raw) => {
              const value = fields(raw, ['name', 'durable']);
              return Object.freeze({
                name: resource(value.name),
                durable: boolean(value.durable, true),
              });
            }),
            (entry) => entry.name,
          );
        if (!exchanges.length && !queues.length) throw failure();
        const bindings = unique(
          array(topology.bindings, 128).map((raw) => {
            const value = fields(raw, ['exchange', 'queue', 'routingKey', 'arguments']),
              exchange = resource(value.exchange),
              queue = resource(value.queue);
            if (
              !exchanges.some((entry) => entry.name === exchange) ||
              !queues.some((entry) => entry.name === queue)
            )
              throw failure();
            return Object.freeze({
              exchange,
              queue,
              routingKey: protocolText(value.routingKey, 255, true),
              arguments: outgoing(
                value.arguments as import('./contracts.js').AmqpHeaders | undefined,
              ).native,
            });
          }),
          (entry) => entry.exchange + '\0' + entry.queue + '\0' + entry.routingKey,
        );
        const maxMessageBytes = integer(value.maxMessageBytes, 16 * 1024 * 1024),
          maxInFlightPublishes = integer(value.maxInFlightPublishes, 1024);
        if (maxMessageBytes * maxInFlightPublishes > 64 * 1024 * 1024) throw failure();
        let tlsCaFile: string | undefined;
        if (value.tlsCaFile !== undefined) {
          tlsCaFile = protocolText(value.tlsCaFile, 4096);
          if (!isAbsolute(tlsCaFile) || normalize(tlsCaFile) !== tlsCaFile) throw failure();
        }
        return Object.freeze({
          name: identifier(value.name),
          connectionUriSecretRef: protocolText(value.connectionUriSecretRef, 256),
          ...(tlsCaFile ? { tlsCaFile } : {}),
          maxMessageBytes,
          maxInFlightPublishes,
          allowTopologyProvisioning: boolean(value.allowTopologyProvisioning),
          topology: Object.freeze({ exchanges, queues, bindings }),
        });
      }),
      (entry) => entry.name,
    );
    if (!connections.length) throw failure();
    return Object.freeze({
      connections,
      resolveSecret: Function.prototype.bind.call(value.resolveSecret, input) as SecretRefResolver,
      resolverUsage: usage as 'production' | 'test-only' | undefined,
    });
  } catch {
    throw failure('EK_AMQP_CONFIG');
  }
}
/** Translate a trusted secret URI into explicit native connection fields, never implicit guest defaults. */
export function endpoint(secret: unknown): Options.Connect {
  try {
    const value = protocolText(secret, 8192),
      url = new URL(value);
    if (
      value.trim() !== value ||
      value.includes('?') ||
      value.includes('#') ||
      url.protocol !== 'amqps:' ||
      !url.hostname ||
      !url.username ||
      !url.password ||
      url.search ||
      url.hash
    )
      throw failure();
    const username = protocolText(decodeURIComponent(url.username), 256),
      password = protocolText(decodeURIComponent(url.password), 1024),
      hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (
      !isIP(hostname) &&
      hostname.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
    )
      throw failure();
    const rawPath = url.pathname.slice(1),
      vhost = rawPath ? decodeURIComponent(rawPath) : '/';
    protocolText(vhost, 255);
    // The pinned native openFrames routine decodes object-form vhosts once; preserve literal percent signs.
    return Object.freeze({
      protocol: 'amqps',
      hostname,
      port: integer(url.port ? Number(url.port) : 5671, 65535),
      username,
      password,
      vhost: encodeURIComponent(vhost),
      heartbeat: 10,
      channelMax: 128,
      frameMax: 131072,
      locale: 'en_US',
    });
  } catch {
    throw failure('EK_AMQP_CONFIG');
  }
}
export type Settings = ReturnType<typeof capture>;
export type ConnectionSettings = Settings['connections'][number];
