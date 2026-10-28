// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute } from 'node:path';
import { types } from 'node:util';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import type { KafkaClusterConfig, SecretRefResolver } from './contracts.js';
import { array, failure, fields, integer, text, topic } from './validation.js';

export interface Settings {
  readonly clusters: readonly KafkaClusterConfig[];
  readonly resolveSecret?: SecretRefResolver;
}
function name(value: unknown): string {
  const result = text(value, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(result)) throw failure();
  return result;
}
function broker(value: unknown): string {
  const result = text(value, 512);
  const match = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$/.exec(result);
  if (!match) throw failure();
  const host = match[1]!,
    port = match[2]!;
  integer(Number(port), 65535);
  if (host.startsWith('[')) {
    if (isIP(host.slice(1, -1)) !== 6) throw failure();
  } else if (!isIP(host)) {
    if (
      domainToASCII(host) !== host.toLowerCase() ||
      host.length > 253 ||
      !host
        .split('.')
        .every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))
    )
      throw failure();
  }
  return result;
}
/** Static validation opens no files, sockets or secret-provider operations. */
export function settings(input: unknown): Settings {
  const source = fields(input, ['clusters', 'resolveSecret']);
  if (
    source.resolveSecret !== undefined &&
    (typeof source.resolveSecret !== 'function' || types.isProxy(source.resolveSecret))
  )
    throw failure();
  const names = new Set<string>();
  const clusters = array(source.clusters, 16).map((value): KafkaClusterConfig => {
    const item = fields(value, [
      'name',
      'brokers',
      'clientId',
      'topics',
      'credentialSecretRef',
      'tlsCaFile',
      'maxBufferedMessages',
      'maxMessageBytes',
      'acks',
      'idempotentProducer',
    ]);
    const id = name(item.name);
    if (names.has(id) || item.acks !== 'all' || item.idempotentProducer !== true) throw failure();
    names.add(id);
    const brokers = array(item.brokers, 32).map(broker),
      topics = array(item.topics, 64).map(topic);
    if (
      !brokers.length ||
      !topics.length ||
      new Set(brokers).size !== brokers.length ||
      new Set(topics).size !== topics.length
    )
      throw failure();
    const maxBufferedMessages = integer(item.maxBufferedMessages, 10000),
      maxMessageBytes = integer(item.maxMessageBytes, 16777216);
    if (maxBufferedMessages * (maxMessageBytes + 16384) > 268435456) throw failure();
    const credentialSecretRef =
      item.credentialSecretRef === undefined ? undefined : text(item.credentialSecretRef, 512);
    const tlsCaFile = item.tlsCaFile === undefined ? undefined : text(item.tlsCaFile, 4096);
    if (
      (credentialSecretRef !== undefined && source.resolveSecret === undefined) ||
      (tlsCaFile !== undefined && !isAbsolute(tlsCaFile))
    )
      throw failure();
    return Object.freeze({
      name: id,
      brokers: Object.freeze(brokers),
      topics: Object.freeze(topics),
      clientId: name(item.clientId),
      maxBufferedMessages,
      maxMessageBytes,
      acks: 'all',
      idempotentProducer: true,
      ...(credentialSecretRef === undefined ? {} : { credentialSecretRef }),
      ...(tlsCaFile === undefined ? {} : { tlsCaFile }),
    });
  });
  if (!clusters.length) throw failure();
  return Object.freeze({
    clusters: Object.freeze(clusters),
    ...(source.resolveSecret === undefined
      ? {}
      : { resolveSecret: source.resolveSecret as SecretRefResolver }),
  });
}
