// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { createSecureContext } from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { isIP } from 'node:net';
import { Pool } from 'undici';
import {
  captureDestination,
  captureCidrs,
  allowedAddress,
  hostname,
  fields,
  failure,
  text,
} from './policy.js';
import { guardedLookup } from './network.js';
import type { ProxyDestinationPolicy } from './contracts.js';

/** Server-owned fixed network policy; callers own request bounds and the returned native pool. */
export interface FixedUpstreamPoolOptions {
  readonly upstreamOrigin: string;
  readonly destinationPolicy: ProxyDestinationPolicy;
  readonly connectionTimeoutMs: number;
  readonly upstreamCaFile?: string;
  /** Additional restrictions never expand the destination allowlist. */
  readonly deniedCidrs?: readonly string[];
}

/** A regular-file read has a fixed allocation even when deployment material changes concurrently. */
async function trustFile(path: string): Promise<Buffer> {
  if (!isAbsolute(path) || path.includes('\0')) throw failure();
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > 1048576n) throw failure();
    const content = Buffer.alloc(Number(before.size));
    let position = 0;
    while (position < content.length) {
      const part = await handle.read(content, position, content.length - position, position);
      if (!part.bytesRead) throw failure();
      position += part.bytesRead;
    }
    if ((await handle.read(Buffer.alloc(1), 0, 1, position)).bytesRead) throw failure();
    const after = await handle.stat({ bigint: true });
    if (
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs
    )
      throw failure();
    const pem = new TextDecoder('utf-8', { fatal: true }).decode(content),
      blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (
      !blocks ||
      blocks.length > 32 ||
      pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() !== ''
    )
      throw failure();
    for (const block of blocks) new X509Certificate(block);
    createSecureContext({ ca: content, minVersion: 'TLSv1.2' });
    return content;
  } finally {
    await handle.close();
  }
}

/** Reuse the proxy's destination and connect-time DNS checks without registering another listener. */
export async function createFixedUpstreamPool(input: FixedUpstreamPoolOptions): Promise<Pool> {
  try {
    const value = fields(input, [
      'upstreamOrigin',
      'destinationPolicy',
      'connectionTimeoutMs',
      'upstreamCaFile',
      'deniedCidrs',
    ]);
    const target = captureDestination(value.upstreamOrigin, value.destinationPolicy),
      timeout = value.connectionTimeoutMs;
    if (!Number.isSafeInteger(timeout) || (timeout as number) < 1 || (timeout as number) > 120000)
      throw failure();
    const denied = value.deniedCidrs === undefined ? [] : captureCidrs(value.deniedCidrs, 0);
    const permitted = (address: string) =>
      !denied.length ||
      !allowedAddress(address, {
        kind: 'private-allowlisted',
        allowedHosts: [],
        allowedCidrs: denied,
      });
    const host = hostname(new URL(target.upstreamOrigin).hostname);
    if (isIP(host) && !permitted(host)) throw failure();
    const ca =
      value.upstreamCaFile === undefined
        ? undefined
        : await trustFile(text(value.upstreamCaFile, 4096));
    return new Pool(target.upstreamOrigin, {
      allowH2: false,
      connections: 16,
      pipelining: 1,
      headersTimeout: timeout as number,
      bodyTimeout: timeout as number,
      maxHeaderSize: 16384,
      connect: {
        lookup: guardedLookup({ ...target, timeoutMs: timeout as number }, undefined, permitted),
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        timeout: timeout as number,
        ...(ca ? { ca } : {}),
      },
    });
  } catch {
    throw failure();
  }
}
