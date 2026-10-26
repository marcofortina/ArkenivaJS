// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import { createSecureContext, type TlsOptions } from 'node:tls';
import { KitError } from './errors.js';
import type { ServerTlsFiles } from './contracts.js';
import { validateServerTlsFiles } from './support.js';

const maximumBytes = 1048576;
/** A nonblocking open rejects pipes/devices before bounded regular-file reads. */
async function material(path: string): Promise<Buffer> {
  const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximumBytes)
      throw new Error('Invalid TLS material file');
    const buffer = Buffer.alloc(maximumBytes + 1);
    try {
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
        if (bytesRead === 0) break;
        length += bytesRead;
      }
      if (length < 1 || length > maximumBytes)
        throw new Error('TLS material exceeds its byte limit');
      return Buffer.from(buffer.subarray(0, length));
    } finally {
      buffer.fill(0);
    }
  } finally {
    await file.close();
  }
}

function certificates(bytes: Buffer): void {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (
    !blocks ||
    blocks.length > 32 ||
    text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() !== ''
  )
    throw new Error('Invalid PEM certificate chain');
  const now = Date.now();
  for (const block of blocks) {
    const cert = new X509Certificate(block);
    if (Date.parse(cert.validFrom) > now || Date.parse(cert.validTo) <= now)
      throw new Error('TLS certificate is outside its validity interval');
  }
}

/**
 * Startup-only private adapter. The consumer must construct its native TLS context before returning.
 * File/key/context failures never downgrade transport; temporary material is cleared on every path.
 */
export async function withServerTls<T>(
  input: ServerTlsFiles,
  consume: (options: Readonly<TlsOptions>) => T | Promise<T>,
): Promise<T> {
  const config = validateServerTlsFiles(input);
  let cert: Buffer | undefined, key: Buffer | undefined, ca: Buffer | undefined;
  try {
    const passphrase =
      config.privateKeyPassphraseEnv === undefined
        ? undefined
        : process.env[config.privateKeyPassphraseEnv];
    if (
      config.privateKeyPassphraseEnv !== undefined &&
      (typeof passphrase !== 'string' || passphrase.length < 1 || passphrase.length > 4096)
    )
      throw new Error('TLS passphrase is unavailable');
    cert = await material(config.certificateFile);
    certificates(cert);
    key = await material(config.privateKeyFile);
    if (config.caFile !== undefined) {
      ca = await material(config.caFile);
      certificates(ca);
    }
    const options: Readonly<TlsOptions> = Object.freeze({
      cert,
      key,
      ...(ca === undefined ? {} : { ca }),
      ...(passphrase === undefined ? {} : { passphrase }),
      minVersion: config.minVersion ?? 'TLSv1.2',
      requestCert: config.clientCertificate === 'required',
      rejectUnauthorized: true,
    });
    // OpenSSL validates key syntax, encryption and certificate/key matching before the consumer runs.
    createSecureContext(options);
    return await consume(options);
  } catch (cause) {
    throw new KitError({
      code: 'EK_HTTP_TLS_CERT',
      message: 'Server TLS material is unavailable or invalid',
      cause,
    });
  } finally {
    cert?.fill(0);
    key?.fill(0);
    ca?.fill(0);
  }
}
