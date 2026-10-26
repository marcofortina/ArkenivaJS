// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { X509Certificate } from 'node:crypto';
import { KitError } from '@arkenivajs/core';

export const parseError = () =>
  new KitError({ code: 'EK_MTLS_CONFIGURATION', message: 'Invalid or excessive certificate data' });
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
)!.get!;
const backing = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'buffer',
)!.get!;

/** Native copying avoids caller iterators, getters and shared-memory mutation during parsing. */
export function snapshot(value: unknown, maximum = 65536): Buffer {
  try {
    if (!(value instanceof Uint8Array)) throw parseError();
    const size: number = byteLength.call(value);
    if (size < 1 || size > maximum || backing.call(value) instanceof SharedArrayBuffer)
      throw parseError();
    const result = Buffer.alloc(size);
    Uint8Array.prototype.set.call(result, value);
    return result;
  } catch {
    throw parseError();
  }
}
/** Exactly one PEM or DER certificate; native parsing must not silently discard trailing input. */
export function nativeCertificate(input: Uint8Array | string, maximum = 65536): X509Certificate {
  try {
    let bytes: Buffer;
    if (typeof input === 'string') {
      if (input.length > maximum || Buffer.byteLength(input) > maximum) throw parseError();
      bytes = Buffer.from(input);
    } else bytes = snapshot(input, maximum);
    const pem = bytes[0] === 45 || bytes[0] === 32 || bytes[0] === 10 || bytes[0] === 13;
    if (typeof input === 'string' || pem) {
      const match =
        /^\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*$/.exec(
          bytes.toString('utf8'),
        );
      if (!match) throw parseError();
      const certificate = new X509Certificate(bytes),
        encoded = match[1]!.replace(/\s/g, '');
      if (certificate.raw.toString('base64') !== encoded) throw parseError();
      return certificate;
    }
    const certificate = new X509Certificate(bytes);
    if (!certificate.raw.equals(bytes)) throw parseError();
    return certificate;
  } catch {
    throw parseError();
  }
}
export function fingerprint(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !(/^[a-fA-F0-9]{64}$/.test(value) || /^(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}$/.test(value))
  )
    throw parseError();
  return value.replaceAll(':', '').toLowerCase();
}
/** Decode Node's quoted SAN representation without splitting commas inside JSON strings. */
export function alternativeNames(value: string | undefined) {
  const dnsSans: string[] = [],
    uriSans: string[] = [];
  if (value === undefined)
    return { dnsSans: Object.freeze(dnsSans), uriSans: Object.freeze(uriSans) };
  if (value.length > 65536) throw parseError();
  const entries: string[] = [];
  let start = 0,
    quoted = false,
    escaped = false;
  for (let index = 0; index < value.length; index++) {
    const character = value[index]!;
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
    } else if (character === '"') quoted = true;
    else if (character === ',') {
      entries.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  if (quoted || escaped) throw parseError();
  entries.push(value.slice(start).trim());
  if (entries.length > 256) throw parseError();
  for (const entry of entries) {
    const separator = entry.indexOf(':');
    if (separator < 1) throw parseError();
    const kind = entry.slice(0, separator),
      encoded = entry.slice(separator + 1).trim();
    if (!['DNS', 'URI'].includes(kind)) continue;
    let decoded: unknown;
    try {
      decoded = encoded.startsWith('"') ? JSON.parse(encoded) : encoded;
    } catch {
      throw parseError();
    }
    if (
      typeof decoded !== 'string' ||
      decoded.length < 1 ||
      decoded.length > 2048 ||
      [...decoded].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
    )
      throw parseError();
    (kind === 'DNS' ? dnsSans : uriSans).push(decoded);
  }
  return { dnsSans: Object.freeze(dnsSans), uriSans: Object.freeze(uriSans) };
}
export function metadata(certificate: X509Certificate) {
  const sans = alternativeNames(certificate.subjectAltName);
  return Object.freeze({
    subject: certificate.subject,
    issuer: certificate.issuer,
    ...sans,
    notBefore: certificate.validFromDate.toISOString(),
    notAfter: certificate.validToDate.toISOString(),
    fingerprintSha256: fingerprint(certificate.fingerprint256),
    publicKeyAlgorithm: certificate.publicKey.asymmetricKeyType ?? 'unknown',
  });
}
