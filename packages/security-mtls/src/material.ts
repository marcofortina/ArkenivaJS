// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPrivateKey } from 'node:crypto';
import type { X509Certificate } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import type { TlsProfile } from './contracts.js';
import { nativeCertificate, snapshot } from './certificate.js';
import { data, invalid, list } from './runtime.js';
import { strings } from './settings.js';
import type { Settings } from './settings.js';

/** Only owned bounded snapshots enter the active credential generation. */
export interface Material {
  readonly ca: readonly Buffer[];
  readonly cert: Buffer;
  readonly key: Buffer;
  readonly leaf: X509Certificate;
  readonly certificates: readonly X509Certificate[];
  readonly minVersion: 'TLSv1.2' | 'TLSv1.3';
  readonly ALPNProtocols?: readonly string[];
}
export function privateKey(value: Buffer) {
  try {
    return createPrivateKey(value);
  } catch {
    try {
      return createPrivateKey({ key: value, format: 'der', type: 'pkcs8' });
    } catch {
      throw invalid();
    }
  }
}
function chain(value: Buffer): readonly X509Certificate[] {
  if (value[0] === 48) return [nativeCertificate(value)];
  const source = value.toString('utf8'),
    matches = [
      ...source.matchAll(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----/g),
    ];
  if (
    matches.length < 1 ||
    matches.length > 16 ||
    source
      .replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----/g, '')
      .trim() !== ''
  )
    throw invalid();
  return matches.map((match) => nativeCertificate(match[0]));
}
export function current(material: Material) {
  const now = Date.now();
  if (
    material.certificates.some(
      (cert) => cert.validFromDate.getTime() > now || cert.validToDate.getTime() <= now,
    )
  )
    throw invalid();
}
export function clear(material: Material) {
  material.key.fill(0);
}

/** Native context construction catches key/certificate mismatch before any consumer can listen. */
export function captureMaterial(value: unknown, profile: TlsProfile, settings: Settings): Material {
  const owned: Buffer[] = [];
  const copy = (value: unknown, maximum: number) => {
    const result = snapshot(value, maximum);
    owned.push(result);
    return result;
  };
  let result: Material | undefined;
  try {
    const fields = data(value, ['ca', 'cert', 'key', 'minVersion', 'ALPNProtocols']);
    let bytes = 0;
    const roots = list(fields.ca, 16, 1).map((input) => {
      const copied = copy(input, Math.min(65536, settings.maxInputBytes - bytes));
      bytes += copied.length;
      const root = nativeCertificate(copied);
      if (!root.ca) throw invalid();
      return root;
    });
    if (new Set(roots.map((root) => root.fingerprint256)).size !== roots.length) throw invalid();
    const certificate = copy(fields.cert, settings.maxInputBytes - bytes);
    bytes += certificate.length;
    const keyBytes = copy(fields.key, Math.min(65536, settings.maxInputBytes - bytes)),
      certificates = chain(certificate),
      leaf = certificates[0]!;
    if (leaf.ca || !leaf.checkPrivateKey(privateKey(keyBytes))) throw invalid();
    for (let index = 0; index < certificates.length - 1; index++) {
      const child = certificates[index]!,
        parent = certificates[index + 1]!;
      if (!parent.ca || !child.checkIssued(parent) || !child.verify(parent.publicKey))
        throw invalid();
    }
    const last = certificates[certificates.length - 1]!;
    if (
      !roots.some(
        (root) =>
          root.raw.equals(last.raw) || (last.checkIssued(root) && last.verify(root.publicKey)),
      )
    )
      throw invalid();
    if (fields.minVersion !== profile.minTlsVersion) throw invalid();
    const protocols =
      fields.ALPNProtocols === undefined ? undefined : strings(fields.ALPNProtocols, 16);
    if (JSON.stringify(protocols) !== JSON.stringify(profile.alpnProtocols)) throw invalid();
    const key = privateKey(keyBytes).export({ format: 'der', type: 'pkcs8' });
    result = {
      ca: Object.freeze(roots.map((root) => Buffer.from(root.toString()))),
      cert: Buffer.from(certificates.map((cert) => cert.toString()).join('')),
      key,
      leaf,
      certificates: Object.freeze([...certificates, ...roots]),
      minVersion: fields.minVersion as Material['minVersion'],
      ...(protocols === undefined ? {} : { ALPNProtocols: protocols }),
    };
    current(result);
    createSecureContext({
      ca: [...result.ca],
      cert: result.cert,
      key: privateKey(key).export({ format: 'pem', type: 'pkcs8' }),
      minVersion: result.minVersion,
    });
    if (
      result.ca.reduce((size, ca) => size + ca.length, result.cert.length + result.key.length) >
      settings.maxOutputBytes
    )
      throw invalid();
    return Object.freeze(result);
  } catch {
    if (result) clear(result);
    throw invalid();
  } finally {
    for (const value of owned) value.fill(0);
  }
}
