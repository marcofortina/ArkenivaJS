// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isIP } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import { performance } from 'node:perf_hooks';
import type { X509Certificate } from 'node:crypto';
import type { Telemetry } from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
import type { CertificateValidation, X509Info, X509Service } from './contracts.js';
import { fingerprint, metadata, nativeCertificate, parseError, snapshot } from './certificate.js';
import { createRuntime, data, list } from './runtime.js';
import type { Settings } from './runtime.js';

const infoFields = [
  'subject',
  'issuer',
  'dnsSans',
  'uriSans',
  'notBefore',
  'notAfter',
  'fingerprintSha256',
  'publicKeyAlgorithm',
] as const;
const validation = (
  status: CertificateValidation['status'],
  reason: string,
): CertificateValidation => Object.freeze({ status, reasons: Object.freeze([reason]) });
function date(value: unknown): number {
  if (
    typeof value !== 'string' ||
    value.length !== 24 ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    throw parseError();
  return Date.parse(value);
}
function names(value: unknown): readonly string[] {
  return list(value, 256).map((name) => {
    if (
      typeof name !== 'string' ||
      name.length < 1 ||
      name.length > 2048 ||
      [...name].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
    )
      throw parseError();
    return name;
  });
}
function sameNames(first: readonly string[], second: unknown): boolean {
  const actual = names(second).slice().sort(),
    expected = first.slice().sort();
  return (
    actual.length === expected.length && actual.every((name, index) => name === expected[index])
  );
}
function validHostname(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 253 ||
    (!isIP(value) &&
      !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$/.test(
        value,
      ))
  )
    throw parseError();
}
function hostnameMatches(certificate: X509Certificate, hostname: string): boolean {
  if (isIP(hostname)) return certificate.checkIP(hostname) !== undefined;
  // Both checks are native; disabling subject fallback prevents CN-only authorization.
  return (
    certificate.checkHost(hostname, {
      subject: 'never',
      partialWildcards: false,
      multiLabelWildcards: false,
    }) !== undefined && checkServerIdentity(hostname, certificate.toLegacyObject()) === undefined
  );
}

export function createService(settings: Settings, telemetry?: Telemetry) {
  const runtime = createRuntime(settings),
    fingerprints = new WeakMap<X509Info, string>();
  const output = (value: unknown) => {
    if (Buffer.byteLength(JSON.stringify(value)) > settings.maxOutputBytes) throw parseError();
  };
  const result = (status: CertificateValidation['status'], reason: string) => {
    const value = validation(status, reason);
    output(value);
    return value;
  };
  function certificates(value: unknown, budget: { bytes: number }) {
    return list(value, 16, 1).map((entry) => {
      const owned = snapshot(entry, Math.min(65536, settings.maxInputBytes - budget.bytes));
      budget.bytes += owned.length;
      return nativeCertificate(owned);
    });
  }
  const service = Object.freeze<X509Service>({
    parse(input) {
      runtime.checkOpen();
      const certificate = nativeCertificate(input, Math.min(65536, settings.maxInputBytes)),
        info = metadata(certificate);
      output(info);
      fingerprints.set(info, certificate.fingerprint512.replaceAll(':', '').toLowerCase());
      return info;
    },
    inspectChain(input, inputTrust, options) {
      const started = performance.now();
      const record = (status: string) => {
        try {
          telemetry?.recordHistogram('x509.validation.duration_ms', performance.now() - started);
          telemetry?.addCounter('x509.validation.completed.' + status, 1);
        } catch {
          /* Diagnostic failures cannot change certificate trust. */
        }
      };
      return runtime
        .run(options, async (call) =>
          instrumentOperation(
            telemetry,
            'x509.inspect_chain',
            {},
            async () => {
              const trust = data(inputTrust, [
                'trustRoots',
                'expectedHostname',
                'requireRevocationCheck',
              ]);
              if (typeof trust.requireRevocationCheck !== 'boolean') throw parseError();
              if (trust.expectedHostname !== undefined) validHostname(trust.expectedHostname);
              const budget = { bytes: 0 },
                chain = certificates(input, budget),
                roots = certificates(trust.trustRoots, budget);
              const requested = roots.map((root) => fingerprint(root.fingerprint256)).sort();
              if (new Set(requested).size !== requested.length) throw parseError();
              const match = [...settings.roots.entries()].find(([, configured]) => {
                const expected = configured.map((root) => fingerprint(root.fingerprint256)).sort();
                return (
                  requested.length === expected.length &&
                  requested.every((value, index) => value === expected[index])
                );
              });
              if (!match) return result('untrusted', 'Trust roots are not configured');
              const now = Date.now();
              for (const certificate of [...chain, ...match[1]]) {
                if (certificate.validToDate.getTime() <= now)
                  return result('expired', 'Certificate has expired');
                if (certificate.validFromDate.getTime() > now)
                  return result('untrusted', 'Certificate is not yet valid');
              }
              const leaf = chain[0]!,
                seen = new Set<string>();
              for (let index = 0; index < chain.length; index++) {
                const current = chain[index]!,
                  id = fingerprint(current.fingerprint256);
                if (seen.has(id)) return result('untrusted', 'Certificate chain contains a cycle');
                seen.add(id);
                const parent = chain[index + 1];
                if (
                  parent &&
                  (!parent.ca || !current.checkIssued(parent) || !current.verify(parent.publicKey))
                )
                  return result('untrusted', 'Certificate chain linkage failed');
              }
              const last = chain[chain.length - 1]!;
              if (
                !match[1].some(
                  (root) =>
                    root.raw.equals(last.raw) ||
                    (last.checkIssued(root) && last.verify(root.publicKey)),
                )
              )
                return result('untrusted', 'Certificate chain is incomplete');
              if (
                trust.expectedHostname !== undefined &&
                !hostnameMatches(leaf, trust.expectedHostname)
              )
                return result('untrusted', 'Certificate hostname does not match');
              const info = metadata(leaf);
              call.check();
              let verified: unknown;
              try {
                // The trusted provider independently validates path, purpose and revocation. These
                // local linkage checks alone never establish complete PKI trust.
                verified = await settings.verify(
                  {
                    peerDer: Buffer.from(leaf.raw),
                    now: new Date(now).toISOString(),
                    policy: Object.freeze({
                      trustRootsRef: match[0],
                      allowedIdentities: Object.freeze(
                        trust.expectedHostname === undefined ? [] : [trust.expectedHostname],
                      ),
                      ...(trust.expectedHostname === undefined
                        ? {}
                        : { hostname: trust.expectedHostname }),
                      revocation: 'approved-online-checker',
                    }),
                  },
                  call.options,
                );
              } catch {
                call.check();
                return result('indeterminate', 'Trust verification is unavailable or denied');
              }
              call.check();
              try {
                const verifiedData = data(verified, [
                  'uriSans',
                  'dnsSans',
                  'certificateFingerprintSha256',
                  'issuer',
                  'notAfter',
                ]);
                if (
                  fingerprint(verifiedData.certificateFingerprintSha256) !==
                    info.fingerprintSha256 ||
                  verifiedData.issuer !== info.issuer ||
                  verifiedData.notAfter !== info.notAfter ||
                  !sameNames(info.uriSans, verifiedData.uriSans) ||
                  !sameNames(info.dnsSans, verifiedData.dnsSans)
                )
                  return result('untrusted', 'Trust verification is not bound to the certificate');
              } catch {
                return result('indeterminate', 'Trust verification returned invalid metadata');
              }
              if (
                [...chain, ...match[1]].some(
                  (certificate) => certificate.validToDate.getTime() <= Date.now(),
                )
              )
                return result('expired', 'Certificate has expired');
              return result('trusted', 'Configured chain and revocation verification succeeded');
            },
            () => {},
          ),
        )
        .then(
          (value) => {
            record(value.status);
            return value;
          },
          (error: unknown) => {
            record('error');
            throw error;
          },
        );
    },
    daysUntilExpiry(cert, at) {
      runtime.checkOpen();
      const info = data(cert, infoFields);
      return Math.floor(
        (date(info.notAfter) - (at === undefined ? Date.now() : date(at))) / 86400000,
      );
    },
    getFingerprints(cert) {
      runtime.checkOpen();
      const info = data(cert, infoFields),
        sha256 = fingerprint(info.fingerprintSha256),
        sha512 = fingerprints.get(cert);
      const result = Object.freeze({ sha256, ...(sha512 === undefined ? {} : { sha512 }) });
      output(result);
      return result;
    },
  });
  return {
    service,
    bootstrap(signal: AbortSignal) {
      runtime.bootstrap(signal);
      try {
        const roots = [...settings.roots.values()].flat();
        telemetry?.setGauge(
          'x509.trust_roots.expiring',
          roots.filter((root) => root.validToDate.getTime() - Date.now() <= 30 * 86400000).length,
        );
      } catch {
        /* Configured-root diagnostics contain no certificate identities. */
      }
    },
    close: runtime.close,
  };
}
