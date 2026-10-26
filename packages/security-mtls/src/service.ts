// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import type { Telemetry } from '@arkenivajs/core';
import { instrumentOperation } from '@arkenivajs/core/support';
import type {
  MtlsService,
  NativeTlsOptions,
  TlsClientOptions,
  TlsProfile,
  TlsServerOptions,
  TlsTrustVerificationPolicy,
  VerifiedPeerIdentity,
} from './contracts.js';
import { fingerprint, metadata, nativeCertificate, snapshot } from './certificate.js';
import { captureMaterial, clear, current, privateKey } from './material.js';
import type { Material } from './material.js';
import { createRuntime, data, failure, invalid } from './runtime.js';
import type { Call } from './runtime.js';
import { hostname, profileKey, strings } from './settings.js';
import type { Settings } from './settings.js';

export function createService(settings: Settings, telemetry?: Telemetry) {
  const runtime = createRuntime(settings),
    issued = new WeakMap<
      object,
      { role: 'client' | 'server'; epoch: object; material: Material; servername?: string }
    >();
  let active = new Map<string, Material>(),
    epoch = {},
    reloading = false;
  const resolve = (input: TlsProfile) => {
    const id = profileKey(input),
      value = settings.profiles.get(id);
    if (!value) throw invalid();
    return { id, profile: value };
  };
  function output(bytes: number) {
    if (bytes > settings.maxOutputBytes) throw invalid();
  }
  async function load(call: Call) {
    const next = new Map<string, Material>();
    try {
      let size = 0;
      for (const [id, profile] of settings.profiles) {
        const value = await settings.load(profile, call.options);
        call.check();
        const captured = captureMaterial(value, profile, settings);
        next.set(id, captured);
        size +=
          captured.key.length +
          captured.cert.length +
          captured.ca.reduce((sum, ca) => sum + ca.length, 0);
        if (size > 16777216) throw invalid();
      }
      call.check();
      return next;
    } catch {
      for (const material of next.values()) clear(material);
      call.check();
      throw invalid();
    }
  }
  function material(input: TlsProfile) {
    const { id } = resolve(input),
      result = active.get(id);
    if (!result) throw invalid();
    current(result);
    return result;
  }
  function options(input: TlsProfile, servername?: string) {
    const value = material(input);
    const result = Object.freeze({
      ca: Object.freeze(value.ca.map((ca) => Buffer.from(ca))),
      cert: Buffer.from(value.cert),
      key: Buffer.from(value.key),
      minVersion: value.minVersion,
      ...(value.ALPNProtocols === undefined ? {} : { ALPNProtocols: value.ALPNProtocols }),
      rejectUnauthorized: true as const,
      ...(servername === undefined ? { requestCert: true as const } : { servername }),
    });
    issued.set(result, {
      role: servername === undefined ? 'server' : 'client',
      epoch,
      material: value,
      ...(servername === undefined ? {} : { servername }),
    });
    return result;
  }
  function convert(
    input: TlsClientOptions | TlsServerOptions,
    role: 'client' | 'server',
  ): NativeTlsOptions {
    runtime.checkOpen();
    const source = issued.get(input);
    if (!source || source.role !== role || source.epoch !== epoch) throw invalid();
    current(source.material);
    const fields = data(input, [
      'ca',
      'cert',
      'key',
      'minVersion',
      'ALPNProtocols',
      'rejectUnauthorized',
      ...(role === 'client' ? ['servername'] : ['requestCert']),
    ]);
    const owned: Buffer[] = [];
    try {
      const cert = snapshot(fields.cert, settings.maxOutputBytes),
        key = snapshot(fields.key, 65536);
      owned.push(cert, key);
      if (
        !cert.equals(source.material.cert) ||
        !key.equals(source.material.key) ||
        fields.minVersion !== source.material.minVersion ||
        fields.rejectUnauthorized !== true ||
        (role === 'client'
          ? fields.servername !== source.servername
          : fields.requestCert !== true) ||
        JSON.stringify(fields.ALPNProtocols) !== JSON.stringify(source.material.ALPNProtocols)
      )
        throw invalid();
      const ca = Array.isArray(fields.ca) ? fields.ca : [];
      if (ca.length !== source.material.ca.length) throw invalid();
      for (let index = 0; index < ca.length; index++) {
        const copy = snapshot(ca[index], settings.maxOutputBytes);
        owned.push(copy);
        if (!copy.equals(source.material.ca[index]!)) throw invalid();
      }
      const native: NativeTlsOptions = {
        ca: source.material.ca.map((root) => root.toString()),
        cert: cert.toString(),
        key: privateKey(key).export({ format: 'pem', type: 'pkcs8' }).toString(),
        minVersion: source.material.minVersion,
        ...(source.material.ALPNProtocols === undefined
          ? {}
          : { ALPNProtocols: [...source.material.ALPNProtocols] }),
        rejectUnauthorized: true,
        ...(role === 'client' ? { servername: source.servername! } : { requestCert: true }),
      };
      output(Buffer.byteLength(JSON.stringify(native)));
      return Object.freeze(native);
    } finally {
      for (const buffer of owned) buffer.fill(0);
    }
  }
  function policy(input: TlsTrustVerificationPolicy): TlsTrustVerificationPolicy {
    const fields = data(input, ['trustRootsRef', 'allowedIdentities', 'hostname', 'revocation']),
      identities = strings(fields.allowedIdentities, 64);
    if (fields.hostname !== undefined) hostname(fields.hostname);
    if (
      ![...settings.profiles.values()].some(
        (profile) =>
          profile.trustRootsRef === fields.trustRootsRef &&
          profile.revocation === fields.revocation &&
          JSON.stringify(profile.allowedIdentities) === JSON.stringify(identities),
      )
    )
      throw failure();
    return Object.freeze({
      trustRootsRef: fields.trustRootsRef as string,
      allowedIdentities: identities,
      ...(fields.hostname === undefined ? {} : { hostname: fields.hostname }),
      revocation: fields.revocation as TlsProfile['revocation'],
    });
  }
  const discard = (values: Map<string, Material>) => {
    for (const material of values.values()) clear(material);
  };
  async function replace(operation?: import('@arkenivajs/core').OperationOptions) {
    let next: Map<string, Material> | undefined;
    try {
      next = await runtime.run(operation, load, discard);
      runtime.checkOpen();
      const previous = active;
      active = next;
      next = undefined;
      epoch = {};
      discard(previous);
    } finally {
      if (next) discard(next);
    }
  }
  const service = Object.freeze<MtlsService>({
    createClientOptions(input, servername, operation) {
      return runtime.run(
        operation,
        async () => {
          hostname(servername);
          const usages = material(input).leaf.keyUsage;
          if (usages && !usages.includes('1.3.6.1.5.5.7.3.2') && !usages.includes('2.5.29.37.0'))
            throw invalid();
          return options(input, servername) as TlsClientOptions;
        },
        (value) => value.key.fill(0),
      );
    },
    createServerOptions(input, operation) {
      return runtime.run(
        operation,
        async () => {
          const usages = material(input).leaf.keyUsage;
          if (usages && !usages.includes('1.3.6.1.5.5.7.3.1') && !usages.includes('2.5.29.37.0'))
            throw invalid();
          return options(input) as TlsServerOptions;
        },
        (value) => value.key.fill(0),
      );
    },
    toNodeClientOptions(input) {
      return convert(input, 'client');
    },
    toNodeServerOptions(input) {
      return convert(input, 'server');
    },
    verifyPeer(peer, input, operation) {
      const started = performance.now();
      const report = (status: string) => {
        try {
          telemetry?.recordHistogram('mtls.verification.duration_ms', performance.now() - started);
          telemetry?.addCounter('mtls.verification.completed.' + status, 1);
        } catch {
          /* Diagnostic failures cannot grant peer authorization. */
        }
      };
      return runtime
        .run(operation, async (call) =>
          instrumentOperation(
            telemetry,
            'mtls.verify_peer',
            {},
            async () => {
              try {
                const certificate = nativeCertificate(
                    snapshot(peer, Math.min(65536, settings.maxInputBytes)),
                  ),
                  requested = policy(input),
                  info = metadata(certificate);
                const now = Date.now();
                if (
                  certificate.ca ||
                  certificate.validFromDate.getTime() > now ||
                  certificate.validToDate.getTime() <= now
                )
                  throw failure();
                if (
                  requested.hostname !== undefined &&
                  (isIP(requested.hostname)
                    ? certificate.checkIP(requested.hostname)
                    : certificate.checkHost(requested.hostname, {
                        subject: 'never',
                        partialWildcards: false,
                        multiLabelWildcards: false,
                      })) === undefined
                )
                  throw failure();
                if (
                  !requested.allowedIdentities.some((identity) => {
                    if (isIP(identity)) return certificate.checkIP(identity) !== undefined;
                    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(identity))
                      return info.uriSans.includes(identity);
                    return (
                      certificate.checkHost(identity, {
                        subject: 'never',
                        partialWildcards: false,
                        multiLabelWildcards: false,
                      }) !== undefined
                    );
                  })
                )
                  throw failure();
                const verified = await settings.verify(
                  {
                    peerDer: Buffer.from(certificate.raw),
                    policy: requested,
                    now: new Date(now).toISOString(),
                  },
                  call.options,
                );
                call.check();
                const fields = data(verified, [
                  'uriSans',
                  'dnsSans',
                  'certificateFingerprintSha256',
                  'issuer',
                  'notAfter',
                ]);
                const dnsSans = strings(fields.dnsSans, 256, 0),
                  uriSans = strings(fields.uriSans, 256, 0);
                if (
                  fingerprint(fields.certificateFingerprintSha256) !== info.fingerprintSha256 ||
                  fields.issuer !== info.issuer ||
                  fields.notAfter !== info.notAfter ||
                  JSON.stringify([...dnsSans].sort()) !==
                    JSON.stringify([...info.dnsSans].sort()) ||
                  JSON.stringify([...uriSans].sort()) !==
                    JSON.stringify([...info.uriSans].sort()) ||
                  certificate.validToDate.getTime() <= Date.now()
                )
                  throw failure();
                const result: VerifiedPeerIdentity = Object.freeze({
                  dnsSans,
                  uriSans,
                  certificateFingerprintSha256: info.fingerprintSha256,
                  issuer: info.issuer,
                  notAfter: info.notAfter,
                });
                output(Buffer.byteLength(JSON.stringify(result)));
                return result;
              } catch {
                call.check();
                throw failure();
              }
            },
            () => {},
          ),
        )
        .then(
          (value) => {
            report('trusted');
            return value;
          },
          (error: unknown) => {
            report('error');
            throw error;
          },
        );
    },
    reloadCertificates(operation) {
      if (reloading) return Promise.reject(failure('EK_BACKEND_UNAVAILABLE'));
      reloading = true;
      return replace(operation).finally(() => {
        reloading = false;
      });
    },
  });
  return {
    service,
    async bootstrap(signal: AbortSignal) {
      runtime.bootstrap(signal);
      await replace({ signal });
    },
    close() {
      runtime.close();
      epoch = {};
      for (const material of active.values()) clear(material);
      active.clear();
    },
  };
}
