// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Worker } from 'node:worker_threads';
import type { FederationProfileV1 } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { verifySamlMetadataSignature } from './saml-metadata-signature.js';
import type { verifySamlRegistryDocument } from './saml-registry-document.js';
import { captureProfile } from './settings.js';
import { failure } from './validation.js';

type SignatureEvidence = ReturnType<typeof verifySamlMetadataSignature>;
type RegistryEvidence = ReturnType<typeof verifySamlRegistryDocument>;
type VerificationMessage =
  { ok: true; result: SignatureEvidence | RegistryEvidence } | { ok: false };

/** The returned promise settles only after the actual native worker has terminated. */
async function native(
  xml: string,
  profile: FederationProfileV1,
  role: 'idp' | 'sp',
  signal: AbortSignal,
  status?: string,
): Promise<SignatureEvidence | RegistryEvidence> {
  if (signal.aborted) throw failure('EK_ABORTED');
  const worker = new Worker(new URL('./saml-signature-worker.js', import.meta.url), {
    workerData: { xml, profile, role, ...(status === undefined ? {} : { status }) },
    env: { NODE_ENV: 'production' },
    stdout: true,
    stderr: true,
    resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
  });
  worker.stdout.resume();
  worker.stderr.resume();
  return new Promise<SignatureEvidence | RegistryEvidence>((resolve, reject) => {
    let settled = false,
      exited!: () => void;
    const physicalExit = new Promise<void>((resolve) => {
      exited = resolve;
    });
    const finish = async (result?: SignatureEvidence, error?: unknown) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      try {
        await worker.terminate();
      } catch {
        // A rejected termination request does not prove that native work has stopped.
        await physicalExit;
        reject(failure('EK_BACKEND_UNAVAILABLE'));
        return;
      }
      if (error !== undefined) reject(error);
      else if (result) resolve(result);
      else reject(failure('EK_EID_FEDERATION'));
    };
    const abort = () => {
      void finish(undefined, failure('EK_ABORTED'));
    };
    worker.once('message', (value: VerificationMessage) => {
      void finish(value.ok ? value.result : undefined);
    });
    worker.once('error', () => {
      void finish(undefined, failure('EK_EID_FEDERATION'));
    });
    worker.once('exit', () => {
      exited();
      if (!settled) void finish(undefined, failure('EK_EID_FEDERATION'));
    });
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
}

/** Owned signature evidence only; authoritative current participation remains an independent gate. */
export class FederationSamlSignatures {
  private readonly profile: FederationProfileV1;
  readonly #owned = new WeakSet<SignatureEvidence>();
  readonly #registrations = new WeakSet<RegistryEvidence>();
  constructor(profile: FederationProfileV1) {
    this.profile = captureProfile(profile, 'spid');
    if (this.profile.protocol !== 'saml2') throw failure('EK_EID_PROFILE');
  }
  async verify(call: FederationCall, xml: string, role: 'idp' | 'sp'): Promise<SignatureEvidence> {
    call.check();
    if (!['idp', 'sp'].includes(role)) throw failure('EK_EID_PROFILE');
    if (
      typeof xml !== 'string' ||
      !xml ||
      Buffer.byteLength(xml) > Math.min(this.profile.metadata.maxBytes, 65536) ||
      Buffer.from(xml).toString('utf8') !== xml
    )
      throw failure('EK_EID_FEDERATION');
    const verified = await call.step((options) => native(xml, this.profile, role, options.signal)),
      evidence = Object.freeze(verified);
    this.#owned.add(evidence);
    this.result(evidence);
    return evidence;
  }
  async verifyRegistry(
    call: FederationCall,
    xml: string,
    status: string,
    role: 'idp' | 'sp',
  ): Promise<RegistryEvidence> {
    call.check();
    if (!['idp', 'sp'].includes(role)) throw failure('EK_EID_PROFILE');
    if (
      typeof xml !== 'string' ||
      !xml ||
      typeof status !== 'string' ||
      !status ||
      Buffer.byteLength(xml) + Buffer.byteLength(status) >
        Math.min(this.profile.metadata.maxBytes, 65536) ||
      Buffer.from(xml).toString('utf8') !== xml ||
      Buffer.from(status).toString('utf8') !== status
    )
      throw failure('EK_EID_FEDERATION');
    const verified = (await call.step((options) =>
        native(xml, this.profile, role, options.signal, status),
      )) as RegistryEvidence,
      evidence = Object.freeze({
        ...verified,
        certificates: Object.freeze([...verified.certificates]),
      });
    this.#owned.add(evidence);
    this.#registrations.add(evidence);
    this.registryResult(evidence);
    return evidence;
  }
  registryResult(input: unknown): RegistryEvidence {
    if (!this.#registrations.has(input as RegistryEvidence)) throw failure('EK_EID_FEDERATION');
    const evidence = this.result(input) as RegistryEvidence;
    if (Date.parse(evidence.expiresAt) <= Date.now()) throw failure('EK_EID_FEDERATION');
    return evidence;
  }
  /** Structural objects, copied results and results from another owner grant no signature authority. */
  result(input: unknown): SignatureEvidence {
    if (!this.#owned.has(input as SignatureEvidence)) throw failure('EK_EID_FEDERATION');
    const evidence = input as SignatureEvidence;
    if (
      Date.parse(evidence.trustAnchorExpiresAt) <= Date.now() ||
      (evidence.validUntil !== undefined && Date.parse(evidence.validUntil) <= Date.now())
    )
      throw failure('EK_EID_FEDERATION');
    return evidence;
  }
}
