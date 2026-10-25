// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { generateSecret, verify } from 'otplib';
import { generateTOTP } from '@otplib/uri';
import { KitError } from '@arkenivajs/core';

const invalid = () => new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid factor proof' });
const storage = () =>
  new KitError({ code: 'EK_MFA_STORAGE', message: 'Factor material is unavailable' });
function seed(value: string): void {
  if (typeof value !== 'string' || !/^[A-Z2-7]{32}$/.test(value) || value.length !== 32)
    throw storage();
}
function label(value: string): void {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 128 ||
    value.trim() !== value ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid provisioning label' });
}

/** Private compatibility adapter; seed generation uses the upstream CSPRNG plugin. */
export function newTotpSecret(): string {
  try {
    const value = generateSecret({ length: 20 });
    seed(value);
    return value;
  } catch {
    throw storage();
  }
}

/** Secret-bearing URI; callers must never include the result in telemetry or errors. */
export function totpProvisioningUri(issuer: string, account: string, secret: string): string {
  label(issuer);
  label(account);
  seed(secret);
  try {
    return generateTOTP({
      issuer,
      label: account,
      secret,
      algorithm: 'sha1',
      digits: 6,
      period: 30,
    });
  } catch {
    throw storage();
  }
}

/**
 * Return the exact upstream-verified timestep; this is not persisted acceptance or MFA evidence.
 * The lifecycle must perform generation-bound durable CAS before returning any success proof.
 */
export async function verifyTotpStep(
  secret: string,
  code: string,
  nowMs: number,
  driftSteps: 0 | 1,
): Promise<number | null> {
  if (typeof code !== 'string' || code.length !== 6 || !/^[0-9]{6}$/.test(code)) throw invalid();
  seed(secret);
  if (
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0 ||
    nowMs > 8640000000000000 ||
    (driftSteps !== 0 && driftSteps !== 1)
  )
    throw new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid factor clock or drift policy' });
  try {
    const result = await verify({
      strategy: 'totp',
      secret,
      token: code,
      algorithm: 'sha1',
      digits: 6,
      period: 30,
      epoch: Math.floor(nowMs / 1000),
      epochTolerance: driftSteps * 30,
    });
    if (!result.valid) return null;
    if (
      !('timeStep' in result) ||
      !Number.isSafeInteger(result.timeStep) ||
      result.timeStep < 0 ||
      Math.abs(result.timeStep - Math.floor(nowMs / 30000)) > driftSteps
    )
      throw storage();
    return result.timeStep;
  } catch {
    throw storage();
  }
}
