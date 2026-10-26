// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import type { PasswordHash, PasswordPolicy, PasswordVerification } from './contracts.js';
import { data, failure, plaintext, passwordPolicy } from './validation.js';

export interface KdfCall {
  check(): void;
  step<T>(code: 'EK_PASSWORD_KDF', work: () => Promise<T>): Promise<T>;
}

/** Validate native allocation parameters before allowing an untrusted PHC string near the binding. */
export function inspectHash(input: unknown) {
  const stored = data(input, ['scheme', 'phc']);
  if (stored.scheme !== 'argon2id' || typeof stored.phc !== 'string' || stored.phc.length > 1024)
    throw failure('EK_PASSWORD_INVALID');
  const match = /^\$argon2id\$v=(16|19)\$([^$]+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(
    stored.phc,
  );
  if (!match) return null;
  const costs: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const part of match[2]!.split(',')) {
    const field = /^([mpt])=([1-9][0-9]{0,8})$/.exec(part);
    if (!field || costs[field[1]!] !== undefined) return null;
    costs[field[1]!] = Number(field[2]);
  }
  const { m, p, t } = costs;
  if (
    m === undefined ||
    p === undefined ||
    t === undefined ||
    p > 16 ||
    t > 10 ||
    m > 262144 ||
    m < 8 * p
  )
    return null;
  const salt = Buffer.from(match[3]!, 'base64'),
    hash = Buffer.from(match[4]!, 'base64');
  if (
    salt.length < 8 ||
    salt.length > 64 ||
    hash.length < 16 ||
    hash.length > 64 ||
    salt.toString('base64').replace(/=+$/, '') !== match[3] ||
    hash.toString('base64').replace(/=+$/, '') !== match[4]
  )
    return null;
  return Object.freeze({ phc: stored.phc, memoryCost: m, parallelism: p, timeCost: t });
}

/** Per-application native work has two permits and no queue, retained until the worker actually settles. */
export function createKdf(policy: Readonly<Required<PasswordPolicy>>) {
  let active = 0,
    closed = false,
    dummy: PasswordHash | undefined;
  const options = (value: Readonly<Required<PasswordPolicy>>): argon2.HashOptions => ({
    type: argon2.argon2id,
    version: 0x13,
    hashLength: 32,
    memoryCost: value.memoryCostKiB,
    timeCost: value.timeCost,
    parallelism: value.parallelism,
  });
  const check = () => {
    if (closed) throw failure('EK_RESOURCE_CLOSED');
  };
  async function native<T>(call: KdfCall, work: () => Promise<T>): Promise<T> {
    check();
    call.check();
    if (active >= 2) throw failure('EK_BACKEND_UNAVAILABLE');
    active++;
    try {
      return await call.step('EK_PASSWORD_KDF', async () => {
        const result = await work();
        check();
        return result;
      });
    } finally {
      active--;
    }
  }
  const hash = async (
    plain: string,
    input: PasswordPolicy | undefined,
    call: KdfCall,
  ): Promise<PasswordHash> => {
    const approved = passwordPolicy(input, policy),
      bytes = plaintext(plain, approved.minLength);
    try {
      return await native(call, async () => {
        const salt = randomBytes(16);
        try {
          return Object.freeze({
            phc: await argon2.hash(bytes, { ...options(approved), salt }),
            scheme: 'argon2id',
          });
        } finally {
          salt.fill(0);
        }
      });
    } finally {
      bytes.fill(0);
    }
  };
  const needsRehash = (stored: PasswordHash) => {
    check();
    const parsed = inspectHash(stored);
    return parsed === null || argon2.needsRehash(parsed.phc, options(policy));
  };
  return {
    hash,
    needsRehash,
    async bootstrap(call: KdfCall) {
      const random = randomBytes(128);
      try {
        dummy = await hash(random.toString('base64url'), policy, call);
      } finally {
        random.fill(0);
      }
    },
    async verify(
      plain: string,
      stored: PasswordHash,
      call: KdfCall,
    ): Promise<PasswordVerification> {
      const parsed = inspectHash(stored);
      if (!dummy) throw failure('EK_RESOURCE_CLOSED');
      const bytes = plaintext(plain);
      try {
        return await native(call, async () => {
          const valid = await argon2.verify(parsed?.phc ?? dummy!.phc, bytes);
          return Object.freeze({
            valid: !!parsed && valid,
            rehashRecommended: !!parsed && valid && argon2.needsRehash(parsed.phc, options(policy)),
          });
        });
      } finally {
        bytes.fill(0);
      }
    },
    close() {
      closed = true;
      dummy = undefined;
    },
  };
}
