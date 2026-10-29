// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type { StatementKey, StatementVerification } from './statements.js';
import { verifyFederationToken } from './statements.js';
import { failure, integer, url } from './validation.js';

export interface VerifiedTrustMark {
  readonly issuer: string;
  readonly subject: string;
  readonly type: string;
  readonly expiresAt: number;
}
interface Evidence {
  readonly token: string;
  readonly keys: readonly StatementKey[];
  readonly maxBytes: number;
  readonly expiresAt: number;
}
/** Owned signed mark evidence is separate from full chain and application identity authorization. */
export class TrustMarkVerifier {
  private readonly evidence = new WeakMap<VerifiedTrustMark, Evidence>();
  async verify(
    token: string,
    expected: StatementVerification & { readonly type: string },
    options?: OperationOptions,
  ): Promise<VerifiedTrustMark> {
    url(expected.type);
    const verified = await verifyFederationToken(
      token,
      { ...expected, type: 'trust-mark+jwt', requiredClaims: ['sub', 'exp'] },
      options,
    );
    const hasId = Object.hasOwn(verified.claims, 'id'),
      hasType = Object.hasOwn(verified.claims, 'trust_mark_type');
    // Italian id and final Federation trust_mark_type name the same bound public mark type.
    if (
      hasId === hasType ||
      (hasId ? verified.claims.id : verified.claims.trust_mark_type) !== expected.type
    )
      throw failure('EK_EID_FEDERATION');
    const mark = Object.freeze({
      issuer: expected.issuer,
      subject: expected.subject,
      type: expected.type,
      expiresAt: verified.expiresAt,
    });
    this.evidence.set(mark, {
      token,
      keys: Object.freeze(expected.keys.map((key) => Object.freeze({ ...key }))),
      maxBytes: expected.maxBytes,
      expiresAt: verified.expiresAt,
    });
    return mark;
  }
  private owned(mark: VerifiedTrustMark): Evidence {
    const proof = this.evidence.get(mark);
    if (!proof || Date.now() / 1000 >= proof.expiresAt) throw failure('EK_EID_FEDERATION');
    return proof;
  }
  /** Return the signed public mark for the authenticated issuer's status request. */
  request(mark: VerifiedTrustMark): string {
    return this.owned(mark).token;
  }
  async verifyStatus(
    token: string,
    mark: VerifiedTrustMark,
    maxAgeSeconds: number,
    options?: OperationOptions,
    track?: (task: Promise<unknown>) => void,
  ): Promise<number> {
    const proof = this.owned(mark);
    const verified = await verifyFederationToken(
      token,
      {
        issuer: mark.issuer,
        keys: proof.keys,
        maxBytes: proof.maxBytes,
        type: 'trust-mark-status-response+jwt',
        requiredClaims: ['trust_mark', 'status'],
        maxAgeSeconds: integer(maxAgeSeconds),
        ...(track ? { track } : {}),
      },
      options,
    );
    this.owned(mark);
    if (verified.claims.trust_mark !== proof.token || verified.claims.status !== 'active')
      throw failure('EK_EID_FEDERATION');
    return Math.min(
      verified.expiresAt,
      mark.expiresAt,
      (verified.claims.iat as number) + maxAgeSeconds,
    );
  }
}
