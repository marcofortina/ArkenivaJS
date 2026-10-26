// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
import type { SecretProvider, BoundedRuntimePolicy } from '@arkenivajs/security-crypto';
import type {
  SecurityStoreSettings,
  TrustedSecurityAuthority,
  IdentitySubject,
} from '@arkenivajs/security-sessions';

export type {
  SecretProvider,
  SecretValue,
  BoundedRuntimePolicy,
} from '@arkenivajs/security-crypto';
export type {
  SecurityStoreSettings,
  SecurityTransactionalStore,
  TrustedSecurityAuthority,
  IdentitySubject,
} from '@arkenivajs/security-sessions';

/** Metadata is covered by the signature; its tenant is independently resolved by the authority. */
export interface WebhookContext {
  readonly destinationId: string;
  readonly eventId: string;
  readonly timestamp: string;
  readonly nonce: string;
  readonly keyId: string;
}
/** A canonical base64url HMAC-SHA256 value; timestamps use canonical UTC ISO instants. */
export interface WebhookSignature {
  readonly algorithm: 'hmac-sha256';
  readonly keyId: string;
  readonly timestamp: string;
  readonly nonce: string;
  readonly signature: string;
}
/** Cryptographic verification is distinct from application payload validation and transport identity. */
export interface VerifiedWebhook {
  readonly eventId: string;
  readonly destinationId: string;
  readonly verifiedAt: string;
}
export interface WebhookEvent {
  readonly type: string;
  readonly id: string;
  readonly payload: unknown;
}
/** No durable outbox is implied by a receiver's HTTP acknowledgement. */
export interface WebhookDelivery {
  readonly destinationId: string;
  readonly eventId: string;
  readonly status: 'accepted' | 'rejected' | 'unknown';
  readonly attemptCount: number;
}
/** Explicit retained verification material references; raw HMAC keys remain in the secret provider. */
export interface WebhookVerificationKey {
  readonly keyId: string;
  readonly hmacKeyRef: string;
  readonly expiresAt: string;
}
export interface WebhookDestinationProfile {
  readonly name: string;
  readonly origin: string;
  readonly hmacKeyRef: string;
  readonly allowedCidrs: readonly string[];
  readonly maxRetries: number;
  readonly timeoutMs: number;
  /** Required to enable retries; the destination contract must actually guarantee event-ID idempotency. */
  readonly idempotent?: boolean;
  /** A bounded rotation window cannot be inferred from the current provider version. */
  readonly verificationKeys?: readonly WebhookVerificationKey[];
}
/** Trusted destination/event hints are supplied by the adapter; identity still requires runtime proof. */
export type WebhookAuthorizationContext = Parameters<TrustedSecurityAuthority['require']>[2] &
  Readonly<{
    destinationId: string;
    eventId: string;
    keyId?: string;
  }>;
export interface WebhookAuthority extends TrustedSecurityAuthority {
  require(
    action: string,
    subject: IdentitySubject | undefined,
    context: WebhookAuthorizationContext,
    options?: OperationOptions,
  ): Promise<IdentitySubject>;
}
export interface WebhooksPluginSettings {
  readonly destinations: readonly WebhookDestinationProfile[];
  readonly secretProvider: SecretProvider;
  readonly nonceStore: SecurityStoreSettings;
  readonly authority: WebhookAuthority;
  readonly policy: BoundedRuntimePolicy;
}
export interface WebhookService {
  sign(
    rawBody: Uint8Array,
    keyRef: string,
    context: WebhookContext,
    options?: OperationOptions,
  ): Promise<WebhookSignature>;
  verify(
    rawBody: Uint8Array,
    signature: WebhookSignature,
    context: WebhookContext,
    options?: OperationOptions,
  ): Promise<VerifiedWebhook>;
  send(
    destinationId: string,
    event: WebhookEvent,
    options?: OperationOptions,
  ): Promise<WebhookDelivery>;
  parseEvent(rawBody: Uint8Array): WebhookEvent;
}
