// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';

export type SecretRefResolver = (reference: string, options?: OperationOptions) => Promise<string>;
export interface KafkaClusterConfig {
  readonly name: string;
  readonly brokers: readonly string[];
  readonly clientId: string;
  /** Exact startup-owned topic catalog; publishing cannot create topics or extend this list. */
  readonly topics: readonly string[];
  readonly credentialSecretRef?: string;
  readonly tlsCaFile?: string;
  readonly maxBufferedMessages: number;
  readonly maxMessageBytes: number;
  readonly acks: 'all';
  readonly idempotentProducer: true;
}
export interface KafkaPluginSettings {
  readonly clusters: readonly KafkaClusterConfig[];
  readonly resolveSecret?: SecretRefResolver;
}
export type KafkaHeaderValue = string | Uint8Array | null | readonly (string | Uint8Array | null)[];
export type KafkaHeaders = Readonly<Record<string, KafkaHeaderValue>>;
export interface KafkaPublishRequest {
  readonly cluster: string;
  readonly topic: string;
  readonly value: Uint8Array | null;
  readonly key?: Uint8Array;
  readonly headers?: KafkaHeaders;
  readonly messageId?: string;
}
export interface KafkaPublicationReceipt {
  readonly topic: string;
  readonly partition: number;
  readonly offset: string;
  readonly status: 'acknowledged';
  /** Caller correlation echoed only after a broker acknowledgement; it is not an identity assertion. */
  readonly messageId?: string;
}
export interface KafkaConsumeSettings {
  readonly cluster: string;
  readonly topics: readonly string[];
  readonly groupId: string;
  readonly offsetReset: 'earliest' | 'latest';
  readonly maxInFlightPerPartition?: 1;
  readonly failurePolicy?: 'stop';
}
/** Wire metadata is untrusted and can never construct a verified tenant context. */
export interface KafkaRecord {
  readonly topic: string;
  readonly partition: number;
  readonly offset: string;
  readonly timestamp?: string;
  readonly key?: Uint8Array;
  readonly value: Uint8Array | null;
  readonly headers: KafkaHeaders;
  readonly verifiedTenant?: VerifiedTenantContext;
}
export interface MessagingSubscription {
  close(options?: OperationOptions): Promise<void>;
}
export interface KafkaService {
  publish(
    message: KafkaPublishRequest,
    options?: OperationOptions,
  ): Promise<KafkaPublicationReceipt>;
  consume(
    settings: KafkaConsumeSettings,
    handler: (message: KafkaRecord) => Promise<void>,
    options?: OperationOptions,
  ): Promise<MessagingSubscription>;
  health(
    cluster: string,
    options?: OperationOptions,
  ): Promise<Readonly<{ available: boolean; checkedAt: string }>>;
  native(cluster: string): unknown;
  close(options?: OperationOptions): Promise<void>;
}
