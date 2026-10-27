// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';
/** Application-owned integration with an external secret authority. */
export type SecretRefResolver = (reference: string, options?: OperationOptions) => Promise<string>;
/** AMQP native values, with bounded nesting and lossless signed 64-bit integers. */
export type AmqpFieldValue =
  | string
  | number
  | boolean
  | null
  | bigint
  | Date
  | Uint8Array
  | readonly AmqpFieldValue[]
  | AmqpFieldTable;
export interface AmqpFieldTable {
  readonly [key: string]: AmqpFieldValue;
}
export interface AmqpHeaders {
  readonly [key: string]: AmqpFieldValue;
}
/** Startup-owned exchange declaration and exact approved publisher routing keys. */
export interface AmqpExchangeSpec {
  readonly name: string;
  readonly type: 'direct' | 'topic' | 'fanout' | 'headers';
  readonly routingKeys: readonly string[];
  readonly durable?: boolean;
}
export interface AmqpQueueSpec {
  readonly name: string;
  readonly durable?: boolean;
}
export interface AmqpBindingSpec {
  readonly exchange: string;
  readonly queue: string;
  readonly routingKey: string;
  readonly arguments?: AmqpHeaders;
}
/** Trusted topology completes the catalog required by the normative routing policy. */
export interface AmqpTopology {
  readonly exchanges: readonly AmqpExchangeSpec[];
  readonly queues: readonly AmqpQueueSpec[];
  readonly bindings: readonly AmqpBindingSpec[];
}
export interface AmqpConnectionConfig {
  readonly name: string;
  readonly connectionUriSecretRef: string;
  readonly tlsCaFile?: string;
  readonly maxInFlightPublishes: number;
  readonly maxMessageBytes: number;
  readonly allowTopologyProvisioning?: boolean;
  readonly topology: AmqpTopology;
}
export interface AmqpPluginSettings {
  readonly connections: readonly AmqpConnectionConfig[];
  readonly resolveSecret: SecretRefResolver;
}
export interface AmqpPublishRequest {
  readonly connection: string;
  readonly exchange: string;
  readonly routingKey: string;
  readonly body: Uint8Array;
  readonly messageId?: string;
  readonly headers?: AmqpHeaders;
  readonly persistent?: boolean;
  readonly mandatory?: boolean;
}
/** A broker confirm proves neither routed delivery nor consumer/business commitment. */
export interface AmqpPublishReceipt {
  readonly messageId: string;
  readonly status: 'confirmed' | 'unroutable' | 'unknown';
  readonly confirmedAt?: string;
}
export interface AmqpConsumeSettings {
  readonly connection: string;
  readonly queue: string;
  readonly prefetch: number;
  readonly maxMessageBytes: number;
  readonly failurePolicy: 'reject' | 'requeue';
}
/** Independent delivery bytes and untrusted metadata; acknowledgments are locally submitted once. */
export interface AmqpDelivery {
  readonly messageId?: string;
  readonly exchange: string;
  readonly routingKey: string;
  readonly redelivered: boolean;
  readonly body: Uint8Array;
  readonly headers: AmqpHeaders;
  readonly verifiedTenant?: VerifiedTenantContext;
  ack(): Promise<void>;
  nack(options: Readonly<{ requeue: boolean }>): Promise<void>;
}
export interface MessagingSubscription {
  close(options?: OperationOptions): Promise<void>;
}
export interface AmqpService {
  publish(message: AmqpPublishRequest, options?: OperationOptions): Promise<AmqpPublishReceipt>;
  subscribe(
    config: AmqpConsumeSettings,
    handler: (message: AmqpDelivery) => Promise<void>,
    options?: OperationOptions,
  ): Promise<MessagingSubscription>;
  health(
    connection: string,
    options?: OperationOptions,
  ): Promise<Readonly<{ available: boolean; checkedAt: string }>>;
  native(connection: string): unknown;
  close(options?: OperationOptions): Promise<void>;
}
