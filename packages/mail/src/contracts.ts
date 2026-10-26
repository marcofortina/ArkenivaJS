// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
/** Explicit bytes or a single-pass stream, never an attachment URL or local path. */
export interface BinaryInput {
  readonly bytes?: Uint8Array;
  readonly stream?: AsyncIterable<Uint8Array>;
}
/** A mailbox address and optional Unicode display name, validated before transport work. */
export interface MailRecipient {
  readonly address: string;
  readonly displayName?: string;
}
/** MIME metadata and a bounded explicit content source. */
export interface MailAttachment {
  readonly filename: string;
  readonly mimeType?: string;
  readonly content: BinaryInput;
}
/** Explicit message content or an allowlisted escaped HTML template. */
export interface MailMessage {
  readonly from: MailRecipient;
  readonly to: readonly MailRecipient[];
  readonly cc?: readonly MailRecipient[];
  readonly bcc?: readonly MailRecipient[];
  readonly subject: string;
  readonly text?: string;
  readonly html?: string;
  readonly attachments?: readonly MailAttachment[];
  readonly templateId?: string;
  readonly templateModel?: Readonly<Record<string, unknown>>;
}
/** SMTP acceptance is not recipient delivery confirmation. */
export interface MailReceipt {
  readonly transportId?: string;
  readonly accepted: readonly string[];
  readonly rejected: readonly string[];
  readonly outcome: 'accepted' | 'partial' | 'rejected';
  readonly sentAt: string;
}
/** Result of an actual TLS/authentication verification, never an import-time probe. */
export interface MailHealth {
  readonly available: boolean;
  readonly checkedAt: string;
}
/** More than one configured profile requires an explicit trusted catalog name. */
export interface MailOperationOptions extends OperationOptions {
  readonly transport?: string;
}
/** Opaque externally supplied credentials; values are never logged or persisted. */
export interface SecretValue {
  readonly bytes: Uint8Array;
  readonly keyVersion: string;
  readonly expiresAt?: string;
}
/** Trusted application injection, consulted before each credential-bearing operation. */
export interface SecretProvider {
  get(reference: string, options?: OperationOptions): Promise<SecretValue>;
}
/** Static SMTP destination, mandatory TLS, sender policy and finite attachment budget. */
export interface MailTransportProfile {
  readonly name: string;
  readonly host: string;
  readonly port: number;
  readonly requireTls: true;
  readonly usernameRef?: string;
  readonly passwordRef?: string;
  readonly allowedFromAddresses: readonly string[];
  readonly maxAttachmentBytes: number;
}
/** Explicit application-wide physical admission and byte/time ceilings. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Named transports and trusted templates are captured before application startup. */
export interface MailPluginSettings {
  readonly transports: readonly MailTransportProfile[];
  readonly secretProvider: SecretProvider;
  readonly templates?: Readonly<Record<string, string>>;
  readonly policy: BoundedRuntimePolicy;
}
/** No implicit mail retry, external file fetch, filesystem read or destination selection. */
export interface MailService {
  send(message: MailMessage, options?: MailOperationOptions): Promise<MailReceipt>;
  verifyTransport(options?: MailOperationOptions): Promise<MailHealth>;
  close(): Promise<void>;
}
