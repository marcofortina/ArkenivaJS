// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import Mustache from 'mustache';
import sanitizeHtml from 'sanitize-html';
import { fields, array, text, address, name, bytes, failure } from './settings.js';
import type { Captured } from './settings.js';
import type { BinaryInput, MailMessage, MailTransportProfile } from './contracts.js';

export interface Message {
  readonly from: Readonly<{ address: string; name: string }>;
  readonly to: readonly Readonly<{ address: string; name: string }>[];
  readonly cc: readonly Readonly<{ address: string; name: string }>[];
  readonly bcc: readonly Readonly<{ address: string; name: string }>[];
  readonly subject: string;
  readonly text: string | undefined;
  readonly html: string | undefined;
  readonly attachments: readonly Readonly<{
    filename: string;
    contentType: string;
    source: BinaryInput;
  }>[];
  readonly metadataBytes: number;
}
function recipient(input: unknown) {
  const value = fields(input, ['address', 'displayName']);
  return Object.freeze({
    address: address(value.address),
    name: value.displayName === undefined ? '' : text(value.displayName, 256, true, true),
  });
}
function model(input: unknown): Readonly<Record<string, unknown>> {
  let nodes = 0,
    total = 0;
  const ancestors = new WeakSet<object>();
  const visit = (value: unknown, depth: number): unknown => {
    if (++nodes > 4096 || depth > 16) throw failure('EK_MAIL_CONFIG');
    if (typeof value === 'string') {
      const result = text(value, 262144, false, true);
      total += Buffer.byteLength(result);
      if (total > 262144) throw failure('EK_MAIL_CONFIG');
      return result;
    }
    if (
      value === null ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value))
    )
      return value;
    if (!value || typeof value !== 'object' || ancestors.has(value))
      throw failure('EK_MAIL_CONFIG');
    ancestors.add(value);
    try {
      if (Array.isArray(value))
        return Object.freeze(array(value, 1000).map((item) => visit(item, depth + 1)));
      const record = fields(value, Reflect.ownKeys(value)),
        result: Record<string, unknown> = Object.create(null);
      if (Reflect.ownKeys(record).length > 256) throw failure('EK_MAIL_CONFIG');
      for (const key of Reflect.ownKeys(record)) {
        if (typeof key !== 'string' || ['__proto__', 'prototype', 'constructor'].includes(key))
          throw failure('EK_MAIL_CONFIG');
        total += Buffer.byteLength(text(key, 128, true));
        if (total > 262144) throw failure('EK_MAIL_CONFIG');
        result[key] = visit(record[key], depth + 1);
      }
      return Object.freeze(result);
    } finally {
      ancestors.delete(value);
    }
  };
  const result = visit(input, 0);
  if (!result || typeof result !== 'object' || Array.isArray(result))
    throw failure('EK_MAIL_CONFIG');
  return result as Readonly<Record<string, unknown>>;
}
function lookup(view: unknown, key: string): string | number | boolean | null | undefined {
  let result: unknown = view;
  for (const part of key.split('.')) {
    if (!result || typeof result !== 'object' || !Object.hasOwn(result, part)) return undefined;
    result = Object.getOwnPropertyDescriptor(result, part)?.value;
  }
  if (
    result === null ||
    result === undefined ||
    ['string', 'number', 'boolean'].includes(typeof result)
  )
    return result as string | number | boolean | null | undefined;
  throw failure('EK_MAIL_CONFIG');
}
/** The upstream writer escapes scalar bindings; no lambda, raw HTML, partial or loop execution. */
export function templates(settings: Captured) {
  const writer = new Mustache.Writer(),
    catalog = new Map<string, string[][]>();
  for (const [id, template] of settings.templates) {
    let tokens: string[][];
    try {
      tokens = writer.parse(template);
    } catch {
      throw failure('EK_MAIL_CONFIG');
    }
    if (tokens.length > 1024 || tokens.some((token) => !['text', 'name', '!'].includes(token[0]!)))
      throw failure('EK_MAIL_CONFIG');
    for (const token of tokens)
      if (
        token[0] === 'name' &&
        (!token[1] ||
          token[1].length > 128 ||
          token[1]
            .split('.')
            .some((part) => !part || ['__proto__', 'prototype', 'constructor'].includes(part)))
      )
        throw failure('EK_MAIL_CONFIG');
    catalog.set(id, tokens);
  }
  return (id: unknown, input: unknown): string => {
    const tokens = catalog.get(name(id));
    if (!tokens) throw failure('EK_MAIL_CONFIG');
    const data = model(input === undefined ? {} : input),
      maximum = Math.min(1048576, settings.maxInputBytes);
    let length = 0;
    for (const token of tokens) {
      const value =
        token[0] === 'text'
          ? token[1]!
          : token[0] === 'name'
            ? Mustache.escape(String(lookup(data, token[1]!) ?? ''))
            : '';
      length += Buffer.byteLength(value);
      if (length > maximum) throw failure('EK_MAIL_CONFIG');
    }
    class OwnContext extends Mustache.Context {
      override lookup(key: string): unknown {
        return lookup(data, key);
      }
    }
    return writer.renderTokens(tokens, new OwnContext(data), undefined, undefined, {
      escape: Mustache.escape,
    });
  };
}
/** Snapshot exactly the public message contract before credentials, attachments or sockets are used. */
export function message(
  input: MailMessage,
  profile: MailTransportProfile,
  settings: Captured,
  render: ReturnType<typeof templates>,
): Message {
  try {
    const value = fields(input, [
        'from',
        'to',
        'cc',
        'bcc',
        'subject',
        'text',
        'html',
        'attachments',
        'templateId',
        'templateModel',
      ]),
      from = recipient(value.from),
      to = Object.freeze(array(value.to, 100).map(recipient)),
      cc = Object.freeze(array(value.cc === undefined ? [] : value.cc, 100).map(recipient)),
      bcc = Object.freeze(array(value.bcc === undefined ? [] : value.bcc, 100).map(recipient));
    if (!profile.allowedFromAddresses.includes(from.address)) throw failure('EK_MAIL_REJECTED');
    if (
      to.length + cc.length + bcc.length < 1 ||
      to.length + cc.length + bcc.length > 100 ||
      (value.templateId === undefined && value.templateModel !== undefined) ||
      (value.templateId !== undefined && value.html !== undefined)
    )
      throw failure('EK_MAIL_CONFIG');
    const subject = text(value.subject, 998, true),
      plain =
        value.text === undefined
          ? undefined
          : text(value.text, Math.min(settings.maxInputBytes, 1048576), false, true),
      rawHtml =
        value.templateId !== undefined
          ? render(value.templateId, value.templateModel)
          : value.html === undefined
            ? undefined
            : text(value.html, Math.min(settings.maxInputBytes, 1048576), false, true),
      html =
        rawHtml === undefined
          ? undefined
          : sanitizeHtml(rawHtml, {
              allowedSchemes: ['https', 'http', 'mailto'],
              disallowedTagsMode: 'discard',
              allowProtocolRelative: false,
            });
    if (plain === undefined && html === undefined) throw failure('EK_MAIL_CONFIG');
    const attachments = Object.freeze(
      array(value.attachments === undefined ? [] : value.attachments, 32).map((item) => {
        const attachment = fields(item, ['filename', 'mimeType', 'content']),
          content = fields(attachment.content, ['bytes', 'stream']),
          filename = text(attachment.filename, 255, true);
        if (
          /[\\/]/.test(filename) ||
          filename === '.' ||
          filename === '..' ||
          (content.bytes === undefined) === (content.stream === undefined)
        )
          throw failure('EK_MAIL_CONFIG');
        const contentType =
          attachment.mimeType === undefined
            ? 'application/octet-stream'
            : text(attachment.mimeType, 127, true);
        if (!/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(contentType))
          throw failure('EK_MAIL_CONFIG');
        let source: BinaryInput;
        if (content.bytes !== undefined)
          source = Object.freeze({
            bytes: bytes(
              content.bytes,
              Math.min(profile.maxAttachmentBytes, settings.maxInputBytes),
            ),
          });
        else {
          const stream = content.stream as AsyncIterable<Uint8Array>;
          if (
            !stream ||
            typeof stream !== 'object' ||
            typeof stream[Symbol.asyncIterator] !== 'function'
          )
            throw failure('EK_MAIL_CONFIG');
          source = Object.freeze({ stream });
        }
        return Object.freeze({ filename, contentType, source });
      }),
    );
    const metadataBytes =
        Buffer.byteLength(subject) +
        Buffer.byteLength(plain ?? '') +
        Buffer.byteLength(html ?? '') +
        [from, ...to, ...cc, ...bcc].reduce(
          (sum, entry) => sum + Buffer.byteLength(entry.address) + Buffer.byteLength(entry.name),
          0,
        ) +
        attachments.reduce(
          (sum, attachment) =>
            sum +
            Buffer.byteLength(attachment.filename) +
            Buffer.byteLength(attachment.contentType),
          0,
        ),
      knownBytes = attachments.reduce(
        (sum, attachment) => sum + (attachment.source.bytes?.byteLength ?? 0),
        0,
      );
    if (
      knownBytes > profile.maxAttachmentBytes ||
      metadataBytes + knownBytes > settings.maxInputBytes
    )
      throw failure('EK_MAIL_CONFIG');
    return Object.freeze({
      from,
      to,
      cc,
      bcc,
      subject,
      text: plain,
      html,
      attachments,
      metadataBytes,
    });
  } catch (cause) {
    let rejected = false;
    try {
      rejected = Object.getOwnPropertyDescriptor(cause, 'code')?.value === 'EK_MAIL_REJECTED';
    } catch {
      /* Do not inspect provider-controlled exception accessors. */
    }
    throw failure(rejected ? 'EK_MAIL_REJECTED' : 'EK_MAIL_CONFIG');
  }
}
