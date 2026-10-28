// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { IncomingHttpHeaders } from 'node:http';
import { failure } from './policy.js';

const requestHeaders = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'content-type',
  'content-encoding',
  'content-length',
  'range',
  'if-match',
  'if-none-match',
  'if-modified-since',
  'if-unmodified-since',
  'if-range',
]);
const responseHeaders = new Set([
  'content-type',
  'content-encoding',
  'content-length',
  'content-language',
  'content-disposition',
  'etag',
  'last-modified',
  'accept-ranges',
  'content-range',
  'retry-after',
  'vary',
]);
/** Forward ordinary content metadata only; identity and hop headers never survive a denylist gap. */
export function contentHeaders(
  input: IncomingHttpHeaders,
  side: 'request' | 'response',
): IncomingHttpHeaders {
  const output: IncomingHttpHeaders = Object.create(null),
    allowed = side === 'request' ? requestHeaders : responseHeaders;
  const connection =
    typeof input.connection === 'string'
      ? new Set(
          input.connection
            .toLowerCase()
            .split(',')
            .map((v) => v.trim()),
        )
      : new Set<string>();
  for (const [name, value] of Object.entries(input))
    if (allowed.has(name) && !connection.has(name)) output[name] = value;
  if (side === 'response') output['cache-control'] = 'no-store';
  return output;
}
/** Reject alternate path normalization before the official proxy computes its static rewrite. */
export function validateTarget(raw: string): void {
  if (
    raw.length > 8192 ||
    !raw.startsWith('/') ||
    raw.startsWith('//') ||
    [...raw].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw failure('EK_PROXY_POLICY');
  const path = raw.split('?', 1)[0]!;
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    throw failure('EK_PROXY_POLICY');
  }
  if (
    path.includes('%25') ||
    decoded.includes('\\') ||
    decoded.includes('//') ||
    decoded.split('/').some((segment) => segment === '.' || segment === '..') ||
    [...decoded].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    throw failure('EK_PROXY_POLICY');
}
