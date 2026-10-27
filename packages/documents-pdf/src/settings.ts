// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute } from 'node:path';
import type { DocumentsPdfPluginSettings, PdfLimits, PdfTextSpec } from './contracts.js';
import { array, fields, integer, text, failure } from './validation.js';

export const builtins = new Set([
  'Courier',
  'Courier-Bold',
  'Courier-Oblique',
  'Courier-BoldOblique',
  'Helvetica',
  'Helvetica-Bold',
  'Helvetica-Oblique',
  'Helvetica-BoldOblique',
  'Times-Roman',
  'Times-Bold',
  'Times-Italic',
  'Times-BoldItalic',
  'Symbol',
  'ZapfDingbats',
]);
export const limitNames = ['maxBytes', 'maxPages', 'maxTextItems', 'maxDecodeMs'] as const;
export function limits(input: PdfLimits = {}) {
  const value = fields(input, limitNames);
  return Object.freeze({
    maxBytes: integer(value.maxBytes ?? 16 * 1024 * 1024, 128 * 1024 * 1024),
    maxPages: integer(value.maxPages ?? 100, 1000),
    maxTextItems: integer(value.maxTextItems ?? 100000, 1000000),
    maxDecodeMs: integer(value.maxDecodeMs ?? 5000, 120000),
  });
}
export type Limits = ReturnType<typeof limits>;
export function capture(input: DocumentsPdfPluginSettings) {
  try {
    const data = fields(input, ['defaults', 'fontAllowlist', 'policy']),
      policy = fields(data.policy, [
        'maxConcurrent',
        'timeoutMs',
        'maxInputBytes',
        'maxOutputBytes',
      ]);
    if (data.defaults === undefined) throw failure();
    const fonts = array(data.fontAllowlist, 32).map((value) => {
      const name = text(value, 4096);
      if (!builtins.has(name) && (!isAbsolute(name) || name.includes('\n') || name.includes('\r')))
        throw failure();
      return name;
    });
    if (!fonts.length || new Set(fonts).size !== fonts.length) throw failure();
    return Object.freeze({
      defaults: limits(data.defaults as PdfLimits),
      fonts: Object.freeze(fonts),
      maxConcurrent: integer(policy.maxConcurrent, 4),
      timeoutMs: integer(policy.timeoutMs, 120000),
      maxInputBytes: integer(policy.maxInputBytes ?? 16 * 1024 * 1024, 128 * 1024 * 1024),
      maxOutputBytes: integer(policy.maxOutputBytes ?? 16 * 1024 * 1024, 128 * 1024 * 1024),
    });
  } catch {
    throw failure('EK_CONFIG_INVALID');
  }
}
export type Settings = ReturnType<typeof capture>;
export function spec(
  input: PdfTextSpec,
  settings: Settings,
  policy: Limits,
): Readonly<Required<PdfTextSpec>> {
  const value = fields(input, [
      'page',
      'text',
      'x',
      'y',
      'font',
      'size',
      'colorHex',
      'rotationDegrees',
    ]),
    content = text(value.text, Math.min(policy.maxBytes, 1048576), true),
    font = text(value.font, 4096),
    color = text(value.colorHex, 7);
  if (
    !settings.fonts.includes(font) ||
    !/^#[0-9A-Fa-f]{6}$/.test(color) ||
    [...content].some((c) => c.charCodeAt(0) < 32 && ![9, 10, 13].includes(c.charCodeAt(0)))
  )
    throw failure();
  const number = (value: unknown, maximum: number, minimum: number) => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum)
      throw failure();
    return value;
  };
  return Object.freeze({
    page: integer(value.page, policy.maxPages),
    text: content,
    x: number(value.x, 1000000, -1000000),
    y: number(value.y, 1000000, -1000000),
    font,
    size: number(value.size, 1000, 0.01),
    colorHex: color.toUpperCase(),
    rotationDegrees:
      number(value.rotationDegrees ?? 0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER) % 360,
  });
}
