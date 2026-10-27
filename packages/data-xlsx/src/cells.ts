// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { XlsxCell, XlsxCellStyle, XlsxCellValue } from './contracts.js';
import type { Options } from './settings.js';
import { array, fields, text, failure } from './validation.js';

const styleNames = [
  'numberFormat',
  'fontName',
  'fontSize',
  'bold',
  'italic',
  'fontColorHex',
  'fillColorHex',
  'horizontalAlignment',
] as const;
/** Cell strings remain strings even when spreadsheet applications recognize their first character. */
export function primitive(input: unknown): string | number | boolean | null {
  if (input === null || typeof input === 'boolean') return input;
  if (typeof input === 'number') {
    if (!Number.isFinite(input)) throw failure();
    return input;
  }
  const value = text(input, 131068, true);
  if (value.length > 32767) throw failure('EK_XLSX_LIMIT');
  if (
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 && ![9, 10, 13].includes(code);
    })
  )
    throw failure();
  return value;
}
export function color(input: unknown): string {
  const value = text(input, 7);
  if (!/^#[0-9a-fA-F]{6}$/.test(value)) throw failure();
  return value.toUpperCase();
}
export function style(input: unknown): XlsxCellStyle {
  const value = fields(input, styleNames),
    result: Record<string, unknown> = Object.create(null);
  for (const name of ['bold', 'italic'] as const)
    if (value[name] !== undefined) {
      if (typeof value[name] !== 'boolean') throw failure();
      result[name] = value[name];
    }
  if (value.numberFormat !== undefined) {
    const format = text(value.numberFormat, 128);
    if (
      /[^0-9a-zA-Z@#?,.% +\-/:()"'_[\]\\;$€£¥]/u.test(format) ||
      /(?:javascript|https?|file|script|hyperlink|webservice|dde|cmd|powershell)/i.test(format)
    )
      throw failure('EK_XLSX_UNSUPPORTED');
    let quoted = false,
      bracket = false;
    for (let index = 0; index < format.length; index++) {
      const character = format[index];
      if (character === '\\') {
        if (++index >= format.length) throw failure();
        continue;
      }
      if (character === '"') quoted = !quoted;
      else if (!quoted && character === '[') {
        if (bracket) throw failure();
        bracket = true;
      } else if (!quoted && character === ']') {
        if (!bracket) throw failure();
        bracket = false;
      }
    }
    if (quoted || bracket) throw failure();
    result.numberFormat = format;
  }
  if (value.fontName !== undefined) {
    const name = text(value.fontName, 128);
    if (
      /[<>"'&{}]/.test(name) ||
      [...name].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
    )
      throw failure();
    result.fontName = name;
  }
  if (value.fontSize !== undefined) {
    if (
      typeof value.fontSize !== 'number' ||
      !Number.isFinite(value.fontSize) ||
      value.fontSize < 1 ||
      value.fontSize > 409
    )
      throw failure();
    result.fontSize = value.fontSize;
  }
  for (const name of ['fontColorHex', 'fillColorHex'] as const)
    if (value[name] !== undefined) result[name] = color(value[name]);
  if (value.horizontalAlignment !== undefined) {
    if (!['left', 'center', 'right'].includes(value.horizontalAlignment as string)) throw failure();
    result.horizontalAlignment = value.horizontalAlignment;
  }
  return Object.freeze(result) as XlsxCellStyle;
}
export function formula(input: unknown): string {
  const value = text(input, 8192);
  primitive(value);
  // Formulas are never evaluated. External references and dynamic external-link functions are unsupported.
  if (
    value.startsWith('=') ||
    /[[\]|]/.test(value) ||
    /(?:https?|ftp|file):|\\\\|\b(?:_xlfn\.)?(?:HYPERLINK|WEBSERVICE|RTD|DDE|CALL|REGISTER\.ID|IMAGE|INDIRECT|STOCKHISTORY)\s*\(/i.test(
      value,
    )
  )
    throw failure('EK_XLSX_UNSUPPORTED');
  return value;
}
export function cell(input: unknown, options: Options): XlsxCell {
  if (input instanceof Date) {
    const millis = Date.prototype.getTime.call(input);
    if (!Number.isFinite(millis)) throw failure();
    return new Date(millis);
  }
  if (input === null || typeof input !== 'object') return primitive(input);
  const value = fields(input, ['value', 'style', 'formula', 'cachedValue']);
  if (Object.hasOwn(value, 'value')) {
    if (
      Object.hasOwn(value, 'formula') ||
      Object.hasOwn(value, 'cachedValue') ||
      (value.value !== null &&
        typeof value.value === 'object' &&
        !(value.value instanceof Date) &&
        Object.hasOwn(value.value, 'value'))
    )
      throw failure();
    const normalized = cell(value.value, options) as XlsxCellValue;
    return Object.freeze({
      value: normalized,
      ...(value.style === undefined ? {} : { style: style(value.style) }),
    });
  }
  if (Object.hasOwn(value, 'style') || !Object.hasOwn(value, 'formula')) throw failure();
  if (options.formulaPolicy === 'reject') throw failure('EK_XLSX_UNSUPPORTED');
  const expression = formula(value.formula),
    cached = Object.hasOwn(value, 'cachedValue') ? primitive(value.cachedValue) : undefined;
  if (options.formulaPolicy === 'strip') return cached ?? null;
  return Object.freeze({
    formula: expression,
    ...(cached === undefined ? {} : { cachedValue: cached }),
  });
}
export function row(input: unknown, options: Options): readonly XlsxCell[] {
  let size = 0;
  return Object.freeze(
    array(input).map((value) => {
      const normalized = cell(value, options);
      size += Buffer.byteLength(JSON.stringify(normalized));
      if (size > Math.min(2 * 1024 * 1024, options.maxUncompressedBytes))
        throw failure('EK_XLSX_LIMIT');
      return normalized;
    }),
  );
}

/** Derived finite style/font/format admission, independent of raw worksheet cell counts. */
export function styleBudget(options: Options) {
  const styles = new Set<string>(),
    fonts = new Set<string>(),
    formats = new Set<string>(),
    maximum = Math.min(4096, options.maxCells + 1);
  return (cells: readonly XlsxCell[]) => {
    for (const value of cells)
      if (
        value &&
        typeof value === 'object' &&
        !(value instanceof Date) &&
        'style' in value &&
        value.style
      ) {
        const current = value.style;
        styles.add(JSON.stringify(current));
        if (current.fontName !== undefined) fonts.add(current.fontName);
        if (current.numberFormat !== undefined) formats.add(current.numberFormat);
        if (
          styles.size > maximum ||
          fonts.size > Math.min(256, maximum) ||
          formats.size > Math.min(256, maximum)
        )
          throw failure('EK_XLSX_LIMIT');
      }
  };
}
