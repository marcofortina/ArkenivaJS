// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { SqlStatement, SqlValue } from '@arkenivajs/core';

/** SQL lexical rules selected by the owning native adapter. */
export type SqlDialect = 'postgres' | 'mysql' | 'mariadb' | 'oracle';

/** Session settings must match the native connection, including changed SQL modes. */
export interface SqlLexicalOptions {
  /** PostgreSQL standard_conforming_strings; defaults to true. */
  readonly standardConformingStrings?: boolean;
  /** MySQL/MariaDB NO_BACKSLASH_ESCAPES; defaults to false. */
  readonly noBackslashEscapes?: boolean;
  /** MySQL/MariaDB ANSI_QUOTES; defaults to false. */
  readonly ansiQuotes?: boolean;
}

/** Resource bounds apply before acquisition; large/native values use the driver API. */
export const SQL_LIMITS = Object.freeze({
  statementBytes: 1_048_576,
  parameterCount: 65_535,
  bindingBytes: 16_777_216,
});

/** Native parameters are copied, never interpolated; containers are immutable. */
export interface CompiledSql {
  readonly dialect: SqlDialect;
  readonly text: string;
  readonly parameters: readonly SqlValue[] | Readonly<Record<string, SqlValue>>;
  /** Placeholder occurrences in source order, including repeated names. */
  readonly names: readonly string[];
  /** SHA-256 over dialect and source text, excluding every supplied binding value. */
  readonly fingerprint: string;
}

const start = (character: string | undefined): boolean =>
  character !== undefined && /[A-Za-z_]/.test(character);
const part = (character: string | undefined): boolean =>
  character !== undefined && /[A-Za-z_0-9]/.test(character);
const nativeStart = (character: string | undefined): boolean =>
  character !== undefined && (start(character) || character.charCodeAt(0) >= 128);
const nativePart = (character: string | undefined): boolean =>
  character !== undefined &&
  (part(character) || character === '$' || character.charCodeAt(0) >= 128);
const newline = (character: string | undefined): boolean =>
  character === '\n' || character === '\r';

function invalid(message: string, offset?: number): never {
  throw new KitError({
    code: 'EK_CONFIG_INVALID',
    message,
    ...(offset === undefined ? {} : { details: { offset } }),
  });
}

function record(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

function dataValue(input: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  if (!descriptor) return undefined;
  if (!('value' in descriptor)) invalid('SQL inputs must not contain accessors');
  return descriptor.value;
}

function statementText(statement: SqlStatement): string {
  if (!record(statement)) invalid('SQL statement must be a plain record');
  const text = dataValue(statement, 'text');
  if (
    typeof text !== 'string' ||
    text.trim().length === 0 ||
    text.includes('\0') ||
    Buffer.byteLength(text) > SQL_LIMITS.statementBytes
  )
    invalid('SQL text must be nonempty, NUL-free and within the byte limit');
  return text;
}

/** Capture caller values before queued execution; lexical compilation still uses the actual session mode. */
export function captureSqlStatement(statement: SqlStatement): Readonly<SqlStatement> {
  const text = statementText(statement);
  const captured = bindings(dataValue(statement, 'bindings')).values;
  const named = Object.create(null) as Record<string, SqlValue>;
  for (const [name, value] of captured) named[name] = value;
  return Object.freeze({ text, bindings: Object.freeze(named) });
}

/** Capture mutable portable values before any asynchronous pool operation. */
function bindings(input: unknown): {
  values: Map<string, SqlValue>;
  sizes: Map<string, number>;
} {
  if (input === undefined) return { values: new Map(), sizes: new Map() };
  if (!record(input) || Object.getOwnPropertySymbols(input).length)
    invalid('SQL bindings must be a plain record of named portable values');
  const keys = Object.getOwnPropertyNames(input);
  if (keys.length > SQL_LIMITS.parameterCount)
    invalid('SQL binding count exceeds the resource limit');
  const captured = new Map<string, SqlValue>();
  const sizes = new Map<string, number>();
  let bytes = 0;
  for (const key of keys) {
    const before = bytes;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || /[\r\n]$/.test(key))
      invalid('Invalid SQL binding identifier');
    const value = dataValue(input, key);
    let copy: SqlValue;
    if (value === null || typeof value === 'boolean') {
      copy = value;
      bytes += 8;
    } else if (typeof value === 'number') {
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))
        invalid('SQL numeric bindings must be finite; large integers require bigint');
      copy = value;
      bytes += 8;
    } else if (typeof value === 'string' || typeof value === 'bigint') {
      copy = value;
      bytes += Buffer.byteLength(String(value));
    } else if (value instanceof Date) {
      const time = Date.prototype.getTime.call(value);
      if (!Number.isFinite(time)) invalid('SQL date bindings must represent a valid instant');
      copy = new Date(time);
      bytes += 8;
    } else if (value instanceof Uint8Array) {
      bytes += value.byteLength;
      if (bytes > SQL_LIMITS.bindingBytes) invalid('SQL bindings exceed the byte limit');
      copy = new Uint8Array(value);
    } else {
      invalid('SQL bindings support only scalar, Date and Uint8Array values');
    }
    bytes += Buffer.byteLength(key);
    if (bytes > SQL_LIMITS.bindingBytes) invalid('SQL bindings exceed the byte limit');
    captured.set(key, copy);
    sizes.set(key, bytes - before);
  }
  return { values: captured, sizes };
}

function lineEnd(text: string, offset: number): number {
  let position = offset;
  while (position < text.length && !newline(text[position])) position++;
  return position;
}

function quoted(text: string, offset: number, quote: string, backslash: boolean): number {
  let position = offset + 1;
  while (position < text.length) {
    if (backslash && text[position] === '\\') {
      position += 2;
    } else if (text[position] === quote) {
      if (text[position + 1] === quote) position += 2;
      else return position + 1;
    } else position++;
  }
  return invalid('Unterminated SQL quoted token', offset);
}

function blockEnd(text: string, offset: number, nested: boolean): number {
  let depth = 1,
    position = offset + 2;
  while (position < text.length) {
    if (text.startsWith('*/', position)) {
      position += 2;
      if (--depth === 0) return position;
    } else if (nested && text.startsWith('/*', position)) {
      depth++;
      position += 2;
    } else position++;
  }
  return invalid('Unterminated SQL block comment', offset);
}

/** PostgreSQL newline-separated string continuations retain the first token's escape mode. */
function continuation(text: string, offset: number): number | undefined {
  let position = offset,
    hasNewline = false;
  while (position < text.length) {
    if (/[ \t\n\r\f\v]/.test(text[position]!)) {
      if (newline(text[position])) hasNewline = true;
      position++;
    } else if (text.startsWith('--', position)) {
      position = lineEnd(text, position + 2);
    } else break;
  }
  return hasNewline && text[position] === "'" ? position : undefined;
}

function oracleQuote(text: string, offset: number): number | undefined {
  if (nativePart(text[offset - 1])) return undefined;
  const prefix = /[nN]/.test(text[offset]!) ? 1 : 0;
  if (!/[qQ]/.test(text[offset + prefix] ?? '') || text[offset + prefix + 1] !== "'")
    return undefined;
  const begin = offset + prefix + 2;
  const codepoint = text.codePointAt(begin);
  if (codepoint === undefined) invalid('Missing Oracle alternative quote delimiter', offset);
  const delimiter = String.fromCodePoint(codepoint);
  if (/[ \t\r\n]/.test(delimiter)) invalid('Invalid Oracle alternative quote delimiter', begin);
  const paired: Record<string, string> = { '[': ']', '{': '}', '<': '>', '(': ')' };
  const close = paired[delimiter] ?? delimiter;
  const end = text.indexOf(close + "'", begin + delimiter.length);
  if (end < 0) invalid('Unterminated Oracle alternative quote', offset);
  return end + close.length + 1;
}

/**
 * Compile portable named binds through dialect-aware lexical states.
 * @param statement SQL text and an exact binding record; values never become SQL text.
 * @param dialect Owning adapter's SQL dialect.
 * @param options Actual session lexical settings; adapters must keep these synchronized.
 * @returns Captured native parameters, source-order bind names and a safe fingerprint.
 * @throws KitError with EK_CONFIG_INVALID before any driver call on uncertain or invalid input.
 */
export function compileSql(
  statement: SqlStatement,
  dialect: SqlDialect,
  options: SqlLexicalOptions = {},
): CompiledSql {
  if (!['postgres', 'mysql', 'mariadb', 'oracle'].includes(dialect)) invalid('Unknown SQL dialect');
  const text = statementText(statement);
  if (!record(options) || Object.getOwnPropertySymbols(options).length)
    invalid('SQL lexical options must be a plain record');
  for (const key of Object.getOwnPropertyNames(options)) {
    if (
      !['standardConformingStrings', 'noBackslashEscapes', 'ansiQuotes'].includes(key) ||
      typeof dataValue(options, key) !== 'boolean' ||
      (key === 'standardConformingStrings'
        ? dialect !== 'postgres'
        : !['mysql', 'mariadb'].includes(dialect))
    )
      invalid('SQL lexical option does not match the selected dialect');
  }
  const { values, sizes } = bindings(dataValue(statement, 'bindings'));
  const mysql = dialect === 'mysql' || dialect === 'mariadb';
  const fragments: string[] = [],
    names: string[] = [],
    positional: SqlValue[] = [];
  const indices = new Map<string, number>();
  const named = Object.create(null) as Record<string, SqlValue>;
  let position = 0,
    copied = 0,
    parameterBytes = 0;
  while (position < text.length) {
    const character = text[position];
    const alternative = dialect === 'oracle' ? oracleQuote(text, position) : undefined;
    if (
      text.startsWith('--', position) &&
      (!mysql || position + 2 === text.length || text.charCodeAt(position + 2) <= 32)
    ) {
      position = lineEnd(text, position + 2);
    } else if (mysql && character === '#') {
      position = lineEnd(text, position + 1);
    } else if (text.startsWith('/*', position)) {
      if (
        mysql &&
        (text[position + 2] === '!' || (dialect === 'mariadb' && text.startsWith('/*M!', position)))
      )
        invalid('Executable SQL comments require the native driver API', position);
      position = blockEnd(text, position, dialect === 'postgres');
    } else if (alternative !== undefined) {
      position = alternative;
    } else if (character === "'" || character === '"' || (mysql && character === '`')) {
      const escaped =
        (mysql &&
          !options.noBackslashEscapes &&
          (character === "'" || (character === '"' && !options.ansiQuotes))) ||
        (dialect === 'postgres' &&
          character === "'" &&
          // Bit/hex and Unicode escape literals have their own non-backslash quote rules.
          !(/[bBxX]/.test(text[position - 1] ?? '') && !nativePart(text[position - 2])) &&
          !(
            text[position - 1] === '&' &&
            /[uU]/.test(text[position - 2] ?? '') &&
            !nativePart(text[position - 3])
          ) &&
          (options.standardConformingStrings === false ||
            (/[eE]/.test(text[position - 1] ?? '') && !nativePart(text[position - 2]))));
      position = quoted(text, position, character, escaped);
      if (dialect === 'postgres' && character === "'") {
        let next: number | undefined;
        while ((next = continuation(text, position)) !== undefined)
          position = quoted(text, next, "'", escaped);
      }
    } else if (dialect === 'postgres' && character === '$' && !nativePart(text[position - 1])) {
      let end = position + 1;
      if (nativeStart(text[end])) {
        end++;
        while (part(text[end]) || (text[end] !== undefined && text.charCodeAt(end) >= 128)) end++;
      }
      if (text[end] === '$') {
        const delimiter = text.slice(position, end + 1);
        const close = text.indexOf(delimiter, end + 1);
        if (close < 0) invalid('Unterminated PostgreSQL dollar quote', position);
        position = close + delimiter.length;
      } else {
        if (/[0-9]/.test(text[position + 1] ?? ''))
          invalid('Native positional parameters require the native driver API', position);
        position++;
      }
    } else if (character === ':' && text[position + 1] === ':') {
      position += 2;
    } else if (character === ':' && start(text[position + 1])) {
      let end = position + 2;
      while (part(text[end])) end++;
      if (nativePart(text[end])) invalid('Invalid SQL binding identifier', position);
      const name = text.slice(position + 1, end);
      if (!values.has(name)) invalid('SQL statement is missing a named binding', position);
      names.push(name);
      if (names.length > SQL_LIMITS.parameterCount)
        invalid('SQL parameter count exceeds the resource limit');
      if (mysql || !indices.has(name)) {
        parameterBytes += sizes.get(name)!;
        if (parameterBytes > SQL_LIMITS.bindingBytes)
          invalid('Expanded SQL parameters exceed the byte limit');
      }
      let placeholder: string;
      if (dialect === 'postgres') {
        let index = indices.get(name);
        if (index === undefined) {
          index = positional.push(values.get(name)!);
          indices.set(name, index);
        }
        placeholder = `$${index}`;
      } else if (mysql) {
        positional.push(values.get(name)!);
        indices.set(name, 1);
        placeholder = '?';
      } else {
        named[name] = values.get(name)!;
        indices.set(name, 1);
        placeholder = `:${name}`;
      }
      fragments.push(text.slice(copied, position), placeholder);
      copied = position = end;
    } else {
      if (character === ':' && nativeStart(text[position + 1]))
        invalid('Invalid SQL binding identifier', position);
      if (
        (mysql && character === '?') ||
        (dialect === 'oracle' && character === ':' && /[0-9]/.test(text[position + 1] ?? ''))
      )
        invalid('Native positional parameters require the native driver API', position);
      position++;
    }
  }
  if (indices.size !== values.size) invalid('SQL statement contains unused named bindings');
  fragments.push(text.slice(copied));
  return Object.freeze({
    dialect,
    text: fragments.join(''),
    parameters: Object.freeze(dialect === 'oracle' ? named : positional),
    names: Object.freeze(names),
    fingerprint: createHash('sha256').update(dialect).update('\0').update(text).digest('hex'),
  });
}
