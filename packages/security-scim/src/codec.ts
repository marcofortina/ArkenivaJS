// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import SCIMMY from 'scimmy';
import { freezeData } from '@arkenivajs/core/support';
import type { ScimRecord, ScimPatch, ScimPage } from './contracts.js';
import { data, object, text, expression, failure } from './validation.js';

export type ResourceKind = 'Users' | 'Groups';
const schema = (kind: ResourceKind) =>
  kind === 'Users' ? SCIMMY.Schemas.User : SCIMMY.Schemas.Group;
function native<T>(work: () => T): T {
  try {
    return work();
  } catch {
    throw failure();
  }
}
/** Native schema objects never cross the public JSON boundary or mutate global resource registrations. */
function plain(value: unknown): unknown {
  return data(JSON.parse(JSON.stringify(value)) as unknown);
}
export function record(
  kind: ResourceKind,
  input: unknown,
  direction: 'in' | 'out' = 'out',
): ScimRecord {
  const value = object(input),
    Schema = schema(kind);
  if (!Array.isArray(value.schemas) || value.schemas.length !== 1 || value.schemas[0] !== Schema.id)
    throw failure();
  const result = native(() => plain(new Schema(value, direction))) as ScimRecord;
  if (direction === 'out') text(result.id, 256);
  return freezeData(result);
}
export function filter(input: unknown, maximumDepth = 8): string {
  const selected = expression(input, maximumDepth);
  native(() => data(JSON.parse(JSON.stringify(new SCIMMY.Types.Filter(selected))) as unknown));
  return selected;
}
function path(input: unknown, maximumDepth: number): string {
  const selected = expression(text(input, 1024), maximumDepth);
  let base = '',
    group = '',
    quoted = false,
    escaped = false,
    depth = 0;
  for (const c of selected) {
    if (quoted) {
      if (depth) group += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') quoted = false;
      continue;
    }
    if (c === '"') {
      if (!depth) throw failure();
      quoted = true;
      group += c;
      continue;
    }
    if (c === '[') {
      if (depth++) group += c;
      continue;
    }
    if (c === ']') {
      if (--depth) group += c;
      else {
        filter(group, maximumDepth);
        group = '';
      }
      continue;
    }
    if (depth) group += c;
    else base += c;
  }
  if (!/^[A-Za-z$][A-Za-z0-9_$:.-]*$/.test(base)) throw failure();
  let valid = false;
  for (const Schema of [SCIMMY.Schemas.User, SCIMMY.Schemas.Group]) {
    try {
      Schema.definition.attribute(base);
      valid = true;
    } catch {
      /* The other core resource schema may own this path. */
    }
  }
  if (!valid) throw failure();
  return selected;
}
export function patch(input: unknown, maximumDepth = 8): ScimPatch {
  const value = object(input);
  if (
    Object.keys(value).some((key) => !['schemas', 'Operations'].includes(key)) ||
    !Array.isArray(value.Operations) ||
    value.Operations.length < 1 ||
    value.Operations.length > 100
  )
    throw failure();
  const Operations = value.Operations.map((input) => {
    const operation = object(input);
    if (Object.keys(operation).some((key) => !['op', 'path', 'value'].includes(key)))
      throw failure();
    const op = text(operation.op, 16).toLowerCase();
    if (
      !['add', 'replace', 'remove'].includes(op) ||
      (op !== 'remove' && !Object.hasOwn(operation, 'value')) ||
      (op === 'remove' && (operation.path === undefined || Object.hasOwn(operation, 'value')))
    )
      throw failure();
    if (operation.path === undefined)
      for (const name of Object.keys(object(operation.value))) path(name, maximumDepth);
    return {
      op: op as 'add' | 'replace' | 'remove',
      ...(operation.path === undefined ? {} : { path: path(operation.path, maximumDepth) }),
      ...(Object.hasOwn(operation, 'value') ? { value: operation.value } : {}),
    };
  });
  const normalized = { schemas: value.schemas, Operations };
  native(() => new SCIMMY.Messages.PatchOp(normalized as never));
  return freezeData(normalized) as ScimPatch;
}
export async function apply(
  kind: ResourceKind,
  source: ScimRecord,
  input: ScimPatch,
): Promise<ScimRecord> {
  const value = record(kind, source),
    operation = patch(input);
  try {
    const Schema = schema(kind),
      result = await new SCIMMY.Messages.PatchOp(operation as never).apply(new Schema(value));
    return record(kind, plain(result ?? value));
  } catch {
    throw failure();
  }
}
/** Already-paged provider results are not sorted or paged for a second time. */
export function page(kind: ResourceKind, input: unknown, maximum = 100): ScimPage {
  const value = object(input);
  for (const key of ['startIndex', 'itemsPerPage', 'totalResults'])
    if (
      !Number.isSafeInteger(value[key]) ||
      (value[key] as number) < (key === 'startIndex' ? 1 : 0)
    )
      throw failure();
  if (
    !Array.isArray(value.Resources) ||
    value.Resources.length > maximum ||
    value.itemsPerPage !== value.Resources.length ||
    value.Resources.length > (value.totalResults as number) ||
    ((value.startIndex as number) > (value.totalResults as number) && value.Resources.length)
  )
    throw failure();
  const Resources = value.Resources.map((item) => record(kind, item));
  return freezeData({
    startIndex: value.startIndex,
    itemsPerPage: value.itemsPerPage,
    totalResults: value.totalResults,
    Resources,
  }) as ScimPage;
}
export function descriptions(): readonly unknown[] {
  return freezeData([
    plain(SCIMMY.Schemas.User.definition.describe()),
    plain(SCIMMY.Schemas.Group.definition.describe()),
  ]);
}
