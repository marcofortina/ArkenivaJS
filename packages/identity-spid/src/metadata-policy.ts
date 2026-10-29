// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isDeepStrictEqual, types } from 'node:util';
import { freezeData } from '@arkenivajs/core/support';
import { failure, fields, integer } from './validation.js';

const operators = [
  'value',
  'add',
  'default',
  'one_of',
  'subset_of',
  'superset_of',
  'essential',
] as const;
type Rule = Record<string, unknown>;
type Policy = Record<string, Record<string, Rule>>;
const own = (value: object, key: string) => Object.hasOwn(value, key);
const equal = (a: unknown, b: unknown) => isDeepStrictEqual(a, b);
const contains = (values: readonly unknown[], value: unknown) =>
  values.some((item) => equal(item, value));
const union = (a: readonly unknown[], b: readonly unknown[]) => [
  ...a,
  ...b.filter((value) => !contains(a, value)),
];
const intersection = (a: readonly unknown[], b: readonly unknown[]) =>
  a.filter((value) => contains(b, value));
const subset = (a: readonly unknown[], b: readonly unknown[]) =>
  a.every((value) => contains(b, value));

/** Normalize interoperable JSON without invoking application getters or proxy traps. */
function snapshot(input: unknown, maxBytes: number): unknown {
  let nodes = 0;
  let bytes = 0;
  const visit = (value: unknown, depth: number): unknown => {
    if (++nodes > 4096 || depth > 16) throw failure('EK_EID_FEDERATION');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      bytes += Buffer.byteLength(value);
      if (bytes > maxBytes) throw failure('EK_EID_FEDERATION');
      if (Buffer.from(value).toString() !== value) throw failure('EK_EID_FEDERATION');
      return value;
    }
    if (typeof value === 'number' && Number.isFinite(value))
      return Object.is(value, -0) ? 0 : value;
    if (value && typeof value === 'object' && types.isProxy(value))
      throw failure('EK_EID_FEDERATION');
    if (Array.isArray(value)) {
      if (value.length > 256 || Reflect.ownKeys(value).length !== value.length + 1)
        throw failure('EK_EID_FEDERATION');
      return Array.from({ length: value.length }, (_, index) => {
        const property = Object.getOwnPropertyDescriptor(value, String(index));
        if (!property || !('value' in property)) throw failure('EK_EID_FEDERATION');
        return visit(property.value, depth + 1);
      });
    }
    const object = fields(value),
      result: Record<string, unknown> = Object.create(null);
    if (Object.keys(object).length > 256) throw failure('EK_EID_FEDERATION');
    for (const [name, item] of Object.entries(object)) {
      bytes += Buffer.byteLength(name);
      if (bytes > maxBytes) throw failure('EK_EID_FEDERATION');
      result[name] = visit(item, depth + 1);
    }
    return result;
  };
  const result = visit(input, 0);
  if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) throw failure('EK_EID_FEDERATION');
  return result;
}
/** Set operators support strings, numbers and objects; arrays and booleans are not set members. */
function values(input: unknown): readonly unknown[] {
  if (!Array.isArray(input)) throw failure('EK_EID_FEDERATION');
  const kind = input.length ? typeof input[0] : undefined;
  if (
    input.some(
      (item) =>
        item === null ||
        Array.isArray(item) ||
        !['string', 'number', 'object'].includes(typeof item) ||
        typeof item !== kind,
    )
  )
    throw failure('EK_EID_FEDERATION');
  if (input.some((item, index) => contains(input.slice(0, index), item)))
    throw failure('EK_EID_FEDERATION');
  return input;
}
function validate(rule: Rule) {
  for (const operator of Object.keys(rule)) {
    if (!operators.includes(operator as (typeof operators)[number]))
      throw failure('EK_EID_FEDERATION');
    if (['add', 'one_of', 'subset_of', 'superset_of'].includes(operator)) values(rule[operator]);
  }
  if (own(rule, 'essential') && typeof rule.essential !== 'boolean')
    throw failure('EK_EID_FEDERATION');
  if (own(rule, 'default') && rule.default === null) throw failure('EK_EID_FEDERATION');
  if (own(rule, 'one_of')) {
    if (
      !values(rule.one_of).length ||
      ['add', 'subset_of', 'superset_of'].some((operator) => own(rule, operator))
    )
      throw failure('EK_EID_FEDERATION');
  }
  if (own(rule, 'value')) {
    if (rule.value === null) {
      if (
        Object.keys(rule).some((operator) => !['value', 'essential'].includes(operator)) ||
        rule.essential === true
      )
        throw failure('EK_EID_FEDERATION');
    } else {
      if (own(rule, 'one_of') && !contains(values(rule.one_of), rule.value))
        throw failure('EK_EID_FEDERATION');
      if (own(rule, 'add') && !subset(values(rule.add), values(rule.value)))
        throw failure('EK_EID_FEDERATION');
      if (own(rule, 'subset_of') && !subset(values(rule.value), values(rule.subset_of)))
        throw failure('EK_EID_FEDERATION');
      if (own(rule, 'superset_of') && !subset(values(rule.superset_of), values(rule.value)))
        throw failure('EK_EID_FEDERATION');
    }
  }
  if (
    own(rule, 'add') &&
    own(rule, 'subset_of') &&
    !subset(values(rule.add), values(rule.subset_of))
  )
    throw failure('EK_EID_FEDERATION');
  if (
    own(rule, 'subset_of') &&
    own(rule, 'superset_of') &&
    !subset(values(rule.superset_of), values(rule.subset_of))
  )
    throw failure('EK_EID_FEDERATION');
}
function merge(target: Rule, incoming: Rule) {
  validate(incoming);
  for (const [operator, value] of Object.entries(incoming)) {
    if (!own(target, operator)) target[operator] = value;
    else if (operator === 'value' || operator === 'default') {
      if (!equal(target[operator], value)) throw failure('EK_EID_FEDERATION');
    } else if (operator === 'essential')
      target[operator] = target[operator] === true || value === true;
    else if (operator === 'add' || operator === 'superset_of')
      target[operator] = union(values(target[operator]), values(value));
    else target[operator] = intersection(values(target[operator]), values(value));
  }
  validate(target);
}
/** Resolve upper-to-lower policies before applying their fixed standard operator order. */
export function applyMetadataPolicies(
  metadata: unknown,
  policies: readonly unknown[],
  maxBytes: number,
): Readonly<Record<string, unknown>> {
  try {
    integer(maxBytes);
    const input = fields(snapshot({ metadata, policies }, maxBytes));
    const result = fields(input.metadata),
      policyList = input.policies;
    for (const parameters of Object.values(result)) fields(parameters);
    if (!Array.isArray(policyList) || policyList.length > 64) throw failure('EK_EID_FEDERATION');
    const merged: Policy = Object.create(null);
    for (const policy of policyList) {
      for (const [entity, parameters] of Object.entries(fields(policy))) {
        const current = (merged[entity] ??= Object.create(null) as Record<string, Rule>);
        for (const [parameter, rule] of Object.entries(fields(parameters))) {
          const target = (current[parameter] ??= Object.create(null) as Rule);
          merge(target, fields(rule));
        }
      }
    }
    for (const [entity, parameters] of Object.entries(merged)) {
      const current = own(result, entity)
        ? fields(result[entity])
        : (Object.create(null) as Record<string, unknown>);
      for (const [parameter, rule] of Object.entries(parameters)) {
        let value = current[parameter];
        if (own(rule, 'value')) value = rule.value === null ? undefined : rule.value;
        if (own(rule, 'add'))
          value = value === undefined ? rule.add : union(values(value), values(rule.add));
        if (value === undefined && own(rule, 'default')) value = rule.default;
        if (value !== undefined && own(rule, 'one_of') && !contains(values(rule.one_of), value))
          throw failure('EK_EID_FEDERATION');
        if (value !== undefined && own(rule, 'subset_of'))
          value = intersection(values(value), values(rule.subset_of));
        if (
          value !== undefined &&
          own(rule, 'superset_of') &&
          !subset(values(rule.superset_of), values(value))
        )
          throw failure('EK_EID_FEDERATION');
        if (rule.essential === true && (value === undefined || value === null))
          throw failure('EK_EID_FEDERATION');
        if (value === null) throw failure('EK_EID_FEDERATION');
        if (value === undefined) delete current[parameter];
        else current[parameter] = value;
      }
      if (own(result, entity) || Object.keys(current).length) result[entity] = current;
    }
    if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) throw failure('EK_EID_FEDERATION');
    return freezeData(result);
  } catch {
    throw failure('EK_EID_FEDERATION');
  }
}
