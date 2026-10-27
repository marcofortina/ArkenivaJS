// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  FilterParser,
  AndFilter,
  OrFilter,
  NotFilter,
  EqualityFilter,
  ApproximateFilter,
  GreaterThanEqualsFilter,
  LessThanEqualsFilter,
  PresenceFilter,
  SubstringFilter,
  ExtensibleFilter,
} from 'ldapts';
import type { Filter } from 'ldapts';
import { fields, text, attribute, failure } from './validation.js';

/** Parse trusted bounded structure upstream, then bind strings as native assertion values, never syntax. */
export function boundFilter(
  template: string,
  input: Readonly<Record<string, string>>,
  allowed: readonly string[],
): Filter {
  try {
    template = text(template, 8192);
    const values = fields(input),
      markers = new Map<string, string>(),
      used = new Set<string>();
    if (template.includes('arkenivajs_ldap_bound_')) throw failure();
    let depth = 0,
      count = 0;
    for (const character of template) {
      if (character === '(') {
        if (++depth > 32 || ++count > 256) throw failure();
      } else if (character === ')' && --depth < 0) throw failure();
    }
    if (depth !== 0 || !template.startsWith('(') || !template.endsWith(')')) throw failure();
    const encoded = template.replace(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g, (_match, name: string) => {
      if (!Object.hasOwn(values, name)) throw failure();
      const marker = 'arkenivajs_ldap_bound_' + markers.size;
      markers.set(marker, text(values[name], 2048, true));
      used.add(name);
      return marker;
    });
    if (
      encoded.includes('{') ||
      encoded.includes('}') ||
      Object.keys(values).some((key) => !used.has(key))
    )
      throw failure();
    const parsed = FilterParser.parseString(encoded);
    const value = (input: string | Buffer) => {
      if (typeof input !== 'string') throw failure();
      if (markers.has(input)) return markers.get(input)!;
      if (input.includes('arkenivajs_ldap_bound_')) throw failure();
      return input;
    };
    const check = (name: string) => {
      const normalized = attribute(name);
      if (!allowed.includes(normalized) && !['objectclass', 'member'].includes(normalized))
        throw failure();
      return normalized;
    };
    const bind = (node: Filter): Filter => {
      if (node instanceof AndFilter) return new AndFilter({ filters: node.filters.map(bind) });
      if (node instanceof OrFilter) return new OrFilter({ filters: node.filters.map(bind) });
      if (node instanceof NotFilter) return new NotFilter({ filter: bind(node.filter) });
      if (node instanceof EqualityFilter)
        return new EqualityFilter({ attribute: check(node.attribute), value: value(node.value) });
      if (node instanceof ApproximateFilter)
        return new ApproximateFilter({
          attribute: check(node.attribute),
          value: value(node.value),
        });
      if (node instanceof GreaterThanEqualsFilter)
        return new GreaterThanEqualsFilter({
          attribute: check(node.attribute),
          value: value(node.value),
        });
      if (node instanceof LessThanEqualsFilter)
        return new LessThanEqualsFilter({
          attribute: check(node.attribute),
          value: value(node.value),
        });
      if (node instanceof PresenceFilter)
        return new PresenceFilter({ attribute: check(node.attribute) });
      if (node instanceof SubstringFilter)
        return new SubstringFilter({
          attribute: check(node.attribute),
          initial: value(node.initial),
          any: node.any.map(value),
          final: value(node.final),
        });
      if (node instanceof ExtensibleFilter)
        return new ExtensibleFilter({
          matchType: check(node.matchType),
          value: value(node.value),
          rule: node.rule,
          dnAttributes: node.dnAttributes,
        });
      throw failure();
    };
    return bind(parsed);
  } catch {
    throw failure();
  }
}
