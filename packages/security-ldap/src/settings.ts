// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { LdapSettings, LdapSearchQuery, SecretProvider } from './contracts.js';
import {
  array,
  attribute,
  fields,
  integer,
  method,
  property,
  text,
  failure,
} from './validation.js';
import { boundFilter } from './filter.js';

/** Capture deployment policy once; operation objects cannot replace endpoints or providers. */
export function capture(input: LdapSettings) {
  const value = fields(input, [
    'url',
    'baseDn',
    'userFilterTemplate',
    'groupSearchBaseDn',
    'serviceBindDnRef',
    'serviceBindPasswordRef',
    'secretProvider',
    'tlsTrustBundleRef',
    'requireStartTls',
    'maxEntries',
    'maxGroupDepth',
    'timeoutMs',
    'allowedAttributes',
    'environment',
  ]);
  let url: URL;
  try {
    url = new URL(text(value.url, 2048));
  } catch {
    throw failure();
  }
  if (
    !['ldap:', 'ldaps:'].includes(url.protocol) ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname && url.pathname !== '/') ||
    (value.requireStartTls !== undefined && typeof value.requireStartTls !== 'boolean') ||
    (url.protocol === 'ldap:' && value.requireStartTls !== true)
  )
    throw failure();
  const allowedAttributes = [
    ...new Set(
      array(value.allowedAttributes ?? ['uid', 'cn', 'memberof', 'samaccountname'], 32).map(
        attribute,
      ),
    ),
  ];
  if (
    !allowedAttributes.includes('cn') ||
    !allowedAttributes.some((name) => ['uid', 'samaccountname'].includes(name))
  )
    throw failure();
  const environment = value.environment ?? 'production';
  if (!['development', 'test', 'production'].includes(environment as string)) throw failure();
  // A test-only marker is advisory in addition to the mandatory production TLS policy.
  const usage = property(value.secretProvider, 'usage');
  if (usage !== undefined && !['production', 'test-only'].includes(usage as string))
    throw failure();
  if (environment !== 'test' && usage === 'test-only') throw failure();
  const template = text(value.userFilterTemplate, 8192);
  boundFilter(template, { username: 'validation' }, allowedAttributes);
  return Object.freeze({
    url: url.href,
    startTls: url.protocol === 'ldap:',
    baseDn: text(value.baseDn, 2048),
    groupBase: text(value.groupSearchBaseDn, 2048),
    template,
    bindDnRef: text(value.serviceBindDnRef, 256),
    bindPasswordRef: text(value.serviceBindPasswordRef, 256),
    ...(value.tlsTrustBundleRef === undefined ? {} : { caRef: text(value.tlsTrustBundleRef, 256) }),
    getSecret: method<SecretProvider['get']>(value.secretProvider, 'get'),
    allowedAttributes: Object.freeze(allowedAttributes),
    maxEntries: integer(value.maxEntries ?? 1000, 5000),
    maxDepth: integer(value.maxGroupDepth ?? 8, 32),
    timeoutMs: integer(value.timeoutMs ?? 5000, 30000),
    environment: environment as 'test' | 'development' | 'production',
  });
}
export type Settings = ReturnType<typeof capture>;
export function query(input: LdapSearchQuery, settings: Settings): LdapSearchQuery {
  const value = fields(input, ['baseDn', 'filter', 'attributes', 'maxEntries', 'pageSize']);
  const baseDn = text(value.baseDn, 2048);
  if (![settings.baseDn, settings.groupBase].includes(baseDn)) throw failure();
  const filter = fields(value.filter, ['template', 'values']),
    values = fields(filter.values),
    normalized: Record<string, string> = Object.create(null);
  for (const [key, value] of Object.entries(values)) normalized[key] = text(value, 2048, true);
  const template = text(filter.template, 8192),
    attributes = array(value.attributes, 32).map(attribute);
  if (
    !attributes.length ||
    attributes.some((name) => !settings.allowedAttributes.includes(name)) ||
    new Set(attributes).size !== attributes.length
  )
    throw failure();
  boundFilter(template, normalized, settings.allowedAttributes);
  return Object.freeze({
    baseDn,
    filter: Object.freeze({ template, values: Object.freeze(normalized) }),
    attributes: Object.freeze(attributes),
    maxEntries: integer(value.maxEntries ?? settings.maxEntries, settings.maxEntries),
    pageSize: integer(value.pageSize ?? 100, 256),
  });
}
