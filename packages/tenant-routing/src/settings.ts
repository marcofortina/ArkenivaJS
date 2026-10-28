// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import type {
  TenantRoutingPluginSettings,
  TenantOperationHandler,
  TenantRegistryProvider,
  TenantRequestTransformer,
  TenantResponseTransformer,
  ApprovedUpstream,
  TenantUpstreamCredentialProvider,
  TenantRoutingEventExporter,
} from './contracts.js';
import { data, captureMethod } from './provider-support.js';
import { routingFailure } from './errors.js';
import { jsonSnapshot } from './json.js';

const identifier = /^[a-z][a-z0-9._-]{0,127}$/;
function callback<T extends (...args: never[]) => unknown>(value: unknown): T {
  if (typeof value !== 'function' || types.isProxy(value)) throw routingFailure();
  return value as T;
}
function functions<T extends (...args: never[]) => unknown>(
  value: unknown,
): ReadonlyMap<string, T> {
  const source = data(value),
    result = new Map<string, T>();
  const entries = Object.entries(source);
  if (entries.length > 20000) throw routingFailure();
  for (const [key, value] of entries) {
    if (!identifier.test(key)) throw routingFailure();
    result.set(key, callback<T>(value));
  }
  return result;
}
export function captureSettings(input: TenantRoutingPluginSettings) {
  try {
    const fields = data(input, [
      'registry',
      'handlers',
      'requestTransformers',
      'responseTransformers',
      'transformers',
      'credentialProvider',
      'eventExporter',
      'approvedUpstreams',
      'capabilitiesPath',
      'maxCapabilities',
      'authorize',
      'activation',
    ]);
    if (
      fields.activation !== 'startup' ||
      ('responseTransformers' in fields && 'transformers' in fields)
    )
      throw routingFailure();
    const maxCapabilities = fields.maxCapabilities === undefined ? 1000 : fields.maxCapabilities;
    if (
      !Number.isInteger(maxCapabilities) ||
      (maxCapabilities as number) < 1 ||
      (maxCapabilities as number) > 5000
    )
      throw routingFailure();
    const capabilitiesPath =
      fields.capabilitiesPath === undefined ? '/api/tenant/capabilities' : fields.capabilitiesPath;
    if (
      typeof capabilitiesPath !== 'string' ||
      capabilitiesPath.length > 512 ||
      !/^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/.test(capabilitiesPath) ||
      capabilitiesPath.split('/').some((part) => part === '.' || part === '..') ||
      ['/graphql', '/health', '/livez', '/readyz'].some(
        (path) => capabilitiesPath === path || capabilitiesPath.startsWith(path + '/'),
      )
    )
      throw routingFailure();
    const upstreams =
      fields.approvedUpstreams === undefined ? [] : jsonSnapshot(fields.approvedUpstreams, 8388608);
    if (!Array.isArray(upstreams) || upstreams.length > 20000) throw routingFailure();
    return Object.freeze({
      registry: Object.freeze({
        loadSnapshot: captureMethod<TenantRegistryProvider['loadSnapshot']>(
          fields.registry,
          'loadSnapshot',
        ),
      }),
      handlers: functions<TenantOperationHandler>(fields.handlers),
      requestTransformers: functions<TenantRequestTransformer>(
        fields.requestTransformers === undefined ? {} : fields.requestTransformers,
      ),
      responseTransformers: functions<TenantResponseTransformer>(
        fields.responseTransformers === undefined
          ? fields.transformers === undefined
            ? {}
            : fields.transformers
          : fields.responseTransformers,
      ),
      credentialProvider:
        fields.credentialProvider === undefined
          ? undefined
          : Object.freeze({
              get: captureMethod<TenantUpstreamCredentialProvider['get']>(
                fields.credentialProvider,
                'get',
              ),
            }),
      approvedUpstreams: upstreams as readonly ApprovedUpstream[],
      eventExporter:
        fields.eventExporter === undefined
          ? undefined
          : Object.freeze({
              export: captureMethod<TenantRoutingEventExporter['export']>(
                fields.eventExporter,
                'export',
              ),
            }),
      capabilitiesPath,
      maxCapabilities: maxCapabilities as number,
      authorize: callback<TenantRoutingPluginSettings['authorize']>(fields.authorize),
    });
  } catch {
    throw routingFailure();
  }
}
export type Settings = ReturnType<typeof captureSettings>;
