// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { types } from 'node:util';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions, VerifiedTenantContext } from '@arkenivajs/core';
import { freezeData, instrumentOperation, captureAbortSignal } from '@arkenivajs/core/support';
import { recorder } from './observation.js';
import type { Observers, Label } from './observation.js';
import type {
  ScimService,
  ScimProvider,
  ScimRecord,
  ScimFilter,
  ScimHttpRequest,
  ScimHttpResponse,
} from './contracts.js';
import { Runtime } from './runtime.js';
import type { Call } from './runtime.js';
import { provider } from './settings.js';
import type { Settings } from './settings.js';
import { data, fields, object, integer, text, failure } from './validation.js';
import { record, filter, patch, apply, page, descriptions, attribute } from './codec.js';
import type { ResourceKind } from './codec.js';

const JSON_TYPE = 'application/scim+json',
  ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error',
  LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const headers = Object.freeze({
  'content-type': JSON_TYPE,
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
});
const response = (
  status: number,
  body: unknown,
  extra: Readonly<Record<string, string>> = {},
): ScimHttpResponse => freezeData({ status, headers: { ...headers, ...extra }, body });
function errorResponse(error: unknown): ScimHttpResponse {
  const code = error instanceof KitError ? error.code : 'EK_BACKEND_UNAVAILABLE';
  const uncertain = error instanceof KitError && error.details?.outcome === 'unknown';
  const status = uncertain
    ? 503
    : ((
        {
          EK_SCIM_UNAUTHORIZED: 403,
          EK_AUTH_REQUIRED: 401,
          EK_AUTH_INVALID: 401,
          EK_AUTH_FORBIDDEN: 403,
          EK_TENANT_UNVERIFIED: 403,
          EK_HTTP_NOT_FOUND: 404,
          EK_SCIM_CONFLICT: 409,
          EK_SCIM_PRECONDITION: 412,
          EK_SCIM_BAD_REQUEST: 400,
          EK_CONFIG_INVALID: 400,
        } as Record<string, number>
      )[code] ?? 503);
  const detail =
    status === 401 || status === 403
      ? 'The provisioning request is not authorized'
      : status === 404
        ? 'The provisioning resource is unavailable'
        : status === 409
          ? 'The provisioning resource conflicts with existing state'
          : status === 412
            ? 'The provisioning resource version does not match'
            : status === 400
              ? 'The provisioning request is invalid'
              : error instanceof KitError && error.details?.outcome === 'unknown'
                ? 'The provisioning outcome is unknown; inspect current state before retrying'
                : 'The provisioning backend is unavailable';
  return response(
    status,
    {
      schemas: [ERROR_SCHEMA],
      status: String(status),
      detail,
      ...(status === 409
        ? { scimType: 'uniqueness' }
        : status === 400
          ? { scimType: 'invalidValue' }
          : {}),
    },
    status === 401 ? { 'www-authenticate': 'Bearer' } : {},
  );
}
function requestHeaders(input: unknown): Readonly<Record<string, string | undefined>> {
  if (
    !input ||
    typeof input !== 'object' ||
    types.isProxy(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input))
  )
    throw failure();
  const selected: Record<string, string> = Object.create(null);
  let bytes = 0;
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key !== 'string' ||
      !/^[A-Za-z0-9-]{1,128}$/.test(key) ||
      !descriptor ||
      !('value' in descriptor) ||
      Object.hasOwn(selected, key.toLowerCase())
    )
      throw failure();
    if (descriptor.value === undefined) continue;
    const value = text(descriptor.value, 16384);
    bytes += Buffer.byteLength(key) + Buffer.byteLength(value);
    if (bytes > 32768) throw failure();
    selected[key.toLowerCase()] = value;
  }
  return Object.freeze(selected);
}
function etag(value: ScimRecord, required: boolean): Readonly<Record<string, string>> {
  const version = value.meta?.version;
  if (version === undefined) {
    if (required) throw failure('EK_BACKEND_UNAVAILABLE');
    return {};
  }
  if (typeof version !== 'string' || !/^(?:W\/)?"[A-Za-z0-9._~-]{1,200}"$/.test(version))
    throw failure('EK_BACKEND_UNAVAILABLE');
  return { etag: version };
}
function currentTenant(settings: Settings, input: unknown): input is VerifiedTenantContext {
  if (!settings.auth || !input || typeof input !== 'object' || types.isProxy(input)) return false;
  const property = Object.getOwnPropertyDescriptor(input, 'identity');
  if (!property || !('value' in property)) return false;
  try {
    return settings.auth.tenantFrom(property.value) === input;
  } catch {
    return false;
  }
}
export function managed(
  settings: Settings,
  owner?: AbortSignal,
  ready?: () => boolean,
  observers: Observers = {},
) {
  const recordObservation = recorder(observers),
    runtime = new Runtime(ready, owner, settings.maxConcurrent, recordObservation.active),
    providers = new Map<ResourceKind, ScimProvider>();
  let sealed = false;
  function register(kind: ResourceKind, input: ScimProvider): void {
    if (sealed || providers.has(kind)) throw failure('EK_LIFECYCLE_STATE');
    providers.set(kind, provider(input, settings.environment));
  }
  async function authorize(
    call: Call,
    input: unknown,
    incoming: Readonly<Record<string, string | undefined>>,
    kind: ResourceKind | undefined,
    method: string,
    bindingRequired: boolean,
  ): Promise<VerifiedTenantContext> {
    const auth = settings.auth,
      authority = settings.authority;
    if (!auth || !authority) throw failure('EK_SCIM_UNAUTHORIZED');
    const identity = await call.step('EK_AUTH_INVALID', (options) =>
        auth.verifyBearer(incoming.authorization, options),
      ),
      tenant = auth.tenantFrom(identity);
    if (
      bindingRequired &&
      (!currentTenant(settings, input) ||
        input.tenantId !== tenant.tenantId ||
        input.identity.issuer !== identity.issuer ||
        input.identity.subject !== identity.subject)
    )
      throw failure('EK_SCIM_UNAUTHORIZED');
    const action = method === 'GET' ? 'read' : 'write';
    if (kind) auth.requireScope(identity, 'scim:' + kind.toLowerCase() + ':' + action);
    else {
      let granted = false;
      for (const resource of ['users', 'groups']) {
        try {
          auth.requireScope(identity, 'scim:' + resource + ':read');
          granted = true;
        } catch {
          /* Either exact read grant may authorize discovery. */
        }
      }
      if (!granted) throw failure('EK_SCIM_UNAUTHORIZED');
    }
    const decision = fields(
      await call.step('EK_SCIM_UNAUTHORIZED', (options) =>
        authority.require(
          'scim.' + (kind?.toLowerCase() ?? 'discovery') + '.' + action,
          { issuer: identity.issuer, subject: identity.subject, tenant },
          { tenant },
          options,
        ),
      ),
      ['issuer', 'subject', 'tenant'],
    );
    if (
      decision.issuer !== identity.issuer ||
      decision.subject !== identity.subject ||
      !currentTenant(settings, decision.tenant) ||
      decision.tenant.tenantId !== tenant.tenantId ||
      decision.tenant.identity.issuer !== identity.issuer ||
      decision.tenant.identity.subject !== identity.subject
    )
      throw failure('EK_SCIM_UNAUTHORIZED');
    return tenant;
  }
  function query(url: URL, kind: ResourceKind): ScimFilter {
    const values = url.searchParams;
    for (const key of values.keys())
      if (
        !['filter', 'startIndex', 'count', 'sortBy', 'sortOrder'].includes(key) ||
        values.getAll(key).length !== 1
      )
        throw failure();
    const number = (name: string, fallback: number, minimum: number, maximum: number) => {
      const value = values.get(name);
      if (value !== null && !/^(?:0|[1-9][0-9]*)$/.test(value)) throw failure();
      return integer(value === null ? fallback : Number(value), maximum, minimum);
    };
    const expression = values.has('filter')
      ? filter(values.get('filter'), settings.maxFilterDepth, kind)
      : 'id pr';
    let sortBy: string | undefined, sortOrder: 'ascending' | 'descending' | undefined;
    if (values.has('sortBy')) {
      if (!settings.capabilities.sort) throw failure();
      sortBy = attribute(kind, values.get('sortBy'));
      sortOrder = (values.get('sortOrder') ?? 'ascending') as typeof sortOrder;
      if (!['ascending', 'descending'].includes(sortOrder!)) throw failure();
    } else if (values.has('sortOrder')) throw failure();
    return freezeData({
      expression,
      startIndex: number('startIndex', 1, 1, 2147483647),
      count: number('count', settings.maxPageSize, 0, settings.maxPageSize),
      ...(sortBy ? { sortBy, sortOrder: sortOrder! } : {}),
    });
  }
  async function perform(
    call: Call,
    input: unknown,
    bindingRequired: boolean,
    label: Label,
  ): Promise<ScimHttpResponse> {
    const value = fields(input, ['method', 'path', 'headers', 'body', 'auth']),
      method = text(value.method, 16),
      path = text(value.path, 8192),
      incoming = requestHeaders(value.headers);
    if (
      !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) ||
      !path.startsWith('/') ||
      path.startsWith('//') ||
      /[\\#]/.test(path)
    )
      throw failure();
    const url = new URL(path, 'https://scim.invalid'),
      match = /^\/(Users|Groups)(?:\/([A-Za-z0-9][A-Za-z0-9._-]{0,255}))?$/.exec(url.pathname),
      kind = match?.[1] as ResourceKind | undefined,
      id = match?.[2];
    label.resource = kind ?? 'discovery';
    label.operation = !kind
      ? 'discovery'
      : method === 'GET'
        ? id
          ? 'get'
          : 'list'
        : method === 'POST'
          ? 'create'
          : method === 'PUT'
            ? 'replace'
            : method === 'PATCH'
              ? 'patch'
              : 'delete';
    const tenant = await authorize(call, value.auth, incoming, kind, method, bindingRequired);
    const work = async (): Promise<ScimHttpResponse> => {
      if (!kind) {
        if (method !== 'GET' || url.search) throw failure('EK_HTTP_NOT_FOUND');
        if (url.pathname === '/ServiceProviderConfig')
          return response(200, {
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            patch: { supported: true },
            bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
            filter: { supported: true, maxResults: settings.maxPageSize },
            changePassword: { supported: false },
            sort: { supported: settings.capabilities.sort },
            etag: { supported: settings.capabilities.etag },
            authenticationSchemes: [
              {
                type: 'oauthbearertoken',
                name: 'OAuth Bearer',
                description:
                  'Issuer-bound bearer verification and explicit tenant provisioning policy',
                primary: true,
              },
            ],
          });
        const schemas = descriptions();
        if (url.pathname === '/Schemas')
          return response(200, {
            schemas: [LIST_SCHEMA],
            totalResults: schemas.length,
            startIndex: 1,
            itemsPerPage: schemas.length,
            Resources: schemas,
          });
        if (url.pathname.startsWith('/Schemas/')) {
          const selected = schemas.find(
            (item) => object(item).id === decodeURIComponent(url.pathname.slice(9)),
          );
          if (!selected) throw failure('EK_HTTP_NOT_FOUND');
          return response(200, selected);
        }
        const resources = ['Users', 'Groups'].map((name, index) => ({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
          id: name === 'Users' ? 'User' : 'Group',
          name: name === 'Users' ? 'User' : 'Group',
          endpoint: '/' + name,
          schema: object(schemas[index]).id,
          schemaExtensions: [],
        }));
        if (url.pathname === '/ResourceTypes')
          return response(200, {
            schemas: [LIST_SCHEMA],
            totalResults: resources.length,
            startIndex: 1,
            itemsPerPage: resources.length,
            Resources: resources,
          });
        if (url.pathname.startsWith('/ResourceTypes/')) {
          const selected = resources.find((item) => item.id === url.pathname.slice(15));
          if (!selected) throw failure('EK_HTTP_NOT_FOUND');
          return response(200, selected);
        }
        throw failure('EK_HTTP_NOT_FOUND');
      }
      const store = providers.get(kind);
      if (!store) throw failure('EK_BACKEND_UNAVAILABLE');
      if (method === 'GET' && !id) {
        const selected = query(url, kind),
          result = page(
            kind,
            await call.step('EK_BACKEND_UNAVAILABLE', (options) =>
              store.list(selected, tenant, options),
            ),
            selected.count,
          );
        if (result.startIndex !== selected.startIndex) throw failure('EK_BACKEND_UNAVAILABLE');
        return response(200, { schemas: [LIST_SCHEMA], ...result });
      }
      if (url.search) throw failure();
      if (method === 'GET' && id) {
        const result = await call.step('EK_BACKEND_UNAVAILABLE', (options) =>
          store.get(id, tenant, options),
        );
        if (!result) throw failure('EK_HTTP_NOT_FOUND');
        const normalized = record(kind, result);
        if (normalized.id !== id) throw failure('EK_BACKEND_UNAVAILABLE');
        return response(200, normalized, etag(normalized, settings.capabilities.etag));
      }
      if (
        method !== 'DELETE' &&
        ![JSON_TYPE, 'application/json'].includes(
          (incoming['content-type'] ?? '').split(';')[0]!.trim().toLowerCase(),
        )
      )
        throw failure();
      const body = method === 'DELETE' ? undefined : data(value.body, settings.maxRequestBytes);
      if (body !== undefined)
        recordObservation.payload(label, 'request', Buffer.byteLength(JSON.stringify(body)));
      if (method === 'POST' && !id) {
        const normalized = record(kind, body, 'in'),
          proposed = { ...normalized, id: randomUUID() },
          result = record(
            kind,
            await call.mutate((options) => store.create(proposed, tenant, options)),
          );
        if (proposed.externalId !== undefined && result.externalId !== proposed.externalId)
          throw failure('EK_BACKEND_UNAVAILABLE');
        return response(201, result, {
          ...etag(result, settings.capabilities.etag),
          location: '/' + kind + '/' + encodeURIComponent(result.id),
        });
      }
      if (!id || method === 'POST') throw failure();
      const ifMatch = incoming['if-match'];
      if (
        ifMatch !== undefined &&
        (!settings.capabilities.etag ||
          (ifMatch !== '*' && !/^(?:W\/)?"[A-Za-z0-9._~-]{1,200}"$/.test(ifMatch)))
      )
        throw failure('EK_SCIM_PRECONDITION');
      const existing = await call.step('EK_BACKEND_UNAVAILABLE', (options) =>
        store.get(id, tenant, options),
      );
      if (!existing) throw failure('EK_HTTP_NOT_FOUND');
      const before = record(kind, existing);
      if (before.id !== id) throw failure('EK_BACKEND_UNAVAILABLE');
      if (ifMatch !== undefined && ifMatch !== '*' && before.meta?.version !== ifMatch)
        throw failure('EK_SCIM_PRECONDITION');
      if (method === 'DELETE') {
        await call.mutate((options) => store.delete(id, ifMatch, tenant, options));
        return response(204, null);
      }
      let result: ScimRecord;
      if (method === 'PUT') {
        const normalized = record(kind, body, 'in');
        if (normalized.externalId !== before.externalId) throw failure();
        result = await call.mutate((options) =>
          store.replace(id, { ...normalized, id }, ifMatch, tenant, options),
        );
      } else {
        const operations = patch(body, settings.maxFilterDepth),
          preview = await apply(kind, before, operations);
        if (preview.id !== before.id || preview.externalId !== before.externalId) throw failure();
        result = await call.mutate((options) =>
          store.patch(id, operations, ifMatch, tenant, options),
        );
      }
      const normalized = record(kind, result);
      if (normalized.id !== id || normalized.externalId !== before.externalId)
        throw failure('EK_BACKEND_UNAVAILABLE');
      return response(200, normalized, etag(normalized, settings.capabilities.etag));
    };
    if (!observers.meter) return work();
    let actual: Promise<ScimHttpResponse> | undefined;
    const invoke = () => {
      if (actual) throw failure('EK_LIFECYCLE_STATE');
      actual = call.watch(Promise.resolve().then(work));
      return actual;
    };
    try {
      await observers.meter.measure({ tenant, operation: 'scim.' + label.operation }, invoke);
    } catch (error) {
      if (!actual) throw error;
      // A diagnostic failure after dispatch cannot repeat or replace the actual storage outcome.
    }
    if (!actual) throw failure('EK_BACKEND_UNAVAILABLE');
    return actual;
  }
  async function execute(
    input: unknown,
    options: OperationOptions | undefined,
    bindingRequired: boolean,
  ): Promise<ScimHttpResponse> {
    const label: Label = { operation: 'invalid', resource: 'unknown' },
      started = performance.now();
    const selected = fields(options ?? {}, ['signal', 'timeoutMs']);
    if (selected.timeoutMs !== undefined) integer(selected.timeoutMs, 30000);
    if (selected.signal !== undefined) captureAbortSignal(selected.signal);
    let completed: ScimHttpResponse | undefined,
      code: string | undefined,
      uncertain = false;
    sealed = true;
    try {
      completed = await instrumentOperation(
        observers.telemetry,
        'scim.operation',
        {},
        () => runtime.run(options, (call) => perform(call, input, bindingRequired, label)),
        () => {},
      );
      return completed;
    } catch (error) {
      code = error instanceof KitError ? error.code : 'EK_BACKEND_UNAVAILABLE';
      uncertain = error instanceof KitError && error.details?.outcome === 'unknown';
      if (
        error instanceof KitError &&
        ['EK_ABORTED', 'EK_TIMEOUT', 'EK_RESOURCE_CLOSED', 'EK_LIFECYCLE_STATE'].includes(
          error.code,
        )
      )
        throw error;
      completed = errorResponse(error);
      return completed;
    } finally {
      if (completed)
        recordObservation.payload(
          label,
          'response',
          completed.status === 204 ? 0 : Buffer.byteLength(JSON.stringify(completed.body)),
        );
      recordObservation.complete(
        label,
        performance.now() - started,
        code,
        completed?.status,
        uncertain,
      );
    }
  }
  const service: ScimService = Object.freeze({
    registerUsers: (input: ScimProvider) => register('Users', input),
    registerGroups: (input: ScimProvider) => register('Groups', input),
    validatePatch: (input: unknown) => patch(input, settings.maxFilterDepth),
    listCapabilities: () => settings.capabilities,
    handle: (input: ScimHttpRequest, options?: OperationOptions) => execute(input, options, true),
  });
  return {
    service,
    /** Private transport entry derives identity from the bearer within the same physical admission slot. */
    http: (input: Omit<ScimHttpRequest, 'auth'>, options?: OperationOptions) =>
      execute(input, options, false),
    close: () => runtime.close(),
    seal: () => {
      sealed = true;
    },
  };
}
