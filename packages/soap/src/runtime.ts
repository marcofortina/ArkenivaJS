// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Client, WSSecurity } from 'soap';
import type { IHttpClient, SoapMethod, IHeaders, IExOptions } from 'soap';
import type { OperationOptions } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { SoapClient, SoapServiceProfile, SoapResult } from './contracts.js';
import { fields } from './settings.js';
import type { Settings } from './settings.js';
import { loadAssets } from './assets.js';
import type { ContractAssets } from './assets.js';
import { nativeGraph } from './backend.js';
import { catalog } from './catalog.js';
import type { Binding } from './catalog.js';
import { inspectEnvelope } from './envelope.js';
import { NativeParser } from './parser.js';
import { HttpsConnection } from './https.js';
import { credentials } from './credentials.js';
import type { Credentials } from './credentials.js';
import { input } from './input.js';
import { Call, Calls, safeFailure } from './calls.js';
import { failure } from './validation.js';
import { verifySecurityHeader } from './security-header.js';
import type { Observers } from './observation.js';
const nativeSecurityXml = WSSecurity.prototype.toXML;

interface Profile {
  readonly setting: SoapServiceProfile;
  readonly assets: ContractAssets;
  readonly bindings: readonly Binding[];
}
interface Tagged {
  readonly call: Call;
  readonly secrets: Credentials;
}
export class Runtime {
  readonly calls: Calls;
  readonly clients = new Set<ManagedClient>();
  private readonly profiles = new Map<string, Profile>();
  private closing: Promise<void> | undefined;
  constructor(
    readonly settings: Settings,
    owner: AbortSignal,
    ready: () => boolean,
    observers: Observers = {},
  ) {
    this.calls = new Calls(settings, owner, ready, observers);
  }
  async initialize(): Promise<void> {
    try {
      await this.calls.run(
        undefined,
        async (call) => {
          for (const setting of this.settings.services) {
            call.check();
            const assets = await loadAssets(setting.wsdlFile, call.signal),
              source = assets.documents.at(-1)!.source;
            const parser = await NativeParser.create(
              {
                source,
                assets,
                protocol: setting.protocol,
                timeoutMs: this.settings.timeoutMs,
                maxBytes: Math.min(setting.maxResponseBytes, this.settings.maxOutputBytes),
              },
              this.calls.signal,
              call.signal,
            );
            try {
              const bindings = catalog(await nativeGraph(assets), assets, setting);
              const secrets = await credentials(this.settings, setting, call.options());
              secrets.clear();
              call.check();
              this.profiles.set(setting.id, Object.freeze({ setting, assets, bindings }));
            } finally {
              await parser.close();
            }
          }
        },
        undefined,
        true,
        'startup',
      );
    } catch (error) {
      await this.close().catch(() => undefined);
      throw error;
    }
  }
  async createClient(id: string, options?: OperationOptions): Promise<SoapClient> {
    this.calls.check();
    const profile = this.profiles.get(id);
    if (!profile) throw failure('EK_SOAP_WSDL');
    return this.calls.run(
      options,
      async (call) => {
        if (this.clients.size >= this.settings.maxConcurrent)
          throw failure('EK_BACKEND_UNAVAILABLE');
        const client = new ManagedClient(this, profile);
        this.clients.add(client);
        try {
          await client.initialize(call);
          call.check();
          return Object.freeze({
            call<T = unknown>(operation: string, value: unknown, options?: OperationOptions) {
              return client.call<T>(operation, value, options);
            },
            describe: () => client.describe(),
            close: () => client.close(),
            native: () => client.native(),
          });
        } catch (error) {
          await client.close().catch(() => undefined);
          throw error;
        }
      },
      undefined,
      false,
      'createClient',
    );
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.calls.stop.abort();
    const cleanup = Promise.all([
      this.calls.close(),
      ...[...this.clients].map((client) => client.close()),
    ]).then(() => undefined);
    this.closing = within(() => cleanup, { timeoutMs: this.settings.timeoutMs });
    void this.closing.catch(() => undefined);
    return this.closing;
  }
}
class ManagedClient implements SoapClient {
  private readonly stop = new AbortController();
  private readonly signal: AbortSignal;
  private readonly pending = new Set<Promise<unknown>>();
  private readonly tagged = new WeakMap<object, Tagged>();
  private nativeInstance: Client | undefined;
  private parser: NativeParser | undefined;
  private connection: HttpsConnection | undefined;
  private security: WSSecurity | undefined;
  private securityVersion: string | undefined;
  private generatedSecurity: string | undefined;
  private decode:
    | { source: string; parsed: unknown; status: number; headers: Readonly<Record<string, string>> }
    | undefined;
  private closed = false;
  private closing: Promise<void> | undefined;
  constructor(
    readonly runtime: Runtime,
    readonly profile: Profile,
  ) {
    this.signal = AbortSignal.any([runtime.calls.signal, this.stop.signal]);
  }
  private installSecurity(secrets: Credentials) {
    this.security = secrets.wsSecurity
      ? new WSSecurity(secrets.wsSecurity.username, secrets.wsSecurity.password, {
          passwordType: 'PasswordDigest',
          hasNonce: true,
          hasTimeStamp: true,
          hasTokenCreated: true,
        })
      : undefined;
    this.generatedSecurity = undefined;
    if (this.security) {
      const security = this.security;
      Object.defineProperty(security, 'toXML', {
        configurable: false,
        writable: false,
        value: () => {
          const xml = nativeSecurityXml.call(security);
          this.generatedSecurity = xml;
          return xml;
        },
      });
      Object.freeze(security);
    }
    this.securityVersion = secrets.version;
  }
  async initialize(call: Call): Promise<void> {
    const { settings } = this.runtime,
      { setting, assets } = this.profile;
    this.parser = await NativeParser.create(
      {
        source: assets.documents.at(-1)!.source,
        assets,
        protocol: setting.protocol,
        timeoutMs: settings.timeoutMs,
        maxBytes: Math.min(setting.maxResponseBytes, settings.maxOutputBytes),
      },
      this.signal,
      call.signal,
    );
    this.parser.worker.once('exit', () => {
      void this.close().catch(() => undefined);
    });
    this.connection = await HttpsConnection.create(
      {
        endpoint: setting.endpoint,
        protocol: setting.protocol,
        timeoutMs: settings.timeoutMs,
        maxConcurrent: settings.maxConcurrent,
        maxInputBytes: settings.maxInputBytes,
        maxResponseBytes: Math.min(setting.maxResponseBytes, settings.maxOutputBytes),
      },
      call.signal,
    );
    const secrets = await credentials(settings, setting, call.options());
    try {
      this.installSecurity(secrets);
    } finally {
      secrets.clear();
    }
    call.check();
    const wsdl = await nativeGraph(assets);
    wsdl.options.forceSoap12Headers = setting.protocol === '1.2';
    const transport: IHttpClient = Object.freeze({
      request: (
        url: string,
        body: string,
        callback: Parameters<IHttpClient['request']>[2],
        headers?: IHeaders,
        options?: IExOptions,
      ) => {
        this.check();
        if (
          url !== setting.endpoint ||
          typeof body !== 'string' ||
          body.length > settings.maxInputBytes ||
          Buffer.byteLength(body) > settings.maxInputBytes
        )
          throw failure('EK_SOAP_SCHEMA');
        let completed = false,
          activeCall: Call | undefined;
        const finish: typeof callback = (...arguments_) => {
          if (completed) return;
          completed = true;
          return callback(...arguments_);
        };
        const tag = options && typeof options === 'object' ? this.tagged.get(options) : undefined;
        if (options && typeof options === 'object') this.tagged.delete(options);
        const nativeOptions = tag ? undefined : fields(options ?? {}, ['timeout', 'signal']);
        const version = this.securityVersion;
        const token = this.generatedSecurity;
        this.generatedSecurity = undefined;
        const hasSecurity = this.security !== undefined;
        const task = tag
          ? this.wire(
              url,
              body,
              headers as Record<string, string>,
              tag.call,
              finish,
              tag.secrets,
              token,
            )
          : this.runtime.calls.run(
              nativeOptions
                ? {
                    ...(nativeOptions.timeout === undefined
                      ? {}
                      : { timeoutMs: nativeOptions.timeout as number }),
                    ...(nativeOptions.signal === undefined
                      ? {}
                      : { signal: nativeOptions.signal as AbortSignal }),
                  }
                : undefined,
              (call) =>
                this.owned(async () => {
                  activeCall = call;
                  const secrets = await credentials(settings, setting, call.options());
                  try {
                    if (
                      (hasSecurity || secrets.wsSecurity !== undefined) &&
                      (hasSecurity !== (secrets.wsSecurity !== undefined) ||
                        secrets.version !== version)
                    )
                      throw failure('EK_BACKEND_UNAVAILABLE');
                    return await this.wire(
                      url,
                      body,
                      headers as Record<string, string>,
                      call,
                      finish,
                      secrets,
                      token,
                    );
                  } finally {
                    secrets.clear();
                  }
                }),
              this.signal,
              false,
              'nativeCall',
            );
        const responding = task.then((completion) => {
          completion.deliver();
          return completion.response;
        });
        // Native callback consumers need no promise subscription; retain a rejection handler here.
        void responding
          .catch((error: unknown) => {
            finish(safeFailure(error, tag?.call ?? activeCall));
          })
          .catch(() => undefined);
        return responding;
      },
    });
    Object.defineProperty(wsdl, 'xmlToObject', {
      configurable: false,
      writable: false,
      value: (source: string) => {
        const context = this.decode;
        if (!context || source !== context.source) throw failure('EK_UNSUPPORTED_CAPABILITY');
        return context.parsed;
      },
    });
    const native = new Client(wsdl, setting.endpoint, {
      httpClient: transport,
      forceSoap12Headers: setting.protocol === '1.2',
      disableCache: true,
    });
    Object.defineProperty(native, 'security', { configurable: false, get: () => this.security });
    Object.defineProperty(native, 'setSecurity', {
      configurable: false,
      writable: false,
      value: () => {
        throw failure('EK_UNSUPPORTED_CAPABILITY');
      },
    });
    for (const [name, value] of [
      ['wsdl', wsdl],
      ['httpClient', transport],
      ['endpoint', setting.endpoint],
      ['streamAllowed', false],
      ['returnSaxStream', false],
    ] as const)
      Object.defineProperty(native, name, { value, writable: false, configurable: false });
    this.nativeInstance = native;
  }
  private owned<T>(work: () => Promise<T>): Promise<T> {
    const task = Promise.resolve().then(work);
    this.pending.add(task);
    void task.then(
      () => this.pending.delete(task),
      () => this.pending.delete(task),
    );
    return task;
  }
  private async wire(
    url: string,
    body: string,
    headers: Readonly<Record<string, string>>,
    call: Call,
    callback: Parameters<IHttpClient['request']>[2],
    secrets: Credentials,
    token?: string,
  ) {
    this.check();
    call.check();
    if (url !== this.profile.setting.endpoint) throw failure('EK_SOAP_SCHEMA');
    const qualified = inspectEnvelope(
      body,
      this.profile.setting.protocol,
      this.runtime.settings.maxInputBytes,
      this.profile.bindings.map((entry) => entry.input),
      false,
    );
    const candidates = this.profile.bindings.filter(
      (entry) => entry.input.local === qualified.local && entry.input.uri === qualified.uri,
    );
    const actionHeader = Object.entries(headers).find(
        ([name]) => name.toLowerCase() === 'soapaction',
      )?.[1],
      contentType = Object.entries(headers).find(
        ([name]) => name.toLowerCase() === 'content-type',
      )?.[1];
    const binding = candidates.find((entry) =>
      this.profile.setting.protocol === '1.1'
        ? actionHeader === '"' + entry.action + '"'
        : typeof contentType === 'string' && contentType.includes('action="' + entry.action + '"'),
    );
    if (!binding) throw failure('EK_SOAP_SCHEMA');
    if (secrets.wsSecurity) verifySecurityHeader(body, token);
    call.inputBytes = Buffer.byteLength(body);
    call.submitted = true;
    const reply = await this.connection!.request(body, headers, secrets.material, call.options());
    call.outputBytes = reply.response.data.length;
    call.check();
    const { output, outputAliases } = binding;
    const parsed = this.parser!.parse(reply.body, call.options().timeoutMs, [
      output,
      ...(outputAliases ?? []).map((local) => ({ local, uri: output.uri })),
    ]);
    if (reply.response.status < 200 || reply.response.status >= 300)
      throw failure('EK_SOAP_SCHEMA');
    const responseHeaders: Record<string, string> = Object.create(null);
    const entries = Object.entries(reply.response.headers);
    if (entries.length > 128) throw failure('EK_SOAP_SCHEMA');
    for (const [name, value] of entries) {
      if (typeof value !== 'string' || value.length > 8192)
        throw failure('EK_UNSUPPORTED_CAPABILITY');
      responseHeaders[name] = value;
    }
    const context = {
      source: reply.body,
      parsed,
      status: reply.response.status,
      headers: Object.freeze(responseHeaders),
    };
    return {
      response: reply.response,
      deliver: () => {
        this.check();
        this.decode = context;
        try {
          callback(null, reply.response, reply.body);
        } finally {
          this.decode = undefined;
        }
      },
    };
  }
  private check() {
    if (this.closed || this.signal.aborted || !this.parser?.isOpen())
      throw failure('EK_RESOURCE_CLOSED');
    this.runtime.calls.check();
  }
  async call<T = unknown>(
    name: string,
    value: unknown,
    options?: OperationOptions,
  ): Promise<SoapResult<T>> {
    this.check();
    const binding = this.profile.bindings.find((entry) => entry.name === name);
    if (!binding) throw failure('EK_SOAP_SCHEMA');
    return this.runtime.calls.run(
      options,
      (call) =>
        this.owned(async () => {
          const data = input(value, this.runtime.settings.maxInputBytes);
          const secrets = await credentials(
            this.runtime.settings,
            this.profile.setting,
            call.options(),
          );
          const requested = {};
          try {
            call.check();
            this.installSecurity(secrets);
            this.tagged.set(requested, { call, secrets });
            const result = await new Promise<SoapResult<T>>((resolve, reject) => {
              const instance = this.nativeInstance!,
                namespace = instance[binding.service]?.[binding.port],
                method: SoapMethod | undefined = namespace?.[binding.name];
              if (typeof method !== 'function') return reject(failure('EK_SOAP_WSDL'));
              method(
                data,
                (error: unknown, result: T) => {
                  if (error) return reject(safeFailure(error, call));
                  try {
                    call.check();
                    const receipt = this.decode;
                    if (!receipt) throw failure('EK_BACKEND_UNAVAILABLE');
                    resolve(
                      Object.freeze({
                        data: result,
                        headers: receipt.headers,
                        status: receipt.status,
                        correlationId: call.id,
                      }),
                    );
                  } catch (error) {
                    reject(error);
                  }
                },
                requested,
              );
            });
            call.check();
            return result;
          } finally {
            this.tagged.delete(requested);
            secrets.clear();
          }
        }),
      this.signal,
    );
  }
  describe() {
    this.check();
    return Object.freeze({
      serviceId: this.profile.setting.id,
      protocol: this.profile.setting.protocol,
      operations: Object.freeze(this.profile.bindings.map((entry) => entry.name).sort()),
    });
  }
  native(): unknown {
    this.check();
    return this.nativeInstance;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.stop.abort();
    const cleanup = Promise.all([
      this.connection?.close(),
      this.parser?.close(),
      Promise.allSettled([...this.pending]),
    ]).then(() => {
      this.runtime.clients.delete(this);
    });
    this.closing = within(() => cleanup, { timeoutMs: this.runtime.settings.timeoutMs });
    void this.closing.catch(() => undefined);
    return this.closing;
  }
}
