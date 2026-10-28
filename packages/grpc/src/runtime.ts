// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Server, status } from '@grpc/grpc-js';
import type {
  ServiceDefinition,
  MethodDefinition,
  ServerUnaryCall,
  ServerWritableStream,
  sendUnaryData,
  UntypedServiceImplementation,
} from '@grpc/grpc-js';
import type { AuthService } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { MtlsService } from '@arkenivajs/security-mtls';
import type { GrpcService, GrpcClient, GrpcHandler, GrpcPolicy } from './contracts.js';
import { policy as capturePolicy, handlers as captureHandlers } from './settings.js';
import type { Settings } from './settings.js';
import { loadDescriptor, messageTypes } from './descriptor.js';
import { ownMessage } from './message.js';
import { RpcGate } from './gate.js';
import { clientCredentials, serverCredentials } from './tls.js';
import { ManagedClient } from './client.js';
import { failure } from './errors.js';
import type { Observers } from './observation.js';

type Profile = Settings['services'][number];
interface Service {
  readonly profile: Profile;
  readonly definition: ServiceDefinition;
}

export class Runtime implements GrpcService {
  private readonly server: Server;
  private readonly gate: RpcGate;
  private readonly services = new Map<string, Service>();
  private readonly clients = new Map<string, ManagedClient>();
  private readonly facades = new Map<string, GrpcClient>();
  private readonly stop = new AbortController();
  private readonly signal: AbortSignal;
  private readonly add: Server['addService'];
  private readonly bind: Server['bindAsync'];
  private frozen = false;
  private closed = false;
  private closing: Promise<void> | undefined;
  constructor(
    private readonly settings: Settings,
    private readonly mtls: MtlsService,
    private readonly auth: AuthService | undefined,
    owner: AbortSignal,
    private readonly ready: () => boolean,
    private readonly observers: Observers = {},
  ) {
    this.signal = AbortSignal.any([owner, this.stop.signal]);
    this.gate = new RpcGate(
      mtls,
      auth,
      settings.require,
      settings.maxConcurrent,
      settings.timeoutMs,
      this.signal,
      ready,
      observers,
    );
    this.server = new Server({
      'grpc.max_receive_message_length': settings.maxInputBytes,
      'grpc.max_send_message_length': settings.maxOutputBytes,
      'grpc.max_concurrent_streams': settings.maxConcurrent,
      'grpc-node.max_session_memory': 64,
      'grpc.keepalive_time_ms': 60000,
      'grpc.keepalive_timeout_ms': 10000,
      'grpc.keepalive_permit_without_calls': 0,
      'grpc.max_connection_idle_ms': 60000,
      interceptors: [this.gate.interceptor],
    });
    this.add = this.server.addService.bind(this.server);
    this.bind = this.server.bindAsync.bind(this.server);
    this.server.addService = (definition, implementation) => {
      this.registration();
      const owned: Record<string, MethodDefinition<unknown, unknown>> = {};
      for (const [method, descriptor] of Object.entries(definition)) {
        const selected = this.gate.methods.get(descriptor.path);
        if (!selected) throw failure('EK_CONFIG_INVALID');
        owned[method] = selected.definition;
      }
      this.add(owned, implementation);
    };
    this.server.bindAsync = () => {
      throw failure('EK_LIFECYCLE_STATE');
    };
    for (const method of ['register', 'unregister', 'removeService'] as const) {
      const native = this.server[method].bind(this.server);
      Object.defineProperty(this.server, method, {
        value: (...args: unknown[]) => {
          this.registration();
          return Reflect.apply(native, this.server, args);
        },
        writable: false,
      });
    }
  }
  private registration(): void {
    if (this.closed || this.signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (this.frozen || this.ready()) throw failure('EK_LIFECYCLE_STATE');
  }
  async initialize(): Promise<void> {
    const loaded = new Map<string, Awaited<ReturnType<typeof loadDescriptor>>>();
    for (const profile of this.settings.services) {
      let definition = loaded.get(profile.descriptorFile);
      if (!definition) {
        definition = await loadDescriptor(
          profile.descriptorFile,
          this.settings.timeoutMs,
          this.signal,
        );
        loaded.set(profile.descriptorFile, definition);
      }
      const candidates = Object.entries(definition).filter(([, value]) => !('format' in value));
      const selected =
        candidates.find(([name]) => name === profile.name) ??
        (candidates.length === 1 ? candidates[0] : undefined);
      if (!selected) throw failure('EK_CONFIG_INVALID');
      const service: Record<string, MethodDefinition<unknown, unknown>> = {};
      for (const method of profile.allowedMethods) {
        const original = (selected[1] as ServiceDefinition)[method];
        if (!original) throw failure('EK_CONFIG_INVALID');
        const types = messageTypes(original),
          inbound = Math.min(profile.maxMessageBytes, this.settings.maxInputBytes),
          outbound = Math.min(profile.maxMessageBytes, this.settings.maxOutputBytes);
        const codec =
          (type: typeof types.request, native: (value: unknown) => Buffer, maximum: number) =>
          (value: unknown) => {
            const result = native(ownMessage(type, value, maximum));
            if (result.length > maximum) throw failure('EK_GRPC_STATUS');
            return result;
          };
        service[method] = Object.freeze({
          ...original,
          requestSerialize: codec(types.request, original.requestSerialize, inbound),
          responseSerialize: codec(types.response, original.responseSerialize, outbound),
          requestDeserialize: (bytes: Buffer) => {
            if (bytes.length > inbound) throw failure('EK_GRPC_STATUS');
            return ownMessage(types.request, original.requestDeserialize(bytes), inbound);
          },
          responseDeserialize: (bytes: Buffer) => {
            if (bytes.length > outbound) throw failure('EK_GRPC_STATUS');
            return ownMessage(types.response, original.responseDeserialize(bytes), outbound);
          },
        });
      }
      this.services.set(profile.name, { profile, definition: Object.freeze(service) });
      if (profile.endpoint) {
        const url = new URL('https://' + profile.endpoint),
          tls = this.settings.tlsProfiles[profile.tlsProfile!];
        if (!tls) throw failure('EK_CONFIG_INVALID');
        this.clients.set(
          profile.name,
          new ManagedClient(
            profile.endpoint,
            await clientCredentials(this.mtls, tls, url.hostname, {
              signal: this.signal,
              timeoutMs: this.settings.timeoutMs,
            }),
            service,
            this.settings.timeoutMs,
            this.settings.maxConcurrent,
            this.signal,
            this.ready,
            profile.maxMessageBytes,
            this.observers,
          ),
        );
      }
    }
    for (const binding of this.settings.bindings)
      this.registerService(binding.descriptor, binding.handlers, binding.policy);
  }
  registerService(
    descriptor: string,
    input: Readonly<Record<string, GrpcHandler>>,
    inputPolicy: GrpcPolicy,
  ): void {
    this.registration();
    const selected = this.services.get(descriptor),
      handlers = captureHandlers(input),
      policy = capturePolicy(inputPolicy);
    if (!selected?.profile.listener) throw failure('EK_CONFIG_INVALID');
    if (policy.requireAuthentication && !this.auth) throw failure('EK_CONFIG_INVALID');
    const service: Record<string, MethodDefinition<unknown, unknown>> = {},
      implementation: UntypedServiceImplementation = {};
    for (const method of policy.methodAllowlist) {
      const definition = selected.definition[method];
      if (!definition || this.gate.methods.has(definition.path)) throw failure('EK_CONFIG_INVALID');
    }
    for (const [method, handler] of Object.entries(handlers)) {
      const definition = selected.definition[method];
      if (!definition || !policy.methodAllowlist.includes(method))
        throw failure('EK_CONFIG_INVALID');
      if (definition.requestStream) throw failure('EK_UNSUPPORTED_CAPABILITY');
      service[method] = definition;
      if (!definition.responseStream) {
        implementation[method] = (
          call: ServerUnaryCall<unknown, unknown>,
          callback: sendUnaryData<unknown>,
        ) => {
          const context = this.gate.contexts.get(call.metadata);
          if (!context)
            return callback({
              code: status.UNAUTHENTICATED,
              details: 'The gRPC request could not be authenticated',
            });
          const task = Promise.resolve()
            .then(() => handler(call.request, context))
            .then(
              (value) => {
                if (!context.signal.aborted) callback(null, value);
              },
              () => {
                if (!context.signal.aborted)
                  callback({ code: status.INTERNAL, details: 'The gRPC handler failed' });
              },
            );
          this.gate.track(call.metadata, task);
        };
      } else {
        implementation[method] = (call: ServerWritableStream<unknown, unknown>) => {
          const context = this.gate.contexts.get(call.metadata);
          const task = async () => {
            if (!context) throw failure();
            const result = await handler(call.request, context);
            if (!result || typeof result !== 'object' || !(Symbol.asyncIterator in result))
              throw failure('EK_GRPC_STATUS');
            for await (const value of result as AsyncIterable<unknown>) {
              if (context.signal.aborted) return;
              if (!call.write(value))
                await within(
                  () =>
                    new Promise<void>((resolve, reject) => {
                      const finish = () => {
                        call.off('drain', drain);
                        call.off('close', close);
                      };
                      const drain = () => {
                          finish();
                          resolve();
                        },
                        close = () => {
                          finish();
                          reject(failure('EK_ABORTED'));
                        };
                      call.once('drain', drain);
                      call.once('close', close);
                    }),
                  { signal: context.signal, timeoutMs: this.settings.timeoutMs },
                );
            }
            if (!context.signal.aborted) call.end();
          };
          const active = task().catch(() =>
            call.destroy(
              Object.assign(new Error('The gRPC stream failed'), { code: status.INTERNAL }),
            ),
          );
          this.gate.track(call.metadata, active);
        };
      }
    }
    for (const method of policy.methodAllowlist) {
      const definition = selected.definition[method]!;
      const inbound = Math.min(
          policy.maxInboundBytes,
          selected.profile.maxMessageBytes,
          this.settings.maxInputBytes,
        ),
        outbound = Math.min(
          policy.maxOutboundBytes,
          selected.profile.maxMessageBytes,
          this.settings.maxOutputBytes,
        );
      const bounded = Object.freeze({
        ...definition,
        requestDeserialize: (bytes: Buffer) => {
          if (bytes.length > inbound) throw failure('EK_GRPC_STATUS');
          return definition.requestDeserialize(bytes);
        },
        responseSerialize: (value: unknown) => {
          const bytes = definition.responseSerialize(value);
          if (bytes.length > outbound) throw failure('EK_GRPC_STATUS');
          return bytes;
        },
      });
      if (service[method]) service[method] = bounded;
      this.gate.methods.set(definition.path, {
        definition: bounded,
        policy,
        tlsProfile: this.settings.tlsProfiles[selected.profile.listener.tlsProfile]!,
      });
    }
    try {
      this.add(service, implementation);
    } catch {
      for (const method of policy.methodAllowlist)
        this.gate.methods.delete(selected.definition[method]!.path);
      throw failure('EK_CONFIG_INVALID');
    }
  }
  async activate(): Promise<void> {
    this.registration();
    this.frozen = true;
    const listeners = new Map<string, string>();
    for (const { profile } of this.services.values())
      if (profile.listener) {
        const listener = profile.listener,
          address = listener.host + ':' + listener.port;
        const previous = listeners.get(address);
        if (previous) {
          if (previous !== listener.tlsProfile) throw failure('EK_CONFIG_INVALID');
          continue;
        }
        listeners.set(address, listener.tlsProfile);
        const tls = this.settings.tlsProfiles[listener.tlsProfile];
        if (!tls) throw failure('EK_CONFIG_INVALID');
        const credentials = await serverCredentials(
          this.mtls,
          tls,
          {
            signal: this.signal,
            timeoutMs: this.settings.timeoutMs,
          },
          this.settings.maxConcurrent,
        );
        const port = await within(
          () =>
            new Promise<number>((resolve, reject) => {
              this.bind(address, credentials, (error, port) =>
                error ? reject(failure('EK_BACKEND_UNAVAILABLE')) : resolve(port),
              );
            }),
          { signal: this.signal, timeoutMs: this.settings.timeoutMs },
        );
        this.gate.profiles.set(port, tls);
      }
  }
  client(serviceName: string): GrpcClient {
    if (this.closed || this.signal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!this.ready()) throw failure('EK_LIFECYCLE_STATE');
    const client = this.clients.get(serviceName);
    if (!client) throw failure('EK_CONFIG_INVALID');
    let facade = this.facades.get(serviceName);
    if (!facade) {
      facade = Object.freeze({
        unary: client.unary.bind(client),
        serverStream: client.serverStream.bind(client),
        native: client.native.bind(client),
      });
      this.facades.set(serviceName, facade);
    }
    return facade;
  }
  nativeServer(): unknown {
    if (this.closed) throw failure('EK_RESOURCE_CLOSED');
    return this.server;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.stop.abort();
    for (const client of this.clients.values()) client.close();
    this.closing = (async () => {
      try {
        await within(
          () =>
            new Promise<void>((resolve, reject) =>
              this.server.tryShutdown((error) =>
                error ? reject(failure('EK_BACKEND_UNAVAILABLE')) : resolve(),
              ),
            ),
          { timeoutMs: this.settings.timeoutMs },
        );
      } finally {
        this.server.forceShutdown();
        await this.gate.close();
      }
    })();
    return this.closing;
  }
}
