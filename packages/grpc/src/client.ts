// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  Client,
  Metadata,
  makeGenericClientConstructor,
  InterceptingCall,
  connectivityState,
  status,
} from '@grpc/grpc-js';
import type {
  ServiceDefinition,
  ClientUnaryCall,
  ClientReadableStream,
  Interceptor,
  ServiceError,
} from '@grpc/grpc-js';
import type { GrpcClient, GrpcCallOptions } from './contracts.js';
import { operation } from './settings.js';
import { failure } from './errors.js';
import { instrumentOperation } from '@arkenivajs/core/support';
import { Observation, injectTrace } from './observation.js';
import type { Observers } from './observation.js';

function translated(error: ServiceError) {
  return failure(
    error.code === status.DEADLINE_EXCEEDED
      ? 'EK_GRPC_DEADLINE'
      : error.code === status.CANCELLED
        ? 'EK_ABORTED'
        : error.code === status.UNAUTHENTICATED || error.code === status.PERMISSION_DENIED
          ? 'EK_GRPC_AUTH'
          : 'EK_GRPC_STATUS',
  );
}
export class ManagedClient implements GrpcClient {
  readonly nativeClient: Client;
  private closed = false;
  private reservations = 0;
  private readonly active = new Set<ClientUnaryCall | ClientReadableStream<unknown>>();
  constructor(
    endpoint: string,
    credentials: ConstructorParameters<typeof Client>[1],
    private readonly service: ServiceDefinition,
    private readonly timeoutMs: number,
    private readonly maximum: number,
    private readonly owner: AbortSignal,
    private readonly ready: () => boolean,
    maxBytes: number,
    private readonly observers: Observers = {},
  ) {
    const permitted = new Map(Object.values(service).map((method) => [method.path, method]));
    const interceptor: Interceptor = (options, next) => {
      this.check();
      if (!permitted.has(options.method_definition.path)) throw failure('EK_CONFIG_INVALID');
      if (this.reservations >= maximum) throw failure('EK_BACKEND_UNAVAILABLE');
      const requested =
        options.deadline instanceof Date
          ? options.deadline.getTime()
          : (options.deadline ?? Infinity);
      if (Number.isNaN(requested)) throw failure('EK_CONFIG_INVALID');
      this.reservations++;
      const codec = permitted.get(options.method_definition.path)!,
        observation = new Observation(
          observers,
          codec.requestStream ? 'native' : codec.responseStream ? 'serverStream' : 'unary',
          'client',
        );
      let reserved = true;
      const release = () => {
        if (reserved) {
          reserved = false;
          this.reservations--;
        }
      };
      try {
        const active = new InterceptingCall(
          next({ ...options, deadline: Math.min(requested, Date.now() + timeoutMs) }),
          {
            start: (metadata, listener, forward) =>
              forward(injectTrace(observers, metadata), {
                onReceiveStatus: (result, receive) => {
                  release();
                  observation.finish(result.code, this.reservations);
                  receive(result);
                },
                onReceiveMessage: (value, receive) => {
                  try {
                    if (value !== null)
                      observation.responseBytes += codec.responseSerialize(value).length;
                    receive(value);
                  } catch {
                    active.cancelWithStatus(status.INTERNAL, 'The gRPC response is invalid');
                    receive(null);
                  }
                },
              }),
            sendMessage: (value, forward) => {
              try {
                const bytes = codec.requestSerialize(value);
                observation.requestBytes += bytes.length;
                forward(codec.requestDeserialize(bytes));
              } catch {
                active.cancelWithStatus(status.INVALID_ARGUMENT, 'The gRPC request is invalid');
              }
            },
          },
        );
        return active;
      } catch (error) {
        release();
        throw error;
      }
    };
    const Native = makeGenericClientConstructor(service, 'OwnedGrpcClient');
    this.nativeClient = new Native(endpoint, credentials, {
      'grpc.max_receive_message_length': maxBytes,
      'grpc.max_send_message_length': maxBytes,
      'grpc.enable_retries': 0,
      'grpc.enable_http_proxy': 0,
      'grpc.service_config_disable_resolution': 1,
      'grpc.use_local_subchannel_pool': 1,
      'grpc-node.max_session_memory': 64,
      'grpc.keepalive_permit_without_calls': 0,
      'grpc.keepalive_time_ms': 60000,
      'grpc.keepalive_timeout_ms': 10000,
      interceptors: [interceptor],
    });
  }
  private check(): void {
    if (this.closed || this.owner.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (this.nativeClient.getChannel().getConnectivityState(false) === connectivityState.SHUTDOWN)
      throw failure('EK_RESOURCE_CLOSED');
    if (!this.ready()) throw failure('EK_LIFECYCLE_STATE');
  }
  private prepare(
    method: string,
    input: unknown,
    options: GrpcCallOptions | undefined,
    stream: boolean,
  ) {
    const captured = operation(options, this.timeoutMs);
    this.check();
    const definition = Object.hasOwn(this.service, method) ? this.service[method] : undefined;
    if (!definition || definition.requestStream || definition.responseStream !== stream)
      throw failure('EK_UNSUPPORTED_CAPABILITY');
    if (this.active.size >= this.maximum) throw failure('EK_BACKEND_UNAVAILABLE');
    const signal = AbortSignal.any([this.owner, ...(captured.signal ? [captured.signal] : [])]);
    if (signal.aborted) throw failure('EK_ABORTED');
    const bytes = definition.requestSerialize(input),
      owned = definition.requestDeserialize(bytes),
      metadata = new Metadata();
    for (const [key, value] of Object.entries(captured.metadata)) metadata.set(key, value);
    return { definition, owned, metadata, signal, deadline: Date.now() + captured.timeoutMs };
  }
  async unary<T = unknown>(method: string, input: unknown, options?: GrpcCallOptions): Promise<T> {
    const call = this.prepare(method, input, options, false);
    return instrumentOperation(
      this.observers.telemetry,
      'grpc.unary',
      { 'grpc.operation': 'unary', 'grpc.side': 'client' },
      () =>
        new Promise<T>((resolve, reject) => {
          const active = this.nativeClient.makeUnaryRequest(
            call.definition.path,
            call.definition.requestSerialize,
            call.definition.responseDeserialize,
            call.owned,
            call.metadata,
            { deadline: call.deadline },
            (error, value) => {
              this.active.delete(active);
              call.signal.removeEventListener('abort', abort);
              if (error) reject(translated(error));
              else resolve(value as T);
            },
          );
          const abort = () => active.cancel();
          this.active.add(active);
          call.signal.addEventListener('abort', abort, { once: true });
          if (call.signal.aborted) abort();
        }),
      () => undefined,
    );
  }
  async *serverStream<T = unknown>(
    method: string,
    input: unknown,
    options?: GrpcCallOptions,
  ): AsyncIterable<T> {
    const call = this.prepare(method, input, options, true),
      active = this.nativeClient.makeServerStreamRequest(
        call.definition.path,
        call.definition.requestSerialize,
        call.definition.responseDeserialize,
        call.owned,
        call.metadata,
        { deadline: call.deadline },
      );
    this.active.add(active);
    const abort = () => active.cancel();
    const completed = new Promise<void>((resolve) =>
      active.once('status', () => {
        this.active.delete(active);
        resolve();
      }),
    );
    active.on('error', () => undefined);
    call.signal.addEventListener('abort', abort, { once: true });
    if (call.signal.aborted) abort();
    try {
      for await (const value of active) yield value as T;
    } catch (error) {
      throw translated(error as ServiceError);
    } finally {
      active.cancel();
      call.signal.removeEventListener('abort', abort);
      await completed;
    }
  }
  native(): unknown {
    this.check();
    return this.nativeClient;
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const call of this.active) call.cancel();
    this.nativeClient.close();
  }
}
