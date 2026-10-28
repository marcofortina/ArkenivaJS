// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Metadata, ServerInterceptingCall, status } from '@grpc/grpc-js';
import type { ServerInterceptor, MethodDefinition } from '@grpc/grpc-js';
import type { AuthService, VerifiedTenantContext } from '@arkenivajs/core';
import { within, instrumentOperation } from '@arkenivajs/core/support';
import type { MtlsService, TlsProfile } from '@arkenivajs/security-mtls';
import type { GrpcPolicy, TrustedSecurityAuthority } from './contracts.js';
import { failure } from './errors.js';
import { Observation, remoteTrace } from './observation.js';
import type { Observers } from './observation.js';

export interface MethodPolicy {
  readonly policy: GrpcPolicy;
  readonly definition: MethodDefinition<unknown, unknown>;
  readonly tlsProfile: TlsProfile;
}
export interface RpcContext {
  readonly signal: AbortSignal;
  readonly authenticatedTenant?: VerifiedTenantContext;
}

/** One native server interceptor also protects calls registered through the trusted escape hatch. */
export class RpcGate {
  readonly contexts = new WeakMap<Metadata, RpcContext>();
  readonly profiles = new Map<number, TlsProfile>();
  readonly methods = new Map<string, MethodPolicy>();
  private readonly active = new Set<AbortController>();
  private readonly perService = new Map<string, number>();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly trackers = new WeakMap<Metadata, (task: Promise<unknown>) => void>();
  private closed = false;
  constructor(
    private readonly mtls: MtlsService,
    private readonly auth: AuthService | undefined,
    private readonly authorize: TrustedSecurityAuthority['require'],
    private readonly maximum: number,
    private readonly timeoutMs: number,
    private readonly owner: AbortSignal,
    private readonly ready: () => boolean,
    private readonly observers: Observers = {},
  ) {}

  readonly interceptor: ServerInterceptor = (descriptor, call) => {
    const serviceKey = descriptor.path.slice(0, descriptor.path.lastIndexOf('/'));
    const controller = new AbortController(),
      signal = AbortSignal.any([controller.signal, this.owner]),
      selected = this.methods.get(descriptor.path);
    const observation = new Observation(
      this.observers,
      descriptor.requestStream ? 'native' : descriptor.responseStream ? 'serverStream' : 'unary',
      'server',
    );
    let finished = false,
      authorizing = false,
      reserved = false,
      working = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let completedCode: number = status.OK;
    const completedError = () =>
      failure(
        completedCode === status.DEADLINE_EXCEEDED
          ? 'EK_GRPC_DEADLINE'
          : completedCode === status.CANCELLED
            ? 'EK_ABORTED'
            : 'EK_GRPC_STATUS',
      );
    let endedResolve!: () => void;
    const ended = new Promise<void>((resolve) => {
      endedResolve = resolve;
    });
    const release = () => {
      if (!reserved || !finished || authorizing || working) return;
      reserved = false;
      this.active.delete(controller);
      observation.active(this.active.size);
      this.perService.set(serviceKey, Math.max(0, (this.perService.get(serviceKey) ?? 1) - 1));
    };
    const finish = (code = status.CANCELLED) => {
      if (finished) return;
      finished = true;
      completedCode = code;
      if (timer) clearTimeout(timer);
      controller.abort();
      endedResolve();
      release();
      observation.finish(code, this.active.size);
    };
    const deny = (code: number) => {
      if (finished) return;
      finish(code);
      call.sendStatus({
        code,
        details:
          code === status.UNAUTHENTICATED
            ? 'The gRPC request could not be authenticated'
            : 'The gRPC request could not be completed',
      });
    };
    signal.addEventListener('abort', () => deny(status.CANCELLED), { once: true });
    return new ServerInterceptingCall(call, {
      start: (next) =>
        next({
          onReceiveMetadata: (metadata, forward) => {
            if (this.closed || !this.ready() || signal.aborted) return deny(status.UNAVAILABLE);
            if (!selected) return deny(status.PERMISSION_DENIED);
            if (
              this.active.size >= this.maximum ||
              (this.perService.get(serviceKey) ?? 0) >= selected.policy.concurrencyLimit
            )
              return deny(status.RESOURCE_EXHAUSTED);
            const deadline = call.getDeadline(),
              milliseconds = deadline instanceof Date ? deadline.getTime() : deadline;
            const remaining = Math.min(this.timeoutMs, milliseconds - Date.now());
            if (remaining <= 0) return deny(status.DEADLINE_EXCEEDED);
            reserved = true;
            authorizing = true;
            this.active.add(controller);
            observation.active(this.active.size);
            this.perService.set(serviceKey, (this.perService.get(serviceKey) ?? 0) + 1);
            timer = setTimeout(() => deny(status.DEADLINE_EXCEEDED), remaining);
            this.trackers.set(metadata, (task) => {
              working++;
              this.pending.add(task);
              void task
                .then(
                  () => undefined,
                  () => undefined,
                )
                .finally(() => {
                  working--;
                  this.pending.delete(task);
                  release();
                });
            });
            const task = remoteTrace(this.observers, metadata, () =>
              instrumentOperation(
                this.observers.telemetry,
                'grpc.server',
                {
                  'grpc.operation': descriptor.requestStream
                    ? 'native'
                    : descriptor.responseStream
                      ? 'serverStream'
                      : 'unary',
                  'grpc.side': 'server',
                },
                async () => {
                  try {
                    const context = call.getAuthContext(),
                      certificate = context.sslPeerCertificate?.raw,
                      profile = this.profiles.get(call.getConnectionInfo().localPort ?? -1);
                    if (
                      context.transportSecurityType !== 'ssl' ||
                      !certificate?.length ||
                      !profile ||
                      profile !== selected.tlsProfile
                    )
                      throw failure();
                    const options = { timeoutMs: Math.max(1, Math.ceil(remaining)), signal };
                    await this.mtls.verifyPeer(
                      certificate,
                      {
                        trustRootsRef: profile.trustRootsRef,
                        allowedIdentities: profile.allowedIdentities,
                        revocation: profile.revocation,
                      },
                      options,
                    );
                    const values = metadata.get('authorization');
                    if (values.length > 1 || (values.length && typeof values[0] !== 'string'))
                      throw failure();
                    let authenticatedTenant: VerifiedTenantContext | undefined;
                    if (selected.policy.requireAuthentication || values.length) {
                      if (!this.auth) throw failure();
                      const identity = await this.auth.verifyBearer(
                        values[0] as string | undefined,
                        options,
                      );
                      authenticatedTenant = this.auth.tenantFrom(identity);
                    }
                    for (const key of Object.keys(metadata.getMap())) {
                      if (/tenant/i.test(key) && !['authorization'].includes(key)) throw failure();
                    }
                    const subject = authenticatedTenant
                      ? {
                          issuer: authenticatedTenant.identity.issuer,
                          subject: authenticatedTenant.identity.subject,
                          tenant: authenticatedTenant,
                        }
                      : undefined;
                    const decision = await this.authorize(
                      'grpc:' + descriptor.path,
                      subject,
                      authenticatedTenant ? { tenant: authenticatedTenant } : {},
                      options,
                    );
                    if (
                      !decision ||
                      typeof decision.issuer !== 'string' ||
                      !decision.issuer ||
                      typeof decision.subject !== 'string' ||
                      !decision.subject ||
                      (subject &&
                        (decision.issuer !== subject.issuer ||
                          decision.subject !== subject.subject ||
                          !decision.tenant ||
                          decision.tenant.tenantId !== subject.tenant.tenantId ||
                          this.auth?.tenantFrom(decision.tenant.identity) !== decision.tenant))
                    )
                      throw failure();
                    if (signal.aborted || finished) throw completedError();
                    this.contexts.set(
                      metadata,
                      Object.freeze({
                        signal,
                        ...(authenticatedTenant ? { authenticatedTenant } : {}),
                      }),
                    );
                    forward(metadata);
                    await ended;
                    if (completedCode !== status.OK) throw completedError();
                  } catch {
                    throw finished ? completedError() : failure();
                  }
                },
                () => undefined,
              ),
            );
            this.pending.add(task);
            void task
              .then(
                () => undefined,
                () => deny(status.UNAUTHENTICATED),
              )
              .finally(() => {
                authorizing = false;
                this.pending.delete(task);
                release();
              });
          },
          onCancel: () => finish(),
          onReceiveMessage: (message, forward) => {
            try {
              if (!selected || signal.aborted) return deny(status.CANCELLED);
              const bytes = selected.definition.requestSerialize(message);
              observation.requestBytes += bytes.length;
              if (bytes.length > selected.policy.maxInboundBytes)
                return deny(status.RESOURCE_EXHAUSTED);
              forward(selected.definition.requestDeserialize(bytes));
            } catch {
              deny(status.INVALID_ARGUMENT);
            }
          },
        }),
      sendMessage: (message, next) => {
        try {
          if (!selected || signal.aborted) return deny(status.CANCELLED);
          const bytes = selected.definition.responseSerialize(message);
          observation.responseBytes += bytes.length;
          if (bytes.length > selected.policy.maxOutboundBytes)
            return deny(status.RESOURCE_EXHAUSTED);
          next(selected.definition.responseDeserialize(bytes));
        } catch {
          deny(status.INTERNAL);
        }
      },
      sendStatus: (result, next) => {
        finish(result.code ?? status.UNKNOWN);
        next(result);
      },
    });
  };
  track(metadata: Metadata, task: Promise<unknown>): void {
    this.trackers.get(metadata)?.(task);
  }
  async close(): Promise<void> {
    this.closed = true;
    for (const controller of this.active) controller.abort();
    await within(() => Promise.allSettled([...this.pending]), { timeoutMs: this.timeoutMs });
  }
}
