import { AsyncLocalStorage } from 'node:async_hooks';
import { InterceptingCall, status } from '@grpc/grpc-js';
import type { CallOptions, Interceptor } from '@grpc/grpc-js';
import { Etcd3, GRPCCancelledError, GRPCDeadlineExceededError } from 'etcd3';
import { NoopPolicy } from 'cockatiel';
import type { IDefaultPolicyContext } from 'cockatiel';
import { KitError } from '@arkenivajs/core';
import type { EtcdConfiguration } from './config.js';
import { ETCD_LIMITS } from './limits.js';

/** One portable call owns its cancellation and records whether native submission began. */
export interface EtcdCallScope {
  readonly signal: AbortSignal;
  readonly timeoutMs: number;
  submitted: boolean;
}

/** Prevent an owned call cancellation from triggering the SDK's host-wide service reset. */
class CancellationPolicy extends NoopPolicy {
  constructor(private readonly current: () => EtcdCallScope | undefined) {
    super();
  }

  override async execute<T>(
    work: (context: IDefaultPolicyContext) => PromiseLike<T> | T,
    signal?: AbortSignal,
  ): Promise<T> {
    try {
      return await super.execute(work, signal);
    } catch (cause) {
      const scope = this.current();
      if (
        scope &&
        (cause instanceof GRPCDeadlineExceededError ||
          (scope.signal.aborted && cause instanceof GRPCCancelledError))
      ) {
        const timeout =
          cause instanceof GRPCDeadlineExceededError ||
          (scope.signal.reason instanceof KitError && scope.signal.reason.code === 'EK_TIMEOUT');
        throw new KitError({
          code: timeout ? 'EK_TIMEOUT' : 'EK_ABORTED',
          message: timeout ? 'etcd operation timed out' : 'etcd operation aborted',
          cause,
        });
      }
      throw cause;
    }
  }
}

/** Use public gRPC CallOptions supplied through etcd3; no protocol stubs or native fields are replaced. */
export function etcdCallOptions(scope: EtcdCallScope): CallOptions {
  const interceptor: Interceptor = (options, nextCall) => {
    const call = new InterceptingCall(nextCall(options), {
      start(metadata, _listener, next) {
        const abort = () => call.cancelWithStatus(status.CANCELLED, 'etcd operation cancelled');
        const detach = () => scope.signal.removeEventListener('abort', abort);
        scope.signal.addEventListener('abort', abort, { once: true });
        scope.submitted = true;
        try {
          next(metadata, {
            onReceiveStatus(value, forward) {
              detach();
              forward(value);
            },
          });
          if (scope.signal.aborted) abort();
        } catch (cause) {
          detach();
          throw cause;
        }
      },
    });
    return call;
  };
  return {
    // Very large budgets use the monotonic owner and cancellation rather than imprecise Date arithmetic.
    ...(scope.timeoutMs <= 2_147_483_647 ? { deadline: Date.now() + scope.timeoutMs } : {}),
    interceptors: [interceptor],
  };
}

/** The actual selected SDK owns authentication, protobuf conversion, channels and host selection. */
export class EtcdTransport {
  readonly client: Etcd3;
  private readonly scopes = new AsyncLocalStorage<EtcdCallScope>();

  constructor(configuration: EtcdConfiguration, lifetime: AbortSignal) {
    const cancellation = new CancellationPolicy(() => this.scopes.getStore());
    this.client = new Etcd3({
      ...configuration.native,
      faultHandling: { ...configuration.native.faultHandling, host: () => cancellation },
      defaultCallOptions: ({ isStream }) => {
        const scope = isStream ? undefined : this.scopes.getStore();
        return etcdCallOptions(
          scope ?? {
            signal: lifetime,
            timeoutMs: isStream ? Number.MAX_SAFE_INTEGER : ETCD_LIMITS.timeoutMs,
            submitted: false,
          },
        );
      },
    });
  }

  /** Async-local call ownership does not modify another concurrent operation's cancellation policy. */
  run<T>(scope: EtcdCallScope, work: () => Promise<T>): Promise<T> {
    if (scope.signal.aborted)
      return Promise.reject(
        new KitError({
          code: 'EK_ABORTED',
          message: 'etcd operation aborted',
          cause: scope.signal.reason,
        }),
      );
    return this.scopes.run(scope, work);
  }
}
