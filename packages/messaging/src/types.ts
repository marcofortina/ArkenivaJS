import type {
  KitError,
  Logger,
  MessageBus,
  MessageEnvelope,
  OperationOptions,
  Telemetry,
  UsageMeter,
} from '@arkenivajs/core';

/** Trusted application error policy receives internal causes; never expose them to message publishers. */
export interface MessageFailure {
  readonly kind: 'handler' | 'wire' | 'overflow' | 'subscription' | 'connection';
  readonly error: KitError;
  readonly topic?: string;
  readonly message?: MessageEnvelope<unknown>;
}

export interface NatsBusOptions {
  /** Resolve a private TLS URL only during explicit startup. Defaults to NATS_URL. */
  readonly connectionStringEnv?: string;
  /** Required bounded error/dead-letter strategy; rejection makes the bus unhealthy. */
  readonly onError: (failure: MessageFailure, options: OperationOptions) => Promise<void>;
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}

/** Numeric observations never include subjects, payloads, credentials or tenant identities. */
export interface MessageBusStats {
  readonly connected: boolean;
  readonly subscriptions: number;
  readonly pendingPublications: number;
  readonly retainedBytes: number;
  readonly queuedMessages: number;
  readonly activeHandlers: number;
  readonly published: number;
  readonly received: number;
  readonly failed: number;
  readonly dropped: number;
  readonly observerFailures: number;
}

/** The portable public declarations deliberately carry no native SDK implementation types. */
export interface ManagedMessageBus extends MessageBus {
  health(options?: OperationOptions): Promise<boolean>;
  close(options?: OperationOptions): Promise<void>;
  stats(): Readonly<MessageBusStats>;
}
