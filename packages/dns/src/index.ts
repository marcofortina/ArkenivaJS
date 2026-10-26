// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { KitError, COMPONENTS } from '@arkenivajs/core';
import type { Logger, OperationOptions, Plugin, Telemetry } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import {
  capture,
  fields,
  failure,
  hostname,
  integer,
  normalize,
  recordTypes,
  safeFailure,
  text,
  array,
} from './validation.js';
import type { Captured } from './validation.js';
import type {
  DnsLookupResult,
  DnsPluginSettings,
  DnsRecordMap,
  DnsRecordType,
  DnsService,
} from './contracts.js';
export type * from './contracts.js';

interface Observation {
  readonly logger: Logger | undefined;
  readonly telemetry: Telemetry | undefined;
}
const OBSERVATION = Symbol('dns.observation');
const observations: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((plugin) => plugin.capabilities.has('logger')),
    telemetry = options.plugins?.find((plugin) => plugin.capabilities.has('telemetry'));
  return {
    id: 'dns-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set(
        [logger?.id, telemetry?.id].filter((value): value is string => value !== undefined),
      ),
    ],
    init(context) {
      context.provide<Observation>(OBSERVATION, {
        logger: logger ? context.require(COMPONENTS.logger) : undefined,
        telemetry: telemetry ? context.require(COMPONENTS.telemetry) : undefined,
      });
    },
    close() {},
  };
};
function service(setting: Captured, observation?: Observation): DnsService {
  const clients = new Map<string, InstanceType<typeof dns.Resolver>>(),
    active = new Set<{ cancel(): void }>();
  let closed = false;
  try {
    for (const profile of setting.resolvers) {
      const client = new dns.Resolver({ timeout: setting.timeoutMs, tries: 1 });
      client.setServers([...profile.servers]);
      clients.set(profile.name, client);
    }
  } catch {
    for (const client of clients.values()) client.cancel();
    throw failure('EK_DNS_CONFIG');
  }
  const ready = () => {
    if (closed) throw failure('EK_RESOURCE_CLOSED');
  };
  const dropped = () => {
    try {
      void Promise.resolve(observation?.telemetry?.addCounter('dns.observation.dropped', 1)).catch(
        () => undefined,
      );
    } catch {
      /* A failed observer cannot recursively report its own failure. */
    }
  };
  const safe = (action: () => unknown) => {
    try {
      const result = action();
      if (result !== undefined) void Promise.resolve(result).catch(dropped);
    } catch {
      dropped();
    }
  };
  const gauge = () => {
    if (observation?.telemetry)
      safe(() => observation.telemetry!.setGauge('dns.inflight', active.size));
  };
  const observe = (
    operation: string,
    type: string,
    profile: string,
    started: number,
    outcome: string,
    count: number,
  ) => {
    const attributes = Object.freeze({
        'dns.operation': operation,
        'dns.type': type,
        'dns.resolver': profile,
        'dns.outcome': outcome,
      }),
      duration = Math.max(0, performance.now() - started);
    if (observation?.telemetry) {
      safe(() => observation.telemetry!.addCounter('dns.operation.count', 1, attributes));
      safe(() => observation.telemetry!.recordHistogram('dns.duration.ms', duration, attributes));
      safe(() => observation.telemetry!.addCounter('dns.response.records', count, attributes));
    }
    if (observation?.logger)
      safe(() =>
        observation.logger!.debug('dns.operation.complete', {
          ...attributes,
          durationMs: duration,
          responseCount: count,
        }),
      );
  };
  const operationOptions = (input?: OperationOptions) => {
    try {
      const options = fields(input === undefined ? {} : input, ['signal', 'timeoutMs']),
        timeoutMs =
          options.timeoutMs === undefined
            ? setting.timeoutMs
            : Math.min(integer(options.timeoutMs, 1, 120000), setting.timeoutMs);
      const signal =
        options.signal === undefined ? undefined : AbortSignal.any([options.signal as AbortSignal]);
      return { timeoutMs, signal };
    } catch {
      throw failure('EK_DNS_CONFIG');
    }
  };
  const invoke = <T>(
    operation: string,
    type: string,
    profile: string,
    options: OperationOptions | undefined,
    work: () => Promise<readonly T[]>,
  ): Promise<readonly T[]> => {
    ready();
    const policy = operationOptions(options);
    if (policy.signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
    if (active.size >= setting.maxConcurrency) return Promise.reject(failure('EK_DNS_TEMPORARY'));
    const started = performance.now(),
      deadline = started + policy.timeoutMs;
    return new Promise((resolve, reject) => {
      let completed = false;
      const finish = (value?: readonly T[], error?: KitError) => {
        if (completed) return;
        completed = true;
        clearTimeout(timer);
        policy.signal?.removeEventListener('abort', abort);
        observe(operation, type, profile, started, error?.code ?? 'ok', value?.length ?? 0);
        if (error) reject(error);
        else resolve(value!);
      };
      const abort = () => finish(undefined, failure('EK_ABORTED')),
        task = { cancel: abort };
      const timer = setTimeout(
        () => finish(undefined, failure('EK_DNS_TIMEOUT')),
        policy.timeoutMs,
      );
      policy.signal?.addEventListener('abort', abort, { once: true });
      active.add(task);
      gauge();
      if (policy.signal?.aborted) abort();
      Promise.resolve()
        .then(() => {
          if (completed || closed) throw failure('EK_ABORTED');
          return work();
        })
        .then(
          (value) => {
            active.delete(task);
            gauge();
            if (performance.now() >= deadline) finish(undefined, failure('EK_DNS_TIMEOUT'));
            else finish(value);
          },
          (cause) => {
            active.delete(task);
            gauge();
            finish(
              undefined,
              performance.now() >= deadline ? failure('EK_DNS_TIMEOUT') : safeFailure(cause),
            );
          },
        );
    });
  };
  const profile = (input: unknown) => {
    const name = input === undefined ? setting.defaultResolver : text(input, 63),
      client = clients.get(name);
    if (!client) throw failure('EK_DNS_CONFIG');
    return { name, client };
  };
  const native = (
    client: InstanceType<typeof dns.Resolver>,
    name: string,
    type: DnsRecordType,
  ): Promise<unknown> => {
    switch (type) {
      case 'A':
        return client.resolve4(name, { ttl: true });
      case 'AAAA':
        return client.resolve6(name, { ttl: true });
      case 'CNAME':
        return client.resolveCname(name);
      case 'MX':
        return client.resolveMx(name);
      case 'NS':
        return client.resolveNs(name);
      case 'PTR':
        return client.resolvePtr(name);
      case 'SOA':
        return client.resolveSoa(name);
      case 'SRV':
        return client.resolveSrv(name);
      case 'TXT':
        return client.resolveTxt(name);
      case 'CAA':
        return client.resolveCaa(name);
      case 'NAPTR':
        return client.resolveNaptr(name);
    }
  };
  const validate = <T>(action: () => T): T => {
    ready();
    try {
      return action();
    } catch {
      throw failure('EK_DNS_CONFIG');
    }
  };
  return Object.freeze({
    async resolve<T extends DnsRecordType>(
      query: Readonly<{ hostname: string; type: T; resolver?: string }>,
      options?: OperationOptions,
    ): Promise<readonly DnsRecordMap[T][]> {
      const captured = validate(() => {
        const input = fields(query, ['hostname', 'type', 'resolver']);
        if (!recordTypes.includes(input.type as DnsRecordType)) throw failure('EK_DNS_CONFIG');
        return {
          hostname: hostname(input.hostname),
          type: input.type as T,
          ...profile(input.resolver),
        };
      });
      return invoke('resolve', captured.type, captured.name, options, async () => {
        try {
          return normalize(
            captured.type,
            await native(captured.client, captured.hostname, captured.type),
          );
        } catch (cause) {
          if (cause instanceof KitError) throw failure('EK_DNS_TEMPORARY');
          throw cause;
        }
      });
    },
    async lookup(
      name: string,
      query?: Readonly<{ family?: 0 | 4 | 6; all?: boolean }>,
      options?: OperationOptions,
    ): Promise<readonly DnsLookupResult[]> {
      const captured = validate(() => {
        const input = fields(query === undefined ? {} : query, ['family', 'all']);
        if (
          (input.family !== undefined && ![0, 4, 6].includes(input.family as number)) ||
          (input.all !== undefined && typeof input.all !== 'boolean')
        )
          throw failure('EK_DNS_CONFIG');
        return {
          hostname: hostname(name, true),
          family: input.family === undefined ? 0 : (input.family as 0 | 4 | 6),
          all: input.all === true,
        };
      });
      return invoke('lookup', 'OS', 'os', options, async () => {
        const result = captured.all
          ? await dns.lookup(captured.hostname, { family: captured.family, all: true })
          : await dns.lookup(captured.hostname, { family: captured.family, all: false });
        try {
          return Object.freeze(
            array(Array.isArray(result) ? result : [result], 1024).map((value) => {
              const data = fields(value, ['address', 'family']),
                address = text(data.address, 45);
              if ((data.family !== 4 && data.family !== 6) || isIP(address) !== data.family)
                throw failure('EK_DNS_CONFIG');
              return Object.freeze({ address, family: data.family });
            }),
          );
        } catch {
          throw failure('EK_DNS_TEMPORARY');
        }
      });
    },
    async reverse(
      ip: string,
      query?: Readonly<{ resolver?: string }>,
      options?: OperationOptions,
    ): Promise<readonly string[]> {
      const captured = validate(() => {
        const input = fields(query === undefined ? {} : query, ['resolver']),
          address = text(ip, 45);
        if (!isIP(address) || address.includes('%')) throw failure('EK_DNS_CONFIG');
        return { address, ...profile(input.resolver) };
      });
      return invoke('reverse', 'PTR', captured.name, options, async () => {
        const result = await captured.client.reverse(captured.address);
        try {
          return Object.freeze(array(result, 1024).map((value) => hostname(value)));
        } catch {
          throw failure('EK_DNS_TEMPORARY');
        }
      });
    },
    getResolvers() {
      ready();
      return Object.freeze(setting.resolvers.map((profile) => profile.name));
    },
    async close(options?: OperationOptions) {
      const policy = operationOptions(options);
      if (!closed) {
        closed = true;
        for (const task of active) task.cancel();
        for (const client of clients.values()) {
          try {
            client.cancel();
          } catch {
            /* Native shutdown remains best effort. */
          }
        }
        clients.clear();
      }
      if (policy.signal?.aborted) throw failure('EK_ABORTED');
    },
  });
}
/** Construct independently owned native resolvers; close the facade when its owner shuts down. */
export function createDnsService(settings: DnsPluginSettings): DnsService {
  return service(capture(settings));
}
/** Explicit per-application DNS capability. */
export const DNS_CAPABILITY: unique symbol = Symbol('arkenivajs.dns');
/** Register native resolvers and optional existing observability through the scoped support SPI. */
export function dnsPlugin(settings: DnsPluginSettings): Plugin {
  const captured = capture(settings),
    instances = new WeakMap<object, DnsService>();
  const plugin: ComposablePlugin = {
    id: 'dns',
    version: '0.1.0',
    capabilities: new Set(['dns']),
    dependencies: ['dns-observation'],
    [SUPPORT_PLUGINS]: [observations],
    init(context) {
      const instance = service(captured, context.require<Observation>(OBSERVATION));
      context.provide(DNS_CAPABILITY, instance);
      instances.set(context, instance);
    },
    async close(context) {
      await instances.get(context)?.close();
      instances.delete(context);
    },
  };
  return plugin;
}
