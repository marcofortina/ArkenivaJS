import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { createMeter } from './meter.js';
import type { MeterOptions, MeterExporter, TenantVerifier, ManagedUsageMeter } from './meter.js';
import { createJsonlExporter } from './jsonl.js';
import { createHttpMeterExporter } from './http.js';
import type { HttpMeterExporterOptions } from './http.js';

/** Root data owns service/exporter selection; executable trust and transport policy remain explicit. */
export interface MeteringPluginOptions extends Omit<
  MeterOptions,
  'service' | 'auth' | 'enabled' | 'queueCapacity' | 'currentTraceId'
> {
  readonly workspace?: string;
  readonly http?: Omit<HttpMeterExporterOptions, 'endpoint' | 'environment'>;
  readonly dependencies?: readonly string[];
}
/** Install one independent event meter per application with explicit authentication ownership. */
export function meteringPlugin(options: MeteringPluginOptions = {}): Plugin {
  const services = new WeakMap<object, ManagedUsageMeter>();
  return {
    id: 'metering',
    version: '0.1.0',
    capabilities: new Set(['meter']),
    dependencies: [...new Set(['logging', 'security', ...(options.dependencies ?? [])])],
    async init(context) {
      const config = context.options.metering;
      if (!config)
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Root metering configuration is required',
        });
      const signal = context.require<AbortSignal>(APPLICATION_SIGNAL);
      const auth = context.require<TenantVerifier>(COMPONENTS.auth);
      if (typeof auth.isVerifiedTenant !== 'function')
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Metering requires verifier-local tenant provenance controls',
        });
      const telemetry = context.options.telemetry
        ? context.require<Telemetry>(COMPONENTS.telemetry)
        : options.telemetry;
      const contextual = telemetry as
        (Telemetry & { currentTraceId?: () => string | undefined }) | undefined;
      let exporter: MeterExporter | undefined = options.exporter;
      let meter: ManagedUsageMeter | undefined;
      try {
        if (config.enabled) {
          if (
            exporter &&
            config.exporter &&
            config.exporter !== 'otlp' &&
            config.exporter !== exporter.kind
          )
            throw new KitError({
              code: 'EK_CONFIG_INVALID',
              message: 'Meter exporter does not match root configuration',
            });
          if (!exporter)
            switch (config.exporter ?? 'jsonl') {
              case 'jsonl':
                if (!options.workspace || !config.path)
                  throw new KitError({
                    code: 'EK_CONFIG_MISSING',
                    message: 'JSONL metering requires an approved workspace and path',
                  });
                exporter = await createJsonlExporter({
                  workspace: options.workspace,
                  path: config.path,
                });
                break;
              case 'http':
                if (!options.http || !config.endpoint)
                  throw new KitError({
                    code: 'EK_CONFIG_MISSING',
                    message: 'HTTP metering requires an authenticated collector endpoint',
                  });
                exporter = createHttpMeterExporter({
                  ...options.http,
                  endpoint: config.endpoint,
                  environment: context.options.service.environment,
                });
                break;
              case 'otlp':
                throw new KitError({
                  code: 'EK_UNSUPPORTED_CAPABILITY',
                  message: 'OTLP diagnostics require a separate independent event exporter',
                });
            }
        }
        await within(() => undefined, { signal });
        meter = createMeter({
          ...options,
          service: context.options.service,
          auth,
          enabled: config.enabled,
          ...(config.queueCapacity !== undefined ? { queueCapacity: config.queueCapacity } : {}),
          ...(exporter ? { exporter } : {}),
          ...(telemetry ? { telemetry } : {}),
          ...(typeof contextual?.currentTraceId === 'function'
            ? { currentTraceId: () => contextual.currentTraceId!() }
            : {}),
        });
        services.set(context, meter);
        context.provide(COMPONENTS.meter, meter);
      } catch (cause) {
        services.delete(context);
        try {
          if (meter) await meter.close();
          else await exporter?.close();
        } catch (cleanup) {
          throw new KitError({
            code: 'EK_METER_EXPORT',
            message: 'Meter initialization and resource cleanup failed',
            cause: new AggregateError([cause, cleanup]),
          });
        }
        throw cause;
      }
    },
    async close(context) {
      const meter = services.get(context);
      services.delete(context);
      await meter?.close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
    },
  };
}
