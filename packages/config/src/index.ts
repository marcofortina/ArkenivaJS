// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import { parseDocument } from 'yaml';
import { KitError, COMPONENTS } from '@arkenivajs/core';
import type { ConfigService, Plugin, OperationOptions } from '@arkenivajs/core';
import {
  ConfigStore,
  copyData,
  mergeData,
  within,
  reportConfigurationDiagnostic,
} from '@arkenivajs/core/support';
import type { StoreOptions } from '@arkenivajs/core/support';

export type { ConfigService } from '@arkenivajs/core';

/** Explicit environment parsing rules; values are never evaluated as shell code. */
export interface EnvironmentField {
  readonly path: string;
  readonly type: 'string' | 'integer' | 'number' | 'boolean' | 'json';
}

/** EK-CONF-001: lower-priority defaults/file/env and highest-priority runtime data. */
export interface ConfigurationOptions<T extends Record<string, unknown>>
  extends StoreOptions<T>, OperationOptions {
  readonly defaults?: Partial<T>;
  readonly yamlFile?: string;
  readonly yamlText?: string;
  readonly workspace: string;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly environmentFields?: Readonly<Record<string, EnvironmentField>>;
  readonly runtime?: Partial<T>;
  readonly secrets?: Readonly<Record<string, string>>;
  readonly secretProvider?: (reference: string, options: OperationOptions) => Promise<string>;
}

const secretName =
  /^(password|authorization|cookie|token|clientSecret|secret|accessToken|refreshToken|apiKey|connectionString)$/i;
function noSecrets(value: unknown, paths: readonly string[], prefix = ''): void {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if ((secretName.test(key) || paths.includes(path)) && child !== undefined && child !== null) {
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Secrets must come from environment or a secret provider',
      });
    }
    noSecrets(child, paths, path);
  }
}

function parseValue(value: string, type: EnvironmentField['type']): unknown {
  switch (type) {
    case 'string':
      return value;
    case 'boolean':
      if (value === 'true' || value === 'false') return value === 'true';
      break;
    case 'integer':
    case 'number': {
      if (value.trim() !== value || !/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/.test(value))
        break;
      const result = Number(value);
      if (Number.isFinite(result) && (type === 'number' || Number.isSafeInteger(result)))
        return result;
      break;
    }
    case 'json':
      try {
        return copyData(JSON.parse(value));
      } catch {
        break;
      }
  }
  throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid environment value' });
}

/** Load and validate without opening application resources or disclosing values. */
export async function createConfig<T extends Record<string, unknown>>(
  options: ConfigurationOptions<T>,
): Promise<ConfigService<T>> {
  try {
    return await within(async () => {
      const workspace = await realpath(options.workspace);
      if (options.yamlText !== undefined && options.yamlFile !== undefined)
        throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Choose one YAML source' });
      let text = options.yamlText;
      if (options.yamlFile !== undefined) {
        const file = await realpath(resolve(workspace, options.yamlFile));
        const path = relative(workspace, file);
        if (path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path))
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Configuration path is outside the approved workspace',
          });
        const metadata = await stat(file);
        if (!metadata.isFile() || metadata.size > 1_048_576)
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Configuration must be a bounded regular file',
          });
        text = await readFile(file, {
          encoding: 'utf8',
          ...(options.signal ? { signal: options.signal } : {}),
        });
      }
      if (text !== undefined && Buffer.byteLength(text) > 1_048_576)
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Configuration exceeds size limit',
        });
      let yaml: Record<string, unknown> = {};
      if (text !== undefined) {
        const document = parseDocument(text, { uniqueKeys: true, customTags: [], strict: true });
        if (document.errors.length || document.warnings.length)
          throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid YAML document' });
        yaml = copyData(document.toJS({ maxAliasCount: 0 })) as Record<string, unknown>;
        if (!yaml || typeof yaml !== 'object' || Array.isArray(yaml))
          throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'YAML root must be a mapping' });
      }
      const record = (input: unknown): Record<string, unknown> => {
        const data = copyData(input === undefined ? {} : input);
        if (!data || typeof data !== 'object' || Array.isArray(data))
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Configuration layers must be mappings',
          });
        return data as Record<string, unknown>;
      };
      const defaults = record(options.defaults),
        runtime = record(options.runtime);
      const secretReferences = record(options.secrets);
      const protectedPaths = [...(options.secretPaths ?? []), ...Object.keys(secretReferences)];
      for (const layer of [defaults, yaml, runtime]) noSecrets(layer, protectedPaths);
      const environment = record(
        options.environment === process.env
          ? { ...process.env }
          : (options.environment ?? { ...process.env }),
      );
      const fields = options.environmentFields ?? {};
      const envData: Record<string, unknown> = {};
      for (const [name, value] of Object.entries(environment)) {
        if (!name.startsWith('ARKENIVAJS_') || value === undefined) continue;
        if (typeof value !== 'string')
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Environment values must be strings',
          });
        const field = fields[name];
        if (!field)
          throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Unknown environment mapping' });
        const keys = field.path.split('.');
        if (
          !keys.every(
            (k) =>
              /^[a-zA-Z][a-zA-Z0-9_]*$/.test(k) &&
              !k.includes('\n') &&
              !['constructor', 'prototype', '__proto__'].includes(k),
          )
        )
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Unsafe environment mapping path',
          });
        let current = envData;
        for (const key of keys.slice(0, -1)) {
          if (current[key] === undefined) current[key] = {};
          if (!current[key] || typeof current[key] !== 'object' || Array.isArray(current[key]))
            throw new KitError({
              code: 'EK_CONFIG_INVALID',
              message: 'Conflicting environment mapping',
            });
          current = current[key] as Record<string, unknown>;
        }
        const last = keys.at(-1)!;
        if (Object.hasOwn(current, last))
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Duplicate environment target',
          });
        current[last] = parseValue(value, field.type);
      }
      for (const [path, reference] of Object.entries(secretReferences)) {
        const keys = path.split('.');
        if (
          !keys.every(
            (key) =>
              /^[a-zA-Z][a-zA-Z0-9_]*$/.test(key) &&
              key.trim() === key &&
              !['__proto__', 'constructor', 'prototype'].includes(key),
          ) ||
          typeof reference !== 'string' ||
          reference.length === 0 ||
          !options.secretProvider
        )
          throw new KitError({
            code: 'EK_CONFIG_INVALID',
            message: 'Invalid secret reference configuration',
          });
        let target = envData;
        for (const key of keys.slice(0, -1)) {
          if (target[key] === undefined) target[key] = {};
          if (!target[key] || typeof target[key] !== 'object' || Array.isArray(target[key]))
            throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Conflicting secret path' });
          target = target[key] as Record<string, unknown>;
        }
        const key = keys.at(-1)!;
        if (!Object.hasOwn(target, key)) {
          const secret = await options.secretProvider(reference, {
            ...(options.signal ? { signal: options.signal } : {}),
            ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
          });
          if (typeof secret !== 'string' || secret.length === 0)
            throw new KitError({
              code: 'EK_CONFIG_MISSING',
              message: 'Secret provider did not return a value',
            });
          target[key] = secret;
        }
      }
      const layers = [
        ['yaml', yaml],
        ['environment', envData],
        ['runtime', runtime],
      ] as const;
      let merged = defaults;
      const overrides: { source: 'yaml' | 'environment' | 'runtime'; keyCount: number }[] = [];
      for (const [source, layer] of layers) {
        const keyCount = Object.keys(layer).filter((key) => Object.hasOwn(merged, key)).length;
        if (keyCount > 0) overrides.push({ source, keyCount });
        merged = mergeData(merged, layer);
      }
      const store = new ConfigStore(merged as T, { ...options, secretPaths: protectedPaths });
      for (const override of overrides)
        reportConfigurationDiagnostic(
          { event: 'configuration.override.applied', ...override },
          options.onDiagnostic,
        );
      return store;
    }, options);
  } catch (cause) {
    if (cause instanceof KitError) throw cause;
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Configuration could not be loaded',
      cause,
    });
  }
}

/** Install a validated configuration service through the explicit plugin SPI. */
export function configPlugin(config: ConfigService): Plugin {
  return {
    id: 'config',
    version: '0.1.0',
    capabilities: new Set(['config']),
    init(context) {
      context.provide(COMPONENTS.config, config);
    },
    close() {
      /* No owned remote resources. */
    },
  };
}
