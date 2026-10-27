// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, realpath, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { dirname, relative, resolve, isAbsolute } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import type { XmlValidationReport } from './contracts.js';
import { Runtime, operation } from './runtime.js';
import { failure } from './validation.js';
import { inputText } from './backend.js';

const engine = '/usr/bin/xmllint',
  limiter = '/usr/bin/prlimit',
  query = '/usr/bin/dpkg-query';
const reviewedVersion = '2.9.14+dfsg-1.3ubuntu3.10';
const environment = {
  PATH: '/usr/bin:/bin',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  XML_CATALOG_FILES: '',
  SGML_CATALOG_FILES: '',
};
const schemaPolicy = {
  maxBytes: 1024 * 1024,
  maxDepth: 128,
  maxAttributes: 65536,
  namespaceMode: 'preserve' as const,
  forbidDtd: true as const,
  externalEntities: false as const,
};

function packageMatches(output: string): boolean {
  return (
    output.trim().split('\n').sort().join('\n') ===
    ['libxml2\t' + reviewedVersion, 'libxml2-utils\t' + reviewedVersion].sort().join('\n')
  );
}
async function engineIdentity(): Promise<string> {
  const value = await lstat(engine);
  if (!value.isFile() || value.isSymbolicLink() || value.uid !== 0 || value.mode & 0o022)
    throw failure('EK_BACKEND_UNAVAILABLE');
  return [value.dev, value.ino, value.size, value.mtimeMs, value.ctimeMs].join(':');
}

/** Native diagnostics are drained with a fixed byte ceiling and never exposed as document errors. */
async function command(
  program: string,
  args: readonly string[],
  signal: AbortSignal,
  input?: string,
  capture = false,
): Promise<{ code: number | null; output: string }> {
  if (signal.aborted) throw failure('EK_ABORTED');
  return new Promise((resolve, reject) => {
    let size = 0,
      output = '',
      failed = false;
    const child = spawn(program, [...args], {
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const abort = () => child.kill('SIGKILL');
    signal.addEventListener('abort', abort, { once: true });
    child.once('error', () => {
      failed = true;
    });
    for (const stream of [child.stdout, child.stderr])
      stream.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 65536) {
          failed = true;
          child.kill('SIGKILL');
        } else if (capture) output += chunk.toString('utf8');
      });
    child.stdin.on('error', () => undefined);
    child.stdin.end(input);
    child.once('close', (code) => {
      signal.removeEventListener('abort', abort);
      if (signal.aborted) reject(failure('EK_ABORTED'));
      else if (failed) reject(failure('EK_BACKEND_UNAVAILABLE'));
      else resolve({ code, output });
    });
    if (signal.aborted) abort();
  });
}
async function trustedExecutable(path: string) {
  const value = await lstat(path);
  return (
    value.isFile() &&
    !value.isSymbolicLink() &&
    value.uid === 0 &&
    !(value.mode & 0o022) &&
    !!(value.mode & 0o111)
  );
}
async function available(runtime: Runtime): Promise<boolean> {
  if (process.platform !== 'linux') return false;
  try {
    if (!(await Promise.all([engine, limiter, query].map(trustedExecutable))).every(Boolean))
      return false;
    return await runtime.external(
      undefined,
      0,
      async (signal) => {
        const packages = await command(
          query,
          ['-W', '-f=${Package}\t${Version}\n', 'libxml2', 'libxml2-utils'],
          signal,
          undefined,
          true,
        );
        if (packages.code !== 0 || !packageMatches(packages.output)) return false;
        const version = await command(engine, ['--version'], signal, undefined, true);
        return (
          version.code === 0 &&
          /libxml version 20914\b/.test(version.output) &&
          /\bSchemas\b/.test(version.output)
        );
      },
      true,
    );
  } catch (error) {
    if (error instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code)) throw error;
    return false;
  }
}
async function readSchema(path: string, signal: AbortSignal): Promise<string> {
  if (signal.aborted) throw failure('EK_ABORTED');
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || (await realpath(path)) !== path)
    throw failure('EK_XML_SECURITY');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > schemaPolicy.maxBytes || stat.mode & 0o022)
      throw failure('EK_XML_SECURITY');
    const data = Buffer.alloc(stat.size);
    let position = 0;
    try {
      while (position < data.length) {
        if (signal.aborted) throw failure('EK_ABORTED');
        const read = await file.read(data, position, data.length - position, position);
        if (!read.bytesRead) throw failure('EK_XML_SCHEMA');
        position += read.bytesRead;
      }
      const after = await file.stat();
      if (
        after.ino !== stat.ino ||
        after.size !== stat.size ||
        after.mtimeMs !== stat.mtimeMs ||
        after.ctimeMs !== stat.ctimeMs ||
        signal.aborted
      )
        throw failure('EK_XML_SECURITY');
      return inputText(data, schemaPolicy.maxBytes);
    } finally {
      data.fill(0);
    }
  } finally {
    await file.close();
  }
}
function importedPath(source: string, reference: string): string {
  if (
    !reference ||
    reference.length > 4096 ||
    reference.startsWith('/') ||
    reference.includes('\\') ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/.test(reference)
  )
    throw failure('EK_XML_SECURITY');
  try {
    const url = new URL(reference, pathToFileURL(source));
    if (url.protocol !== 'file:' || url.search || url.hash) throw failure('EK_XML_SECURITY');
    return fileURLToPath(url);
  } catch {
    throw failure('EK_XML_SECURITY');
  }
}
/** Immutable offline snapshots prevent native imports from reaching files outside the approved catalog. */
export class Xsd {
  private constructor(
    readonly runtime: Runtime,
    readonly directory: string,
    readonly schemas: ReadonlyMap<string, string>,
    readonly binding: string,
  ) {}
  static async create(runtime: Runtime): Promise<Xsd | undefined> {
    const entries = Object.entries(runtime.settings.schemas);
    if (!entries.length || !(await available(runtime))) return undefined;
    let directory: string | undefined;
    try {
      const sources = await runtime.external(
        undefined,
        0,
        async (signal) => {
          const values = new Map<string, string>();
          let total = 0;
          for (const [, path] of entries) {
            if (values.has(path)) continue;
            const text = await readSchema(path, signal);
            total += Buffer.byteLength(text);
            if (total > 8 * 1024 * 1024) throw failure('EK_XML_SECURITY');
            values.set(path, text);
          }
          return values;
        },
        true,
      );
      const graph = new Map<string, readonly string[]>();
      for (const [path, text] of sources) {
        const raw = JSON.parse(
          await runtime.execute<string>('xsd-schema', text, schemaPolicy, undefined, true),
        ) as unknown;
        if (
          !Array.isArray(raw) ||
          raw.length > 32 ||
          !raw.every((value) => typeof value === 'string')
        )
          throw failure('EK_XML_SCHEMA');
        const targets = raw.map((value) => importedPath(path, value as string));
        if (targets.some((target) => !sources.has(target))) throw failure('EK_XML_SECURITY');
        graph.set(path, targets);
      }
      const visited = new Set<string>(),
        stack = new Set<string>();
      function visit(path: string) {
        if (stack.has(path)) throw failure('EK_XML_SECURITY');
        if (visited.has(path)) return;
        stack.add(path);
        for (const target of graph.get(path) ?? []) visit(target);
        stack.delete(path);
        visited.add(path);
      }
      for (const path of sources.keys()) visit(path);
      let common = dirname(sources.keys().next().value!);
      while (
        [...sources.keys()].some((path) => {
          const value = relative(common, path);
          return value === '..' || value.startsWith('../') || isAbsolute(value);
        })
      )
        common = dirname(common);
      const snapshots = await runtime.external(
        undefined,
        0,
        async (signal) => {
          directory = await mkdtemp('/tmp/arkenivajs-xsd-');
          const values = new Map<string, string>();
          for (const [path, text] of sources) {
            if (signal.aborted) throw failure('EK_ABORTED');
            const target = resolve(directory, relative(common, path));
            await mkdir(dirname(target), { recursive: true, mode: 0o700 });
            await writeFile(target, text, { encoding: 'utf8', flag: 'wx', mode: 0o400 });
            values.set(path, target);
          }
          return new Map(entries.map(([id, path]) => [id, values.get(path)!]));
        },
        true,
      );
      const adapter = new Xsd(runtime, directory!, snapshots, await engineIdentity());
      for (const path of new Set(snapshots.values())) {
        await runtime.external(
          undefined,
          0,
          async (signal, timeout) => {
            const code = await adapter.validateNative(
              '<arkenivajs-schema-probe/>',
              path,
              signal,
              timeout,
            );
            if (code !== 0 && code !== 3) throw failure('EK_XML_SCHEMA');
          },
          true,
        );
      }
      return adapter;
    } catch (error) {
      await runtime.close();
      if (directory) await rm(directory, { recursive: true, force: true });
      throw error instanceof KitError ? error : failure('EK_XML_SCHEMA');
    }
  }
  private async validateNative(
    text: string,
    schema: string,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<number | null> {
    if ((await engineIdentity()) !== this.binding) throw failure('EK_BACKEND_UNAVAILABLE');
    const packages = await command(
      query,
      ['-W', '-f=${Package}\t${Version}\n', 'libxml2', 'libxml2-utils'],
      signal,
      undefined,
      true,
    );
    if (packages.code !== 0 || !packageMatches(packages.output))
      throw failure('EK_BACKEND_UNAVAILABLE');
    const result = await command(
      limiter,
      [
        '--as=268435456',
        '--data=134217728',
        '--fsize=0',
        '--nofile=32',
        '--cpu=' + String(Math.ceil(timeoutMs / 1000) + 1),
        '--',
        engine,
        '--nonet',
        '--nocatalogs',
        '--nowarning',
        '--noout',
        '--schema',
        schema,
        '-',
      ],
      signal,
      text,
    );
    return result.code;
  }
  async validate(
    text: string,
    id: string,
    requested?: OperationOptions,
  ): Promise<XmlValidationReport> {
    const config = operation(requested, this.runtime.settings.timeoutMs),
      deadline = performance.now() + config.timeoutMs,
      schema = this.schemas.get(id);
    if (!schema) throw failure('EK_XML_SCHEMA');
    const remaining = () => {
      const timeoutMs = Math.ceil(deadline - performance.now());
      if (timeoutMs < 1) throw failure('EK_TIMEOUT');
      return { ...(config.signal ? { signal: config.signal } : {}), timeoutMs };
    };
    await this.runtime.execute<string>(
      'xsd-guard',
      text,
      {
        ...this.runtime.settings.defaults,
        maxBytes: Math.min(
          this.runtime.settings.defaults.maxBytes,
          this.runtime.settings.maxInputBytes,
        ),
      },
      remaining(),
    );
    return this.runtime.external<XmlValidationReport>(
      remaining(),
      Buffer.byteLength(text),
      async (signal, timeout) => {
        const code = await this.validateNative(text, schema, signal, timeout);
        if (code === 0) return Object.freeze({ valid: true, messages: Object.freeze([]) });
        if (code === 3)
          return Object.freeze({
            valid: false,
            messages: Object.freeze([
              Object.freeze({
                path: '',
                code: 'EK_XML_SCHEMA',
                message: 'The document does not satisfy the registered XML schema',
              }),
            ]),
          });
        throw failure('EK_XML_SCHEMA');
      },
      false,
      (value) => (value.valid ? 'ok' : 'invalid'),
    );
  }
  async close(): Promise<void> {
    await rm(this.directory, { recursive: true, force: true });
  }
}
