// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { failure } from './policy.js';

const contentTypes: Readonly<Record<string, string>> = {
  js: 'application/javascript',
  css: 'text/css',
  txt: 'text/plain',
  ttf: 'font/ttf',
  woff2: 'font/woff2',
};

/** Serve only build-manifest assets, authenticated on the existing listener. */
export async function registerIde(
  server: FastifyInstance,
  path: string,
  ownership: symbol,
  authorize: (request: FastifyRequest) => Promise<void>,
) {
  const root = new URL('./ide/', import.meta.url);
  const manifest: unknown = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
  if (
    !manifest ||
    typeof manifest !== 'object' ||
    !('format' in manifest) ||
    manifest.format !== 1 ||
    !('files' in manifest) ||
    !Array.isArray(manifest.files) ||
    !manifest.files.length ||
    manifest.files.length > 1000
  )
    throw failure();
  const files = new Map<string, { content: Buffer; mime: string }>();
  let bytes = 0;
  for (const entry of manifest.files) {
    if (
      !entry ||
      typeof entry !== 'object' ||
      typeof entry.name !== 'string' ||
      !/^[A-Za-z0-9_-]+\.(?:js|css|(?:js|css)\.LEGAL\.txt|ttf|woff2)$/.test(entry.name) ||
      !Number.isSafeInteger(entry.bytes) ||
      entry.bytes < 0 ||
      entry.bytes > 33554432 ||
      typeof entry.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(entry.sha256) ||
      files.has(entry.name)
    )
      throw failure();
    const content = await readFile(new URL(`assets/${entry.name}`, root));
    bytes += content.byteLength;
    if (
      bytes > 67108864 ||
      content.byteLength !== entry.bytes ||
      createHash('sha256').update(content).digest('hex') !== entry.sha256
    )
      throw failure();
    const extension = entry.name.split('.').at(-1)!;
    const mime = contentTypes[extension];
    if (!mime) throw failure();
    files.set(entry.name, { content, mime });
  }
  if (!files.has('app.js') || !files.has('app.css')) throw failure();
  const prefix = `${path}/ide`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="arkenivajs-graphql-endpoint" content="${path}"><title>ArkenivaJS GraphQL IDE</title><link rel="stylesheet" href="${prefix}/assets/app.css"></head><body style="margin:0"><div id="graphql-ide" style="height:100dvh"></div><script type="module" src="${prefix}/assets/app.js"></script></body></html>`;
  const config = { [ownership]: true };
  const headers = {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy':
      "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; worker-src 'self'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  };
  server.get(prefix, { config, preHandler: authorize }, (_request, reply) =>
    reply.headers(headers).type('text/html').send(html),
  );
  for (const [name, asset] of files)
    server.get(`${prefix}/assets/${name}`, { config, preHandler: authorize }, (_request, reply) =>
      reply.headers(headers).type(asset.mime).send(asset.content),
    );
}
