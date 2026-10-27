// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import helmet from '@fastify/helmet';
import nativeHelmet from 'helmet';
import type { FastifyHelmetOptions } from '@fastify/helmet';
import type { FastifyInstance } from 'fastify';
import type { HttpSecurityPolicy } from './contracts.js';
import { fields, array, text, integer, failure } from './validation.js';

/** Freeze only validated header data; no callbacks, getters, wildcard defaults or report-only downgrade. */
function captureHeaderPolicy(input: unknown): HttpSecurityPolicy {
  const value = fields(input, [
    'contentSecurityPolicy',
    'hstsMaxAgeSeconds',
    'csrfEnabled',
    'frameAncestors',
  ]);
  if (typeof value.csrfEnabled !== 'boolean') throw failure();
  const directives = fields(value.contentSecurityPolicy),
    result: Record<string, readonly string[]> = Object.create(null);
  if (!Object.hasOwn(directives, 'default-src')) throw failure();
  let bytes = 0;
  for (const [name, values] of Object.entries(directives)) {
    if (
      !/^[a-z]+(?:-[a-z]+)*$/.test(name) ||
      name.length > 64 ||
      ['frame-ancestors', 'report-uri', 'report-to'].includes(name)
    )
      throw failure();
    result[name] = Object.freeze(
      array(values, 32).map((entry) => {
        const source = text(entry, 512);
        if (
          !/^[\x21-\x7e]+$/.test(source) ||
          /[;,]/.test(source) ||
          source.includes('*') ||
          source === "'unsafe-eval'"
        )
          throw failure();
        bytes += source.length;
        if (bytes > 8192) throw failure();
        return source;
      }),
    );
  }
  if (!result['default-src']?.length) throw failure();
  const ancestors = array(value.frameAncestors, 16).map((entry) => {
    const source = text(entry, 512);
    if (source !== "'none'" && source !== "'self'") {
      const url = new URL(source);
      if (
        url.protocol !== 'https:' ||
        url.origin !== source ||
        url.username ||
        url.password ||
        source.includes('*')
      )
        throw failure();
    }
    return source;
  });
  if (!ancestors.length || (ancestors.includes("'none'") && ancestors.length !== 1))
    throw failure();
  return Object.freeze({
    contentSecurityPolicy: Object.freeze(result),
    hstsMaxAgeSeconds: integer(value.hstsMaxAgeSeconds, 63072000),
    csrfEnabled: value.csrfEnabled,
    frameAncestors: Object.freeze(ancestors),
  });
}
export function headerPolicy(input: unknown): HttpSecurityPolicy {
  try {
    const policy = captureHeaderPolicy(input);
    nativeHelmet(nativeHeaderOptions(policy));
    return policy;
  } catch {
    throw failure();
  }
}
export function nativeHeaderOptions(policy: HttpSecurityPolicy) {
  return {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        ...policy.contentSecurityPolicy,
        'frame-ancestors': [...policy.frameAncestors],
      },
    },
    hsts: { maxAge: policy.hstsMaxAgeSeconds, includeSubDomains: false, preload: false },
    referrerPolicy: { policy: 'no-referrer' },
    xContentTypeOptions: true,
    xFrameOptions: false,
  } satisfies FastifyHelmetOptions;
}
/** Apply the native middleware at response time so a trusted policy update covers the next response. */
export function installNativeHeaders(
  server: FastifyInstance,
  current: () => HttpSecurityPolicy,
): void {
  server.register(helmet, { global: false });
  server.addHook('onSend', async (request, reply, payload) => {
    const options = nativeHeaderOptions(current());
    if (typeof reply.helmet === 'function') await reply.helmet(options);
    else
      await new Promise<void>((resolve, reject) =>
        nativeHelmet(options)(request.raw, reply.raw, (error?: unknown) =>
          error ? reject(failure()) : resolve(),
        ),
      );
    return payload;
  });
}
