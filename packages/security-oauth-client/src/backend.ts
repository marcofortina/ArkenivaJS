// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHttpClient } from '@arkenivajs/http';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import * as native from 'openid-client';
import type { Settings, Call } from './runtime.js';
import { data, failure, instant } from './validation.js';

export type Registration = Settings['clients'][number];
export type NativeTokens = Awaited<ReturnType<typeof native.authorizationCodeGrant>>;
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'byteLength',
)!.get!;
const backing = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'buffer',
)!.get!;
const unsupported = (capability: 'authorization_code' | 'token_revocation') =>
  new KitError({
    code: 'EK_UNSUPPORTED_CAPABILITY',
    message: 'The OAuth provider does not support the required operation',
    details: { capability, supported: false },
  });

function metadata(input: unknown): native.ServerMetadata {
  let nodes = 0;
  const visit = (value: unknown, depth: number): void => {
    if (++nodes > 4096 || depth > 16) throw failure('EK_OAUTH_PROVIDER');
    if (typeof value === 'string') {
      if (value.length > 16384) throw failure('EK_OAUTH_PROVIDER');
      return;
    }
    if (value === null || typeof value === 'boolean' || typeof value === 'number') return;
    if (!value || typeof value !== 'object') throw failure('EK_OAUTH_PROVIDER');
    if (Array.isArray(value)) {
      if (value.length > 2048) throw failure('EK_OAUTH_PROVIDER');
      value.forEach((item) => visit(item, depth + 1));
      return;
    }
    const fields = Object.keys(value);
    if (fields.length > 256) throw failure('EK_OAUTH_PROVIDER');
    for (const field of fields) {
      if (['__proto__', 'prototype', 'constructor'].includes(field))
        throw failure('EK_OAUTH_PROVIDER');
      visit((value as Record<string, unknown>)[field], depth + 1);
    }
  };
  visit(input, 0);
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw failure('EK_OAUTH_PROVIDER');
  return input as native.ServerMetadata;
}

/** Each SDK request passes the existing owned, bounded HTTP transport and its exact registration policy. */
export function createBackend(settings: Settings) {
  const http = createHttpClient({
      allowedOrigins: settings.origins,
      allowPrivateNetwork: settings.allowLoopback,
      timeoutMs: settings.timeoutMs,
      maxResponseBytes: 262144,
      connections: 8,
      retry: { attempts: 1 },
    }),
    servers = new Map<string, native.ServerMetadata>();
  const endpoint = (input: unknown, registration: Registration, maximum = 2048) => {
    if (typeof input !== 'string' || input.length > maximum) throw failure('EK_OAUTH_PROVIDER');
    const url = new URL(input),
      loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
    if (
      url.username ||
      url.password ||
      url.hash ||
      !registration.origins.includes(url.origin) ||
      !(
        url.protocol === 'https:' ||
        (settings.allowLoopback && loopback && url.protocol === 'http:')
      )
    )
      throw failure('EK_OAUTH_PROVIDER');
    return url;
  };
  async function configuration(registration: Registration, call: Call) {
    const server = servers.get(registration.id);
    if (!server) throw failure('EK_RESOURCE_CLOSED');
    let authentication = native.None();
    if (registration.clientSecretRef) {
      const result = await call.step('EK_OAUTH_PROVIDER', (options) =>
          settings.getSecret(registration.clientSecretRef!, options),
        ),
        value = data(result, ['bytes', 'keyVersion', 'expiresAt']);
      if (
        typeof value.keyVersion !== 'string' ||
        !value.keyVersion.length ||
        value.keyVersion.length > 256 ||
        !(value.bytes instanceof Uint8Array) ||
        backing.call(value.bytes) instanceof SharedArrayBuffer ||
        byteLength.call(value.bytes) < 1 ||
        byteLength.call(value.bytes) > 4096 ||
        (value.expiresAt !== undefined && Date.parse(instant(value.expiresAt)) <= Date.now())
      )
        throw failure('EK_OAUTH_PROVIDER');
      const copy = Buffer.alloc(byteLength.call(value.bytes));
      Uint8Array.prototype.set.call(copy, value.bytes);
      try {
        const secret = copy.toString('utf8');
        if (
          !Buffer.from(secret).equals(copy) ||
          [...secret].some(
            (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
          )
        )
          throw failure('EK_OAUTH_PROVIDER');
        authentication = native.ClientSecretBasic(secret);
      } finally {
        copy.fill(0);
      }
    }
    const config = new native.Configuration(
      server,
      registration.clientId,
      {
        redirect_uris: [registration.redirectUri],
        id_token_signed_response_alg: registration.idTokenAlgorithm,
      },
      authentication,
    );
    if (settings.allowLoopback) native.allowInsecureRequests(config);
    native.enableNonRepudiationChecks(config);
    config.timeout = Math.max(1, Math.ceil(call.options().timeoutMs! / 1000));
    config[native.customFetch] = async (address, init) => {
      endpoint(address, registration);
      const options = call.options();
      const { body: originalBody, ...transport } = init;
      let body = originalBody;
      if (typeof body === 'string' || body instanceof URLSearchParams) {
        const form = new URLSearchParams(body);
        // The SDK strips callback query parameters; preserve the exact registered redirect URI.
        if (form.get('grant_type') === 'authorization_code') {
          form.set('redirect_uri', registration.redirectUri);
          body = form;
        }
      }
      let payload: string | ArrayBuffer | null | undefined;
      if (typeof body === 'string' || body instanceof URLSearchParams) {
        payload = body.toString();
        if (Buffer.byteLength(payload) > 65536) throw failure('EK_OAUTH_POLICY');
      } else if (body === null || body === undefined) payload = body;
      else if (body instanceof Uint8Array && body.byteLength <= 65536) {
        const copy = new Uint8Array(body.byteLength);
        copy.set(body);
        payload = copy.buffer;
      } else if (body instanceof ArrayBuffer && body.byteLength <= 65536) payload = body.slice(0);
      else throw failure('EK_OAUTH_POLICY');
      return http.request(address, {
        ...transport,
        ...(payload === undefined ? {} : { body: payload }),
        ...options,
        signal: AbortSignal.any([options.signal!, ...(init.signal ? [init.signal] : [])]),
      });
    };
    return config;
  }
  return {
    async bootstrap(call: Call) {
      for (const registration of settings.clients) {
        const address =
          registration.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration';
        endpoint(address, registration);
        const response = await call.step('EK_OAUTH_PROVIDER', (options) =>
          http.get(address, options),
        );
        if (response.status !== 200) throw failure('EK_OAUTH_PROVIDER');
        const value = metadata(await call.step('EK_OAUTH_PROVIDER', () => response.json()));
        if (value.issuer !== registration.issuer || typeof value.token_endpoint !== 'string')
          throw failure('EK_OAUTH_PROVIDER');
        for (const field of [
          'authorization_endpoint',
          'token_endpoint',
          'jwks_uri',
          'revocation_endpoint',
        ] as const)
          if (value[field] !== undefined) endpoint(value[field], registration);
        if (
          value.authorization_endpoint !== undefined &&
          (!Array.isArray(value.code_challenge_methods_supported) ||
            !value.code_challenge_methods_supported.includes('S256'))
        )
          throw failure('EK_OAUTH_POLICY');
        const methods = value.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
        if (
          !Array.isArray(methods) ||
          !methods.includes(registration.clientSecretRef ? 'client_secret_basic' : 'none')
        )
          throw failure('EK_OAUTH_POLICY');
        if (
          registration.allowedScopes.includes('openid') &&
          (typeof value.jwks_uri !== 'string' ||
            !Array.isArray(value.id_token_signing_alg_values_supported) ||
            !value.id_token_signing_alg_values_supported.includes(registration.idTokenAlgorithm))
        )
          throw failure('EK_OAUTH_POLICY');
        servers.set(registration.id, Object.freeze({ ...value }));
      }
    },
    async authorization(
      registration: Registration,
      scope: readonly string[],
      state: string,
      nonce: string,
      verifier: string,
      resource: string,
      call: Call,
    ) {
      const config = await configuration(registration, call);
      if (!config.serverMetadata().authorization_endpoint) throw unsupported('authorization_code');
      const challenge = await native.calculatePKCECodeChallenge(verifier);
      call.check();
      const url = native.buildAuthorizationUrl(config, {
        response_type: 'code',
        redirect_uri: registration.redirectUri,
        scope: scope.join(' '),
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        resource,
        ...(scope.includes('openid') ? { nonce } : {}),
      });
      endpoint(url.href, registration, 32768);
      return url.href;
    },
    async exchange(
      registration: Registration,
      code: string,
      state: string,
      nonce: string,
      verifier: string,
      scope: readonly string[],
      resource: string,
      call: Call,
    ): Promise<NativeTokens> {
      const config = await configuration(registration, call),
        url = new URL(registration.redirectUri);
      url.searchParams.set('code', code);
      url.searchParams.set('state', state);
      url.searchParams.set('iss', registration.issuer);
      return call.step('EK_OAUTH_EXCHANGE', () =>
        native.authorizationCodeGrant(
          config,
          url,
          {
            expectedState: state,
            pkceCodeVerifier: verifier,
            ...(scope.includes('openid') ? { expectedNonce: nonce, idTokenExpected: true } : {}),
          },
          { resource },
        ),
      );
    },
    async credentials(
      registration: Registration,
      scope: readonly string[],
      resource: string,
      call: Call,
    ): Promise<NativeTokens> {
      if (!registration.clientSecretRef) throw failure('EK_OAUTH_POLICY');
      const config = await configuration(registration, call);
      return call.step('EK_OAUTH_EXCHANGE', () =>
        native.clientCredentialsGrant(config, { resource, scope: scope.join(' ') }),
      );
    },
    async refresh(
      registration: Registration,
      refreshToken: string,
      scope: readonly string[],
      resource: string,
      call: Call,
    ): Promise<NativeTokens> {
      const config = await configuration(registration, call);
      return call.step('EK_OAUTH_EXCHANGE', () =>
        native.refreshTokenGrant(config, refreshToken, { resource, scope: scope.join(' ') }),
      );
    },
    async revoke(registration: Registration, refreshToken: string, call: Call) {
      const config = await configuration(registration, call);
      if (!config.serverMetadata().revocation_endpoint) throw unsupported('token_revocation');
      await call.step('EK_OAUTH_PROVIDER', () =>
        native.tokenRevocation(config, refreshToken, { token_type_hint: 'refresh_token' }),
      );
    },
    async close(options?: OperationOptions) {
      servers.clear();
      await http.close(options);
    },
  };
}
