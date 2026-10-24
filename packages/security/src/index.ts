import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';
import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type {
  AuthService,
  Identity,
  TenantId,
  VerifiedTenantContext,
  OperationOptions,
  Environment,
  Plugin,
  MfaAssurance,
} from '@arkenivajs/core';
import { copyData, freezeData, within } from '@arkenivajs/core/support';
import { createHttpClient } from '@arkenivajs/http';

export type {
  AuthService,
  Identity,
  TenantId,
  VerifiedTenantContext,
  MfaAssurance,
} from '@arkenivajs/core';
/** Trust policy is captured at construction and is never inferred from a request. */
export interface AuthOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly tenantClaim?: string;
  readonly algorithms?: readonly string[];
  readonly environment?: Environment;
  readonly tokenType?: 'JWT' | 'at+jwt';
  readonly clockToleranceSeconds?: number;
  readonly jwksUrl?: string;
  readonly allowedJwksOrigins?: readonly string[];
  readonly allowInsecureLoopback?: boolean;
  readonly jwksCooldownMs?: number;
  readonly jwksCacheMaxAgeMs?: number;
  readonly authorizeTenant?: (identity: Identity, tenantId: string) => boolean;
  readonly assuranceResolver?: (identity: Identity) => MfaAssurance;
  readonly onObservation?: (event: AuthObservation) => void;
}
/** Authentication observations contain no token, claims, subject or tenant. */
export interface AuthObservation {
  readonly outcome: 'verified' | 'rejected';
  readonly code?: string;
}
/** Runtime provenance is local to this verifier, independent of TypeScript brands. */
export interface ManagedAuthService extends AuthService {
  /** Startup capability check; presence never grants assurance to a request. */
  hasAssurancePolicy(): boolean;
  isVerifiedTenant(value: unknown): value is VerifiedTenantContext;
  close(options?: OperationOptions): Promise<void>;
  stats(): Readonly<{ verified: number; rejected: number; observerFailures: number }>;
}
const invalid = (message: string) => new KitError({ code: 'EK_CONFIG_INVALID', message });
const assuranceLevels: readonly MfaAssurance[] = ['single-factor', 'mfa', 'phishing-resistant'];
const policyError = (message: string, cause?: unknown) =>
  new KitError({ code: 'EK_MFA_POLICY', message, cause });
const supported = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);
const hasControls = (value: string) =>
  [...value].some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127);
const token = (value: unknown, max = 128): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= max &&
  !/\s/.test(value) &&
  !hasControls(value);

/** EK-AUTH-001: OIDC discovery and rotating remote keys through a bounded TLS client. */
export async function createAuthService(
  input: AuthOptions,
  operation: OperationOptions = {},
): Promise<ManagedAuthService> {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    typeof input.issuer !== 'string' ||
    (input.algorithms !== undefined && !Array.isArray(input.algorithms)) ||
    (input.allowedJwksOrigins !== undefined && !Array.isArray(input.allowedJwksOrigins)) ||
    (input.jwksUrl !== undefined && typeof input.jwksUrl !== 'string')
  )
    throw invalid('Invalid authentication options');
  const options = { ...input };
  if (options.assuranceResolver !== undefined && typeof options.assuranceResolver !== 'function')
    throw policyError('Assurance resolver must be a synchronous trusted function');
  const resolveAssurance = (identity: Identity): MfaAssurance => {
    if (!options.assuranceResolver) throw policyError('A trusted assurance resolver is required');
    try {
      const assurance = options.assuranceResolver(identity);
      if (!assuranceLevels.includes(assurance)) {
        // A mistakenly asynchronous policy cannot leave a rejected promise unobserved.
        if ((assurance as unknown) instanceof Promise)
          void (assurance as unknown as Promise<unknown>).catch(() => undefined);
        throw new Error('Assurance resolver returned an invalid decision');
      }
      return assurance;
    } catch (cause) {
      throw policyError('Trusted assurance resolution failed', cause);
    }
  };
  const algorithms = [...(options.algorithms ?? ['RS256'])];
  const skew = options.clockToleranceSeconds ?? 5;
  const cooldown = options.jwksCooldownMs ?? 30_000;
  const maxAge = options.jwksCacheMaxAgeMs ?? 300_000;
  const tenantClaim = options.tenantClaim ?? 'tenant_id';
  if (
    !token(options.audience, 512) ||
    !token(tenantClaim) ||
    ['__proto__', 'prototype', 'constructor'].includes(tenantClaim) ||
    !algorithms.length ||
    algorithms.some((a) => !supported.has(a)) ||
    new Set(algorithms).size !== algorithms.length ||
    !Number.isFinite(skew) ||
    skew < 0 ||
    skew > 60 ||
    !Number.isSafeInteger(cooldown) ||
    cooldown < 0 ||
    cooldown > 60_000 ||
    !Number.isSafeInteger(maxAge) ||
    maxAge < 1000 ||
    maxAge > 3_600_000 ||
    (options.environment !== undefined &&
      !['development', 'test', 'production'].includes(options.environment)) ||
    (options.tokenType !== undefined && !['JWT', 'at+jwt'].includes(options.tokenType)) ||
    (options.allowInsecureLoopback !== undefined &&
      typeof options.allowInsecureLoopback !== 'boolean') ||
    (options.authorizeTenant !== undefined && typeof options.authorizeTenant !== 'function') ||
    (options.onObservation !== undefined && typeof options.onObservation !== 'function') ||
    ((options.environment ?? 'production') === 'production' &&
      (options.allowInsecureLoopback || cooldown < 1000))
  )
    throw invalid('Invalid authentication trust policy');
  const url = (value: string): URL => {
    try {
      const result = new URL(value);
      if (
        result.username ||
        result.password ||
        result.hash ||
        result.search ||
        (result.protocol !== 'https:' &&
          !(
            options.allowInsecureLoopback &&
            result.protocol === 'http:' &&
            ['127.0.0.1', '[::1]'].includes(result.hostname)
          ))
      )
        throw invalid('Authentication endpoints require trusted HTTPS URLs');
      return result;
    } catch (cause) {
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Invalid authentication endpoint',
        cause,
      });
    }
  };
  const issuer = url(options.issuer);
  const origins = new Set([issuer.origin]);
  for (const value of options.allowedJwksOrigins ?? []) {
    const endpoint = url(value);
    if (endpoint.pathname !== '/') throw invalid('JWKS allowlist entries must be origins');
    origins.add(endpoint.origin);
  }
  await within(() => undefined, operation);
  const client = createHttpClient({
    allowedOrigins: [...origins],
    allowPrivateNetwork: options.allowInsecureLoopback === true,
    timeoutMs: 5000,
    maxResponseBytes: 524_288,
    connections: 2,
  });
  const controller = new AbortController();
  let closed = false;
  let closing: Promise<void> | undefined;
  let identities = new WeakSet<Identity>();
  let tenants = new WeakSet<VerifiedTenantContext>();
  const contexts = new WeakMap<Identity, VerifiedTenantContext>();
  const counters = { verified: 0, rejected: 0, observerFailures: 0 };
  const observe = (event: AuthObservation) => {
    try {
      options.onObservation?.(Object.freeze(event));
    } catch {
      counters.observerFailures++;
    }
  };
  try {
    let endpoint: URL;
    if (options.jwksUrl) endpoint = url(options.jwksUrl);
    else {
      const discovery = options.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration';
      const response = await client.get(discovery, {
        timeoutMs: operation.timeoutMs ?? 5000,
        ...(operation.signal ? { signal: operation.signal } : {}),
      });
      if (response.status !== 200) throw invalid('OIDC discovery request failed');
      const metadata = (await response.json()) as { issuer?: unknown; jwks_uri?: unknown };
      if (!metadata || metadata.issuer !== options.issuer || typeof metadata.jwks_uri !== 'string')
        throw invalid('OIDC discovery does not match the configured issuer');
      endpoint = url(metadata.jwks_uri);
    }
    if (!origins.has(endpoint.origin)) throw invalid('JWKS origin requires explicit authorization');
    const keys = createRemoteJWKSet(endpoint, {
      timeoutDuration: 5000,
      cooldownDuration: cooldown,
      cacheMaxAge: maxAge,
      [customFetch]: async (address, init) =>
        client.request(address, {
          method: init.method,
          headers: init.headers,
          signal: AbortSignal.any([controller.signal, init.signal]),
        }),
    });
    const open = () => {
      if (closed)
        throw new KitError({
          code: 'EK_RESOURCE_CLOSED',
          message: 'Authentication service is closed',
        });
    };
    const current = (identity: Identity) => {
      const exp = identity.claims.exp;
      const nbf = identity.claims.nbf;
      return (
        typeof exp === 'number' &&
        Date.now() / 1000 < exp + skew &&
        (nbf === undefined || (typeof nbf === 'number' && Date.now() / 1000 + skew >= nbf))
      );
    };
    const verified = (identity: Identity) => identities.has(identity) && current(identity);
    return Object.freeze({
      async verifyBearer(
        header: string | undefined,
        request: OperationOptions = {},
      ): Promise<Identity> {
        open();
        try {
          if (header === undefined || header === '')
            throw new KitError({
              code: 'EK_AUTH_REQUIRED',
              message: 'Bearer authentication is required',
            });
          if (
            typeof header !== 'string' ||
            header.length > 16_384 ||
            !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/i.test(header)
          )
            throw new KitError({
              code: 'EK_AUTH_INVALID',
              message: 'Invalid bearer authentication',
            });
          const result = await within(
            () =>
              jwtVerify(header.slice(7), keys, {
                issuer: options.issuer,
                audience: options.audience,
                algorithms,
                clockTolerance: skew,
                typ: options.tokenType ?? 'JWT',
                requiredClaims: ['sub', 'iss', 'aud', 'exp'],
              }),
            {
              timeoutMs: request.timeoutMs ?? 5000,
              signal: AbortSignal.any([
                controller.signal,
                ...(request.signal ? [request.signal] : []),
              ]),
            },
          );
          open();
          const claims = result.payload;
          if (!token(claims.sub, 512))
            throw new KitError({ code: 'EK_AUTH_INVALID', message: 'Invalid subject claim' });
          const scopes = claims.scope ?? claims.scp ?? '';
          if (typeof scopes !== 'string' || scopes.length > 4096 || hasControls(scopes))
            throw new KitError({ code: 'EK_AUTH_INVALID', message: 'Invalid scope claim' });
          const verifiedIdentity: Identity = freezeData({
            subject: claims.sub,
            issuer: options.issuer,
            audience: typeof claims.aud === 'string' ? [claims.aud] : [...claims.aud!],
            scopes: [...new Set(scopes.split(' ').filter(Boolean))],
            claims: copyData(claims),
          });
          const identity: Identity = options.assuranceResolver
            ? Object.freeze({ ...verifiedIdentity, assurance: resolveAssurance(verifiedIdentity) })
            : verifiedIdentity;
          identities.add(identity);
          counters.verified++;
          observe({ outcome: 'verified' });
          return identity;
        } catch (cause) {
          counters.rejected++;
          const error =
            cause instanceof KitError &&
            [
              'EK_AUTH_REQUIRED',
              'EK_AUTH_INVALID',
              'EK_ABORTED',
              'EK_TIMEOUT',
              'EK_RESOURCE_CLOSED',
              'EK_MFA_POLICY',
            ].includes(cause.code)
              ? cause
              : new KitError({
                  code: 'EK_AUTH_INVALID',
                  message: 'Bearer verification failed',
                  cause,
                });
          observe({ outcome: 'rejected', code: error.code });
          throw error;
        }
      },
      requireScope(identity: Identity, scope: string): void {
        open();
        if (!verified(identity) || !token(scope) || !identity.scopes.includes(scope))
          throw new KitError({
            code: 'EK_AUTH_FORBIDDEN',
            message: 'Required scope is not granted',
          });
      },
      hasAssurancePolicy: () => !closed && options.assuranceResolver !== undefined,
      requireAssurance(identity: Identity, requirement: MfaAssurance): void {
        open();
        if (!assuranceLevels.includes(requirement))
          throw policyError('Unknown assurance requirement');
        if (!verified(identity) || identity.assurance === undefined)
          throw new KitError({
            code: 'EK_MFA_ASSURANCE_REQUIRED',
            message: 'Verified authentication assurance is insufficient',
          });
        // Reevaluate issuer freshness at authorization time without upgrading an older decision.
        const currentAssurance = resolveAssurance(identity);
        if (
          Math.min(
            assuranceLevels.indexOf(identity.assurance),
            assuranceLevels.indexOf(currentAssurance),
          ) < assuranceLevels.indexOf(requirement)
        )
          throw new KitError({
            code: 'EK_MFA_ASSURANCE_REQUIRED',
            message: 'Verified authentication assurance is insufficient',
          });
      },
      tenantFrom(identity: Identity): VerifiedTenantContext {
        open();
        const claim = verified(identity) ? identity.claims[tenantClaim] : undefined;
        if (
          typeof claim !== 'string' ||
          !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?![\s\S])/.test(claim)
        )
          throw new KitError({
            code: 'EK_TENANT_UNVERIFIED',
            message: 'A verified tenant claim is required',
          });
        try {
          if (options.authorizeTenant && options.authorizeTenant(identity, claim) !== true)
            throw new Error('Tenant authorization denied');
        } catch (cause) {
          throw new KitError({
            code: 'EK_TENANT_UNVERIFIED',
            message: 'Tenant authorization failed',
            cause,
          });
        }
        let context = contexts.get(identity);
        if (!context) {
          context = Object.freeze({
            tenantId: claim as TenantId,
            identity,
            verifiedAt: new Date().toISOString(),
            source: 'oidc' as const,
          });
          contexts.set(identity, context);
          tenants.add(context);
        }
        return context;
      },
      isVerifiedTenant(value: unknown): value is VerifiedTenantContext {
        return (
          !closed &&
          !!value &&
          typeof value === 'object' &&
          tenants.has(value as VerifiedTenantContext) &&
          verified((value as VerifiedTenantContext).identity)
        );
      },
      stats: () => Object.freeze({ ...counters }),
      close(request: OperationOptions = {}): Promise<void> {
        if (closing) return closing;
        closed = true;
        identities = new WeakSet();
        tenants = new WeakSet();
        controller.abort();
        closing = client.close(request);
        return closing;
      },
    });
  } catch (cause) {
    await client.close();
    if (cause instanceof KitError) throw cause;
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Authentication initialization failed',
      cause,
    });
  }
}
/** Root configuration owns issuer/audience; advanced policy remains explicit in the plugin. */
export type SecurityPluginOptions = Omit<
  AuthOptions,
  'issuer' | 'audience' | 'tenantClaim' | 'algorithms' | 'environment'
>;
/** Create one verifier per application and close its private JWKS transport on shutdown. */
export function securityPlugin(options: SecurityPluginOptions = {}): Plugin {
  const services = new WeakMap<object, ManagedAuthService>();
  return {
    id: 'security',
    version: '0.1.0',
    capabilities: new Set(['auth']),
    dependencies: ['logging'],
    async init(context) {
      if (!context.options.security) throw invalid('Security configuration is required');
      const auth = await createAuthService(
        {
          ...options,
          ...context.options.security,
          environment: context.options.service.environment,
          onObservation(event) {
            context.logger.info('Authentication completed', {
              outcome: event.outcome,
              ...(event.code ? { code: event.code } : {}),
            });
            options.onObservation?.(event);
          },
        },
        { signal: context.require<AbortSignal>(APPLICATION_SIGNAL) },
      );
      try {
        context.provide(COMPONENTS.auth, auth);
        services.set(context, auth);
      } catch (error) {
        await auth.close();
        throw error;
      }
    },
    async close(context) {
      await services
        .get(context)
        ?.close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
      services.delete(context);
    },
  };
}
