// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, timingSafeEqual } from 'node:crypto';
import validator from 'validator';
import {
  Configuration,
  PrivateKeyJwt,
  authorizationCodeGrant,
  fetchUserInfo,
  customFetch,
  enableDecryptingResponses,
  enableNonRepudiationChecks,
  setJwksCache,
  getJwksCache,
  clockTolerance,
  modifyAssertion,
} from 'openid-client';
import { decodeProtectedHeader, exportJWK, createLocalJWKSet, jwtVerify } from 'jose';
import { KitError } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { FederationAssurance, FederationEncryptionPolicy } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import type { FederationHttp } from './metadata-http.js';
import type { FederationProtocolHttp } from './protocol-http.js';
import { FederationMembership } from './membership.js';
import { FederationTransactions } from './transactions.js';
import { configurationEndpoint } from './resolver.js';
import { loadFederationSigningKey } from './signing.js';
import { loadFederationDecryptionKey } from './decryption.js';
import { publicKeys } from './statements.js';
import { failure, fields, list, method, text, url } from './validation.js';

export interface VerifiedOidcResult {
  readonly profileId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly assurance: FederationAssurance;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
  readonly returnPath: string;
  readonly tenantHint?: string;
  readonly expiresAt: string;
}
const assuranceLevels = ['spid-l1', 'spid-l2', 'spid-l3'] as const,
  acrValues = assuranceLevels.map((_, index) => 'https://www.spid.gov.it/SpidL' + (index + 1));
function encrypted(token: unknown, policy: FederationEncryptionPolicy) {
  if (typeof token !== 'string' || token.split('.').length !== 5)
    throw failure('EK_EID_FEDERATION');
  const header = decodeProtectedHeader(token);
  if (header.alg !== policy.algorithm || header.enc !== policy.encryption || header.cty !== 'JWT')
    throw failure('EK_EID_FEDERATION');
}
/** Consume protected state before exchange; only this verifier's live results may enter mapping. */
export class FederationOidcCallback {
  private readonly profile;
  private readonly membership;
  private readonly transactions;
  private readonly read;
  private readonly owned = new WeakMap<VerifiedOidcResult, () => void>();
  constructor(
    private readonly settings: Settings,
    profileId: string,
    http: Pick<FederationHttp, 'statement' | 'trustMarkStatus'>,
    private readonly transport: FederationProtocolHttp,
    crypto: CryptoService,
  ) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    if (!profile?.oidcRegistration || profile.protocol !== 'oidc-federation')
      throw failure('EK_EID_PROFILE');
    this.profile = profile;
    this.membership = new FederationMembership(profile, http);
    this.transactions = new FederationTransactions(settings, profileId, crypto);
    this.read = method<FederationHttp['statement']>(http, 'statement');
  }
  async consume(call: FederationCall, input: unknown): Promise<VerifiedOidcResult> {
    try {
      call.check();
      const maximum = Math.min(
        this.profile.metadata.maxBytes,
        this.settings.policy.maxInputBytes ?? Infinity,
      );
      if (
        typeof input !== 'string' ||
        !input.length ||
        [...input].some(
          (character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127,
        ) ||
        Buffer.byteLength(input) > maximum ||
        Buffer.from(input).toString() !== input
      )
        throw failure('EK_EID_FEDERATION');
      const incoming = new URL(input),
        expected = new URL(this.profile.redirectUri),
        registration = this.profile.oidcRegistration!,
        parameters = incoming.searchParams;
      if (
        incoming.origin !== expected.origin ||
        incoming.pathname !== expected.pathname ||
        incoming.hash ||
        incoming.username ||
        incoming.password
      )
        throw failure('EK_EID_FEDERATION');
      const permitted = new Set([
        'code',
        'state',
        'iss',
        'error',
        'error_description',
        'error_uri',
        ...expected.searchParams.keys(),
      ]);
      for (const name of parameters.keys())
        if (!permitted.has(name) || parameters.getAll(name).length !== 1)
          throw failure('EK_EID_FEDERATION');
      for (const [name, value] of expected.searchParams)
        if (
          ['code', 'state', 'iss', 'error', 'error_description', 'error_uri'].includes(name) ||
          parameters.get(name) !== value
        )
          throw failure('EK_EID_FEDERATION');
      const issuer = url(parameters.get('iss')),
        state = text(parameters.get('state'), 64),
        transaction = await this.transactions.consume(call, state, issuer);
      if (parameters.has('error') || !parameters.get('code')) throw failure('EK_EID_FEDERATION');
      const configuration = await call.step((options) =>
          this.read(configurationEndpoint(issuer), undefined, options),
        ),
        proof = await this.membership.verify(call, configuration),
        metadata = fields(proof.metadata.openid_provider);
      if (proof.subject !== issuer || metadata.issuer !== issuer)
        throw failure('EK_EID_FEDERATION');
      const tokenEndpoint = url(metadata.token_endpoint),
        userInfoEndpoint = url(metadata.userinfo_endpoint),
        jwksEndpoint = metadata.jwks_uri === undefined ? undefined : url(metadata.jwks_uri),
        nativeFetch = this.transport.fetch(call, {
          tokenEndpoint,
          userInfoEndpoint,
          ...(jwksEndpoint ? { jwksEndpoint } : {}),
        }),
        signer = await loadFederationSigningKey(
          call,
          this.settings,
          this.profile.profileId,
          registration.signingAlgorithm,
        ),
        decryptor = await loadFederationDecryptionKey(call, this.settings, this.profile.profileId),
        supported = (name: string, value: string) => {
          if (!list(metadata[name]).includes(value)) throw failure('EK_EID_FEDERATION');
        };
      if (signer.kid === decryptor.publicJwk.kid) throw failure('EK_EID_FEDERATION');
      supported('token_endpoint_auth_methods_supported', 'private_key_jwt');
      supported('token_endpoint_auth_signing_alg_values_supported', signer.algorithm);
      supported('id_token_signing_alg_values_supported', registration.idTokenSigningAlgorithm);
      supported('userinfo_signing_alg_values_supported', registration.userInfoSigningAlgorithm);
      for (const [prefix, policy] of [
        ['userinfo', registration.userInfoEncryption],
        ...(registration.idTokenEncryption
          ? [['id_token', registration.idTokenEncryption] as const]
          : []),
      ] as const) {
        supported(prefix + '_encryption_alg_values_supported', policy.algorithm);
        supported(prefix + '_encryption_enc_values_supported', policy.encryption);
      }
      const config = new Configuration(
        {
          issuer,
          token_endpoint: tokenEndpoint,
          userinfo_endpoint: userInfoEndpoint,
          ...(jwksEndpoint ? { jwks_uri: jwksEndpoint } : {}),
          authorization_response_iss_parameter_supported: true,
        },
        this.profile.clientId!,
        {
          redirect_uris: [this.profile.redirectUri],
          token_endpoint_auth_signing_alg: signer.algorithm,
          id_token_signed_response_alg: registration.idTokenSigningAlgorithm,
          userinfo_signed_response_alg: registration.userInfoSigningAlgorithm,
          ...(registration.idTokenEncryption
            ? {
                id_token_encrypted_response_alg: registration.idTokenEncryption.algorithm,
                id_token_encrypted_response_enc: registration.idTokenEncryption.encryption,
              }
            : {}),
          userinfo_encrypted_response_alg: registration.userInfoEncryption.algorithm,
          userinfo_encrypted_response_enc: registration.userInfoEncryption.encryption,
          [clockTolerance]: 0,
        },
        PrivateKeyJwt(
          { key: signer.key, kid: signer.kid },
          {
            [modifyAssertion]: (_header, payload) => {
              payload.aud = tokenEndpoint;
              payload.exp = Math.floor(
                Math.min(payload.exp as number, proof.expiresAt, signer.expiresAt / 1000),
              );
              signer.check();
              this.membership.nodes(proof);
            },
          },
        ),
      );
      const verificationJwks = async (input: unknown) => {
        const keys = list(fields(input, ['keys']).keys, 32).map((item) => fields(item));
        if (
          keys.some((key) =>
            ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((name) => Object.hasOwn(key, name)),
          )
        )
          throw failure('EK_EID_FEDERATION');
        const validated = publicKeys(
          { keys: keys.filter((key) => key.use !== 'enc') },
          proof.expiresAt * 1000,
        );
        return {
          keys: await Promise.all(
            validated.map(async (key) => ({
              ...(await call.step(() => exportJWK(key.publicKey))),
              kid: key.kid,
              use: 'sig',
              ...(key.algorithm ? { alg: key.algorithm } : {}),
            })),
          ),
        };
      };
      if (metadata.jwks !== undefined)
        setJwksCache(config, {
          jwks: await verificationJwks(metadata.jwks),
          uat: Math.floor(Date.now() / 1000),
        });
      else if (!jwksEndpoint) throw failure('EK_EID_FEDERATION');
      enableNonRepudiationChecks(config);
      enableDecryptingResponses(
        config,
        [
          ...new Set([
            registration.userInfoEncryption.encryption,
            ...(registration.idTokenEncryption ? [registration.idTokenEncryption.encryption] : []),
          ]),
        ],
        ...decryptor.keys,
      );
      config.timeout = Math.max(1, Math.ceil(call.options().timeoutMs / 1000));
      config[customFetch] = async (address, init) => {
        signer.check();
        decryptor.check();
        this.membership.nodes(proof);
        let options = init;
        if (address === tokenEndpoint && init.body instanceof URLSearchParams) {
          const body = new URLSearchParams(init.body);
          body.set('redirect_uri', this.profile.redirectUri);
          options = { ...init, body };
        }
        const response = await nativeFetch(address, options),
          bytes = await call.step(() => response.arrayBuffer());
        if (address === jwksEndpoint && response.status === 200)
          return Response.json(
            await verificationJwks(
              JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
            ),
          );
        if (address === userInfoEndpoint && response.status === 200)
          encrypted(
            new TextDecoder('utf-8', { fatal: true }).decode(bytes),
            registration.userInfoEncryption,
          );
        if (
          address === tokenEndpoint &&
          response.status === 200 &&
          registration.idTokenEncryption
        ) {
          const body = fields(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
          encrypted(body.id_token, registration.idTokenEncryption);
        }
        return new Response(bytes, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      };
      const tokens = await call.step(() =>
          authorizationCodeGrant(config, incoming, {
            expectedState: transaction.transactionId,
            expectedNonce: transaction.nonce,
            pkceCodeVerifier: transaction.verifier,
            idTokenExpected: true,
          }),
        ),
        claims = fields(tokens.claims()),
        subject = text(claims.sub, 2048),
        now = Math.floor(Date.now() / 1000),
        level = acrValues.indexOf(claims.acr as string),
        requested = assuranceLevels.indexOf(
          transaction.assurance as (typeof assuranceLevels)[number],
        );
      if (level < 0 || requested < 0 || level < requested) throw failure('EK_EID_ASSURANCE');
      supported('acr_values_supported', claims.acr as string);
      if (
        !Number.isSafeInteger(claims.iat) ||
        (claims.iat as number) < 0 ||
        !Number.isSafeInteger(claims.exp) ||
        (claims.iat as number) > now ||
        (claims.exp as number) <= now
      )
        throw failure('EK_EID_FEDERATION');
      if (
        claims.aud !== this.profile.clientId ||
        claims.nbf !== claims.iat ||
        typeof claims.jti !== 'string' ||
        !validator.isUUID(claims.jti, '4')
      )
        throw failure('EK_EID_FEDERATION');
      const hash = createHash('sha' + registration.idTokenSigningAlgorithm.slice(2))
          .update(tokens.access_token, 'ascii')
          .digest(),
        expectedHash = Buffer.from(hash.subarray(0, hash.length / 2).toString('base64url')),
        actualHash =
          typeof claims.at_hash === 'string' ? Buffer.from(claims.at_hash) : Buffer.alloc(0);
      if (actualHash.length !== expectedHash.length || !timingSafeEqual(actualHash, expectedHash))
        throw failure('EK_EID_FEDERATION');
      const cache = getJwksCache(config);
      if (!cache?.jwks) throw failure('EK_EID_FEDERATION');
      const access = await call.step(() =>
        jwtVerify(tokens.access_token, createLocalJWKSet(cache.jwks), {
          algorithms: ['RS256', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'],
          issuer,
          subject,
          audience: userInfoEndpoint,
          clockTolerance: 0,
          requiredClaims: ['iss', 'sub', 'aud', 'client_id', 'iat', 'exp', 'jti'],
        }),
      );
      if (
        access.payload.client_id !== this.profile.clientId ||
        !Number.isSafeInteger(access.payload.iat) ||
        (access.payload.iat as number) < 0 ||
        (access.payload.iat as number) > now ||
        !Number.isSafeInteger(access.payload.exp) ||
        typeof access.payload.jti !== 'string' ||
        !validator.isUUID(access.payload.jti, '4') ||
        (access.payload.scope !== undefined && access.payload.scope !== 'openid')
      )
        throw failure('EK_EID_FEDERATION');
      const userInfo = fields(
          await call.step(() => fetchUserInfo(config, tokens.access_token, subject)),
        ),
        attributes: Record<string, readonly string[]> = Object.create(null);
      if (
        userInfo.iss !== issuer ||
        userInfo.aud !== this.profile.clientId ||
        !Number.isSafeInteger(userInfo.iat) ||
        (userInfo.iat as number) < 0 ||
        (userInfo.iat as number) > Math.floor(Date.now() / 1000) ||
        !Number.isSafeInteger(userInfo.exp) ||
        (userInfo.exp as number) <= Date.now() / 1000
      )
        throw failure('EK_EID_FEDERATION');
      for (const name of registration.requestedClaims) {
        const value = userInfo[name];
        if (value === undefined) continue;
        const values = Array.isArray(value) ? list(value, 64) : [value];
        attributes[name] = Object.freeze(
          values.map((item) => {
            if (typeof item === 'boolean' || (typeof item === 'number' && Number.isFinite(item)))
              return String(item);
            if (
              typeof item !== 'string' ||
              Buffer.byteLength(item) > 4096 ||
              Buffer.from(item).toString() !== item
            )
              throw failure('EK_EID_FEDERATION');
            return item;
          }),
        );
      }
      const mappedSubject =
          this.profile.subjectClaim === 'sub'
            ? subject
            : text(userInfo[this.profile.subjectClaim], 2048),
        expiresAt = Math.floor(
          Math.min(
            claims.exp as number,
            access.payload.exp as number,
            userInfo.exp as number,
            proof.expiresAt,
            signer.expiresAt / 1000,
            decryptor.expiresAt / 1000,
            Date.parse(transaction.expiresAt) / 1000,
          ),
        ),
        check = () => {
          signer.check();
          decryptor.check();
          this.membership.nodes(proof);
          if (Date.now() / 1000 >= expiresAt) throw failure('EK_EID_FEDERATION');
        };
      check();
      call.check();
      const result = freezeData({
        profileId: this.profile.profileId,
        issuer,
        subject: mappedSubject,
        assurance: assuranceLevels[level]!,
        attributes,
        returnPath: transaction.returnPath,
        ...(transaction.tenantHint ? { tenantHint: transaction.tenantHint } : {}),
        expiresAt: new Date(expiresAt * 1000).toISOString(),
      });
      if (
        Buffer.byteLength(JSON.stringify(result)) >
        Math.min(this.profile.metadata.maxBytes, this.settings.policy.maxOutputBytes ?? Infinity)
      )
        throw failure('EK_EID_FEDERATION');
      this.owned.set(result, check);
      return result;
    } catch (error) {
      if (
        error instanceof KitError &&
        [
          'EK_TIMEOUT',
          'EK_ABORTED',
          'EK_EID_ASSURANCE',
          'EK_BACKEND_UNAVAILABLE',
          'EK_RESOURCE_CLOSED',
        ].includes(error.code)
      )
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  result(input: VerifiedOidcResult): VerifiedOidcResult {
    const check = this.owned.get(input);
    if (!check) throw failure('EK_EID_FEDERATION');
    check();
    return input;
  }
}
