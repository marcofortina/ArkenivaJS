// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { performance } from 'node:perf_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { ItalianFederationService, FederationAssurance } from './contracts.js';
import type { Settings } from './settings.js';
import type { FederationTenantVerifier } from './identity-mapping.js';
import { FederationRuntime } from './runtime.js';
import { FederationHttp } from './metadata-http.js';
import { FederationProtocolHttp } from './protocol-http.js';
import { FederationMembership } from './membership.js';
import { FederationRelyingParty } from './relying-party.js';
import { FederationOidcLogin } from './oidc-login.js';
import { FederationOidcCallback } from './oidc-callback.js';
import { FederationSamlLogin } from './saml-login.js';
import { FederationIdentityMapping } from './identity-mapping.js';
import { FederationTransactions, returnPath } from './transactions.js';
import { failure, fields, text, url } from './validation.js';
import { recorder } from './observation.js';
import type { Observers, Operation } from './observation.js';

/** One shared admission/lifecycle owner; profile views never create independent authority. */
export async function managed(
  settings: Settings,
  crypto: CryptoService,
  auth: FederationTenantVerifier,
  owner?: AbortSignal,
  ready: () => boolean = () => true,
  observers: Observers = {},
) {
  if (!settings.encryptionRefs.length || !settings.macRefs.length) throw failure('EK_EID_PROFILE');
  for (const profile of settings.profiles) {
    if (profile.protocol === 'saml2') {
      if (!profile.samlRegistration?.registrySources) throw failure('EK_EID_PROFILE');
    } else if (!profile.oidcRegistration?.approvedProtocolEndpoints)
      throw failure('EK_EID_PROFILE');
  }
  const record = recorder(observers, settings.profiles[0]!.system),
    runtime = new FederationRuntime(settings.policy, ready, owner),
    transports: Array<{ metadata: FederationHttp; protocol?: FederationProtocolHttp }> = [],
    instances = new Map<
      string,
      | {
          kind: 'oidc';
          profile: Settings['profiles'][number];
          rp: FederationRelyingParty;
          login: FederationOidcLogin;
          callback: FederationOidcCallback;
          mapping: FederationIdentityMapping;
          membership: FederationMembership;
          transactions: FederationTransactions;
        }
      | {
          kind: 'saml';
          profile: Settings['profiles'][number];
          login: FederationSamlLogin;
          mapping: FederationIdentityMapping;
          transactions: FederationTransactions;
        }
    >(),
    views = new Map<string, ItalianFederationService>();
  let closed: Promise<void> | undefined;
  async function observe<T>(
    operation: Operation,
    work: () => Promise<T>,
    verdict?: (result: T) => unknown,
  ): Promise<T> {
    const began = performance.now();
    let error: unknown;
    try {
      const result = await work();
      error = verdict?.(result);
      return result;
    } catch (caught) {
      error = caught;
      throw caught;
    } finally {
      record.complete(operation, error, performance.now() - began);
    }
  }
  async function close(options?: OperationOptions): Promise<void> {
    return (closed ??= (async () => {
      const results = await Promise.allSettled([
        runtime.close(options),
        ...transports.flatMap((transport) => [
          transport.metadata.close(options),
          ...(transport.protocol ? [transport.protocol.close(options)] : []),
        ]),
      ]);
      const failed = results.find((result) => result.status === 'rejected');
      if (failed?.status === 'rejected') throw failed.reason;
    })());
  }
  try {
    for (const profile of settings.profiles) {
      const metadata = new FederationHttp(profile.metadata, settings.policy, settings.environment);
      if (profile.protocol === 'saml2') {
        transports.push({ metadata });
        const login = new FederationSamlLogin(settings, profile.profileId, metadata, crypto);
        instances.set(profile.profileId, {
          kind: 'saml',
          profile,
          login,
          mapping: new FederationIdentityMapping(settings, profile.profileId, login, auth),
          transactions: new FederationTransactions(settings, profile.profileId, crypto),
        });
        continue;
      }
      let protocol: FederationProtocolHttp;
      try {
        protocol = new FederationProtocolHttp(settings, profile.profileId);
      } catch (error) {
        await metadata.close();
        throw error;
      }
      transports.push({ metadata, protocol });
      const callback = new FederationOidcCallback(
        settings,
        profile.profileId,
        metadata,
        protocol,
        crypto,
      );
      instances.set(profile.profileId, {
        kind: 'oidc',
        profile,
        rp: new FederationRelyingParty(settings, profile.profileId, metadata),
        login: new FederationOidcLogin(settings, profile.profileId, metadata, crypto),
        callback,
        mapping: new FederationIdentityMapping(settings, profile.profileId, callback, auth),
        membership: new FederationMembership(profile, metadata),
        transactions: new FederationTransactions(settings, profile.profileId, crypto),
      });
    }
    const selected = (id?: string) => {
      if (id === undefined && instances.size !== 1) throw failure('EK_EID_PROFILE');
      const instance = id === undefined ? instances.values().next().value : instances.get(text(id));
      if (!instance) throw failure('EK_EID_PROFILE');
      return instance;
    };
    const bind = (id?: string): ItalianFederationService => {
      if (id !== undefined) selected(id);
      const key = id ?? '';
      const cached = views.get(key);
      if (cached) return cached;
      const methods = Object.freeze<ItalianFederationService>({
        forProfile(profileId) {
          return bind(text(profileId));
        },
        async beginAuthentication(context, assurance: FederationAssurance, options) {
          const instance = selected(id),
            value = fields(context, ['returnPath', 'tenantId', 'issuer']),
            path = returnPath(value.returnPath),
            hint = value.tenantId === undefined ? undefined : text(value.tenantId),
            issuer =
              value.issuer === undefined
                ? instance.profile.expectedIssuers.length === 1
                  ? instance.profile.expectedIssuers[0]!
                  : undefined
                : url(value.issuer);
          if (
            issuer === undefined ||
            !instance.profile.expectedIssuers.includes(issuer) ||
            !instance.profile.allowedAssurance.includes(assurance)
          )
            throw failure('EK_EID_ASSURANCE');
          return runtime.run(async (call) => {
            const receipt = fields(
              await call.step((operation) =>
                settings.authority.require(
                  instance.profile.system + '.begin_authentication',
                  undefined,
                  {},
                  operation,
                ),
              ),
              ['issuer', 'subject', 'tenant'],
            );
            text(receipt.issuer, 2048);
            text(receipt.subject, 2048);
            if (instance.kind === 'saml')
              return instance.login.begin(call, {
                issuer,
                assurance,
                returnPath: path,
                ...(hint ? { tenantHint: hint } : {}),
              });
            const rp = await instance.rp.verify(call),
              registration = instance.rp.registration(rp),
              result = await instance.login.begin(
                call,
                {
                  issuer,
                  assurance,
                  returnPath: path,
                  ...(hint ? { tenantHint: hint } : {}),
                },
                registration.signingKid,
              );
            instance.rp.check(rp);
            return result;
          }, options);
        },
        async consumeAuthentication(response, options) {
          const instance = selected(id);
          return runtime.run(async (call) => {
            if (instance.kind === 'saml')
              return instance.mapping.map(call, await instance.login.consume(call, response));
            const rp = await instance.rp.verify(call),
              upstream = await instance.callback.consume(
                call,
                response,
                instance.rp.registration(rp),
              ),
              result = await instance.mapping.map(call, upstream);
            instance.rp.check(rp);
            return result;
          }, options);
        },
        async verifyFederationTrust(statement, options) {
          const instance = selected(id);
          return runtime.run(async (call) => {
            try {
              if (instance.kind === 'saml') await instance.login.verifyTrust(call, statement);
              else await instance.membership.verify(call, statement);
              return Object.freeze({
                trusted: true,
                source: instance.profile.profileId,
                evaluatedAt: new Date().toISOString(),
                reasons: Object.freeze([] as string[]),
              });
            } catch (error) {
              if (!(error instanceof KitError) || error.code !== 'EK_EID_FEDERATION') throw error;
              return Object.freeze({
                trusted: false,
                source: instance.profile.profileId,
                evaluatedAt: new Date().toISOString(),
                reasons: Object.freeze(['federation_policy_rejected']),
              });
            }
          }, options);
        },
        async metadata() {
          const instance = selected(id);
          return runtime.run(async (call) => {
            if (instance.kind === 'saml') return instance.login.metadata(call);
            const proof = await instance.rp.verify(call);
            return instance.rp.registration(proof).metadata;
          });
        },
      });
      const service = Object.freeze<ItalianFederationService>({
        ...methods,
        beginAuthentication: (...args) =>
          observe('begin_authentication', () => methods.beginAuthentication(...args)),
        consumeAuthentication: (...args) =>
          observe('consume_authentication', () => methods.consumeAuthentication(...args)),
        metadata: () => observe('metadata', () => methods.metadata()),
        verifyFederationTrust: (...args) =>
          observe(
            'verify_federation_trust',
            () => methods.verifyFederationTrust(...args),
            (result) => (result.trusted ? undefined : failure('EK_EID_FEDERATION')),
          ),
      });
      views.set(key, service);
      return service;
    };
    return {
      service: bind(),
      close,
      async bootstrap() {
        await observe('bootstrap', () =>
          runtime.run(
            async (call) => {
              for (const instance of instances.values()) {
                await instance.transactions.probe(call);
                if (instance.kind === 'saml') await instance.login.metadata(call);
                else await instance.rp.verify(call);
              }
            },
            undefined,
            true,
          ),
        );
      },
      async health(options: OperationOptions) {
        try {
          await observe('health', () =>
            runtime.run(
              async (call) => {
                for (const instance of instances.values()) {
                  await instance.transactions.probe(call);
                  if (instance.kind === 'saml') await instance.login.metadata(call);
                  else await instance.rp.verify(call);
                }
              },
              options,
              true,
            ),
          );
          return true;
        } catch {
          return false;
        }
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
