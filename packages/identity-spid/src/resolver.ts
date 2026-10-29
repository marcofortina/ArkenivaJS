// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { FederationProfileV1 } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { FederationHttp } from './metadata-http.js';
import type { ChainEvidence, FederationPath } from './chain.js';
import { FederationChainVerifier } from './chain.js';
import { captureProfile } from './settings.js';
import { inspectConfiguration } from './statements.js';
import { failure, fields, list, method, url } from './validation.js';

/** Configuration discovery appends the well-known path to the complete Entity Identifier. */
export function configurationEndpoint(entity: string): string {
  const identifier = url(entity),
    parsed = new URL(identifier);
  if (parsed.search) throw failure('EK_EID_FEDERATION');
  return identifier.replace(/\/$/u, '') + '/.well-known/openid-federation';
}
interface Candidate {
  readonly entity: string;
  readonly encoded: string;
  readonly claims: Readonly<Record<string, unknown>>;
}
/** Discovery remains untrusted until the complete selected path passes the pinned verifier. */
export class FederationResolver {
  private readonly profile: FederationProfileV1;
  private readonly verifier: FederationChainVerifier;
  private readonly approved: ReadonlySet<string>;
  private readonly read: FederationHttp['statement'];
  constructor(profile: FederationProfileV1, http: Pick<FederationHttp, 'statement'>) {
    this.profile = captureProfile(profile);
    this.verifier = new FederationChainVerifier(this.profile);
    this.approved = new Set(
      this.profile.metadata.approvedMetadataEndpoints.map((item) => new URL(item).href),
    );
    this.read = method<FederationHttp['statement']>(http, 'statement');
  }
  async resolve(call: FederationCall, leafConfiguration: string): Promise<ChainEvidence> {
    try {
      call.check();
      const policy = this.profile.metadata,
        roots = new Set(policy.trustAnchors.map((anchor) => anchor.issuer)),
        configurations = new Map<string, Candidate>(),
        statements = new Map<string, string>();
      let bytes = 0,
        edges = 0,
        documents = 0;
      const consume = (encoded: string) => {
        if (typeof encoded !== 'string') throw failure('EK_EID_FEDERATION');
        bytes += Buffer.byteLength(encoded);
        if (++documents > 129 || bytes > policy.maxBytes) throw failure('EK_EID_FEDERATION');
        return encoded;
      };
      const candidate = (encoded: string): Candidate => {
        const inspected = inspectConfiguration(consume(encoded), policy.maxBytes);
        return { ...inspected, encoded };
      };
      const approved = (endpoint: string) => {
        const selected = new URL(url(endpoint)).href;
        if (!this.approved.has(selected)) throw failure('EK_EID_FEDERATION');
        return selected;
      };
      const leaf = candidate(leafConfiguration);
      if (!this.profile.expectedIssuers.includes(leaf.entity) || roots.has(leaf.entity))
        throw failure('EK_EID_FEDERATION');
      configurations.set(leaf.entity, leaf);
      const configuration = async (entity: string): Promise<Candidate> => {
        const existing = configurations.get(entity);
        if (existing) return existing;
        const endpoint = approved(configurationEndpoint(entity)),
          encoded = await call.step((options) => this.read(endpoint, undefined, options)),
          result = candidate(encoded);
        if (result.entity !== entity) throw failure('EK_EID_FEDERATION');
        configurations.set(entity, result);
        return result;
      };
      const walk = async (
        child: Candidate,
        tail: FederationPath['descendants'],
        visited: ReadonlySet<string>,
      ): Promise<ChainEvidence | undefined> => {
        call.check();
        if (tail.length >= Math.min(policy.maxChainDepth, 64)) return undefined;
        const hints = list(child.claims.authority_hints, 64).map((hint) => url(hint));
        if (new Set(hints).size !== hints.length) throw failure('EK_EID_FEDERATION');
        for (const entity of hints) {
          call.check();
          if (++edges > 64) throw failure('EK_EID_FEDERATION');
          if (visited.has(entity)) continue;
          try {
            const parent = await configuration(entity),
              endpoint = approved(
                url(
                  fields(fields(parent.claims.metadata).federation_entity)
                    .federation_fetch_endpoint,
                ),
              ),
              cacheKey = JSON.stringify([entity, child.entity]);
            let statement = statements.get(cacheKey);
            if (statement === undefined) {
              statement = consume(
                await call.step((options) => this.read(endpoint, child.entity, options)),
              );
              statements.set(cacheKey, statement);
            }
            const descendants = [
              { entity: child.entity, statement, configuration: child.encoded },
              ...tail,
            ];
            if (roots.has(entity))
              return await this.verifier.verify(call, {
                anchor: entity,
                configuration: parent.encoded,
                descendants,
              });
            const result = await walk(parent, descendants, new Set([...visited, entity]));
            if (result) return result;
          } catch (error) {
            if (bytes > policy.maxBytes || documents > 129 || edges > 64)
              throw failure('EK_EID_FEDERATION');
            if (
              error instanceof KitError &&
              ['EK_TIMEOUT', 'EK_ABORTED', 'EK_BACKEND_UNAVAILABLE', 'EK_RESOURCE_CLOSED'].includes(
                error.code,
              )
            )
              throw error;
            // A failed candidate grants no evidence; another approved path must verify in full.
          }
        }
        return undefined;
      };
      const result = await walk(leaf, [], new Set([leaf.entity]));
      call.check();
      if (!result) throw failure('EK_EID_FEDERATION');
      return result;
    } catch (error) {
      if (
        error instanceof KitError &&
        ['EK_TIMEOUT', 'EK_ABORTED', 'EK_BACKEND_UNAVAILABLE', 'EK_RESOURCE_CLOSED'].includes(
          error.code,
        )
      )
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  nodes(proof: ChainEvidence) {
    return this.verifier.nodes(proof);
  }
}
