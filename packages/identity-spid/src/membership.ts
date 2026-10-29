// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { FederationProfileV1 } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { FederationHttp } from './metadata-http.js';
import type { ChainEvidence, ChainNode } from './chain.js';
import type { StatementKey } from './statements.js';
import { FederationResolver, configurationEndpoint } from './resolver.js';
import { captureProfile } from './settings.js';
import { inspectTrustMark } from './statements.js';
import { TrustMarkVerifier } from './trust-marks.js';
import { failure, fields, list, method, url } from './validation.js';

type Role = 'intermediate' | 'openid_provider' | 'openid_relying_party' | 'oauth_resource';
export type MembershipEvidence = ChainEvidence;
interface Member {
  readonly path: readonly ChainNode[];
  readonly roles: readonly Role[];
}
function italianRole(type: string): Role | undefined {
  const parts = new URL(url(type)).pathname.split('/');
  if (
    !['intermediate', 'openid_provider', 'openid_relying_party', 'oauth_resource'].includes(
      parts[1] ?? '',
    )
  )
    return undefined;
  // Italian identifiers place the role first; profile and extension suffixes are optional.
  return parts[1] as Role;
}
function keys(node: ChainNode): readonly StatementKey[] {
  const result: StatementKey[] = [];
  for (const delegated of node.keys) {
    const published = node.configuration.keys.find(
      (candidate) =>
        candidate.kid === delegated.kid && candidate.publicKey.equals(delegated.publicKey),
    );
    if (
      !published ||
      (published.algorithm && delegated.algorithm && published.algorithm !== delegated.algorithm)
    )
      continue;
    result.push(
      Object.freeze({
        ...delegated,
        expiresAt: Math.min(
          delegated.expiresAt ?? Infinity,
          published.expiresAt ?? Infinity,
          node.configuration.expiresAt * 1000,
        ),
        ...(published.algorithm ? { algorithm: published.algorithm } : {}),
      }),
    );
  }
  if (!result.length) throw failure('EK_EID_FEDERATION');
  return Object.freeze(result);
}
function interrupted(error: unknown) {
  return (
    error instanceof KitError &&
    ['EK_TIMEOUT', 'EK_ABORTED', 'EK_BACKEND_UNAVAILABLE', 'EK_RESOURCE_CLOSED'].includes(
      error.code,
    )
  );
}
/** Full private participation evidence requires role-specific authorized marks and fresh signed status. */
export class FederationMembership {
  private readonly profile: FederationProfileV1;
  private readonly read: FederationHttp['statement'];
  private readonly status: FederationHttp['trustMarkStatus'];
  private readonly owned = new WeakMap<
    MembershipEvidence,
    { resolver: FederationResolver; chain: ChainEvidence }
  >();
  constructor(
    profile: FederationProfileV1,
    http: Pick<FederationHttp, 'statement' | 'trustMarkStatus'>,
  ) {
    this.profile = captureProfile(profile);
    this.read = method<FederationHttp['statement']>(http, 'statement');
    this.status = method<FederationHttp['trustMarkStatus']>(http, 'trustMarkStatus');
  }
  async verify(call: FederationCall, configuration: string): Promise<MembershipEvidence> {
    try {
      call.check();
      const policy = this.profile.metadata,
        approved = new Set(
          policy.approvedMetadataEndpoints.map((endpoint) => new URL(endpoint).href),
        );
      let bytes = 0,
        documents = 0,
        attempts = 0,
        exhausted = false;
      const consume = (token: string) => {
        if (typeof token !== 'string') throw failure('EK_EID_FEDERATION');
        bytes += Buffer.byteLength(token);
        if (++documents > 129 || bytes > policy.maxBytes) exhausted = true;
        if (exhausted) throw failure('EK_EID_FEDERATION');
        return token;
      };
      const endpoint = (input: string) => {
        call.check();
        if (documents >= 129 || bytes >= policy.maxBytes) exhausted = true;
        if (exhausted) throw failure('EK_EID_FEDERATION');
        const selected = new URL(url(input)).href;
        if (!approved.has(selected)) throw failure('EK_EID_FEDERATION');
        return selected;
      };
      const transport: Pick<FederationHttp, 'statement'> = {
        statement: async (input, subject, options) =>
          consume(await this.read(endpoint(input), subject, options)),
      };
      const resolver = new FederationResolver(this.profile, transport),
        chain = await resolver.resolve(call, consume(configuration)),
        nodes = resolver.nodes(chain),
        root = nodes[0]!,
        catalog = fields(root.configuration.claims.trust_mark_issuers),
        members = new Map<string, Member>(),
        visiting = new Set<string>(),
        done = new Set<string>(),
        marks = new TrustMarkVerifier();
      let expiry = chain.expiresAt;
      const remember = (path: readonly ChainNode[], leafRoles: readonly Role[]) => {
        path.forEach((node, index) => {
          const entity = node.configuration.subject;
          if (members.has(entity)) return;
          if (members.size >= 64) throw failure('EK_EID_FEDERATION');
          members.set(entity, {
            path: Object.freeze(path.slice(0, index + 1)),
            roles: index === path.length - 1 ? leafRoles : ['intermediate'],
          });
        });
      };
      remember(nodes, ['openid_provider']);
      if (!Object.hasOwn(chain.metadata, 'openid_provider')) throw failure('EK_EID_FEDERATION');
      const authorized = (type: string, issuer: string) => {
        if (!Object.hasOwn(catalog, type)) return false;
        const raw = catalog[type];
        const allowed =
          Array.isArray(raw) && raw.length === 0 ? [] : list(raw, 64).map((item) => url(item));
        if (new Set(allowed).size !== allowed.length) throw failure('EK_EID_FEDERATION');
        return allowed.length === 0 || allowed.includes(issuer);
      };
      const issuer = async (entity: string): Promise<ChainNode> => {
        if (entity === chain.anchor) return root;
        let member = members.get(entity);
        if (!member) {
          if (members.size >= 64) throw failure('EK_EID_FEDERATION');
          const encoded = await call.step((options) =>
              transport.statement(configurationEndpoint(entity), undefined, options),
            ),
            issuerProfile = {
              ...this.profile,
              expectedIssuers: [entity],
              metadata: {
                ...policy,
                trustAnchors: policy.trustAnchors.filter(
                  (anchor) => anchor.issuer === chain.anchor,
                ),
              },
            },
            issuerResolver = new FederationResolver(issuerProfile, transport),
            proof = await issuerResolver.resolve(call, encoded);
          if (proof.anchor !== chain.anchor) throw failure('EK_EID_FEDERATION');
          expiry = Math.min(expiry, proof.expiresAt);
          const roles = (
            ['openid_provider', 'openid_relying_party', 'oauth_resource'] as const
          ).filter((role) => Object.hasOwn(proof.metadata, role));
          remember(issuerResolver.nodes(proof), roles.length ? roles : ['intermediate']);
          member = members.get(entity)!;
        }
        for (let index = 1; index < member.path.length; index++) {
          const node = member.path[index]!;
          const roles: readonly Role[] =
            index === member.path.length - 1 ? member.roles : ['intermediate'];
          for (const role of roles) await validate(node, role);
        }
        return member.path.at(-1)!;
      };
      const validate = async (node: ChainNode, role: Role): Promise<void> => {
        call.check();
        const subject = node.configuration.subject,
          id = JSON.stringify([subject, role]);
        if (done.has(id)) return;
        if (visiting.has(id)) throw failure('EK_EID_FEDERATION');
        visiting.add(id);
        try {
          const entries = list(node.configuration.claims.trust_marks, 32);
          for (const raw of entries) {
            if (++attempts > 64) throw failure('EK_EID_FEDERATION');
            try {
              const entry = fields(raw, ['id', 'trust_mark_type', 'trust_mark']),
                hasId = Object.hasOwn(entry, 'id'),
                hasType = Object.hasOwn(entry, 'trust_mark_type');
              if (hasId === hasType || typeof entry.trust_mark !== 'string')
                throw failure('EK_EID_FEDERATION');
              const type = url(hasId ? entry.id : entry.trust_mark_type);
              if (italianRole(type) !== role) continue;
              const inspected = inspectTrustMark(entry.trust_mark, policy.maxBytes);
              if (
                inspected.type !== type ||
                inspected.subject !== subject ||
                !authorized(type, inspected.issuer) ||
                Object.hasOwn(inspected.claims, 'crit') ||
                Object.hasOwn(inspected.claims, 'delegation')
              )
                throw failure('EK_EID_FEDERATION');
              const signer = await issuer(inspected.issuer),
                mark = await call.step((options) =>
                  marks.verify(
                    entry.trust_mark as string,
                    {
                      issuer: inspected.issuer,
                      subject,
                      type,
                      keys: keys(signer),
                      maxBytes: policy.maxBytes,
                      track: call.track,
                    },
                    options,
                  ),
                ),
                statusEndpoint = endpoint(
                  url(
                    fields(fields(signer.configuration.claims.metadata).federation_entity)
                      .federation_trust_mark_status_endpoint,
                  ),
                ),
                status = consume(
                  await call.step((options) =>
                    this.status(statusEndpoint, marks.request(mark), options),
                  ),
                ),
                until = await call.step((options) =>
                  marks.verifyStatus(
                    status,
                    mark,
                    policy.refreshIntervalSeconds,
                    options,
                    call.track,
                  ),
                );
              expiry = Math.min(
                expiry,
                node.configuration.expiresAt,
                signer.configuration.expiresAt,
                until,
              );
              done.add(id);
              return;
            } catch (error) {
              if (interrupted(error) || exhausted || attempts > 64) throw error;
            }
          }
          throw failure('EK_EID_FEDERATION');
        } finally {
          visiting.delete(id);
        }
      };
      for (let index = 1; index < nodes.length; index++)
        await validate(
          nodes[index]!,
          index === nodes.length - 1 ? 'openid_provider' : 'intermediate',
        );
      call.check();
      if (exhausted || expiry <= Date.now() / 1000) throw failure('EK_EID_FEDERATION');
      const result = freezeData({
        anchor: chain.anchor,
        subject: chain.subject,
        expiresAt: expiry,
        metadata: chain.metadata,
      });
      this.owned.set(result, { resolver, chain });
      return result;
    } catch (error) {
      if (interrupted(error)) throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  nodes(evidence: MembershipEvidence) {
    const proof = this.owned.get(evidence);
    if (!proof || evidence.expiresAt <= Date.now() / 1000) throw failure('EK_EID_FEDERATION');
    return proof.resolver.nodes(proof.chain);
  }
}
