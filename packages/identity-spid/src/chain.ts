// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
import { KitError } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { FederationProfileV1 } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { SignedStatement, StatementKey } from './statements.js';
import { anchorKeys, verifyStatement } from './statements.js';
import { captureProfile } from './settings.js';
import { applyMetadataPolicies } from './metadata-policy.js';
import { failure, fields, list, text, url } from './validation.js';

/** An explicit path is input data, never authority to choose a different trust root. */
export interface FederationPath {
  readonly anchor: string;
  readonly configuration: string;
  readonly descendants: readonly {
    readonly entity: string;
    readonly statement: string;
    readonly configuration: string;
  }[];
}
export interface ChainEvidence {
  readonly anchor: string;
  readonly subject: string;
  readonly expiresAt: number;
  readonly metadata: Readonly<Record<string, unknown>>;
}
export interface ChainNode {
  readonly configuration: SignedStatement;
  readonly delegation?: SignedStatement;
  readonly keys: readonly StatementKey[];
}
function names(input: unknown): readonly string[] {
  if (Array.isArray(input) && input.length === 0 && Reflect.ownKeys(input).length === 1) return [];
  const result = list(input, 64).map((item) => text(item, 2048));
  if (new Set(result).size !== result.length) throw failure('EK_EID_FEDERATION');
  return result;
}
function supported(statement: SignedStatement) {
  // No extension claim is implemented; critical extensions cannot be ignored.
  if (Object.hasOwn(statement.claims, 'crit')) throw failure('EK_EID_FEDERATION');
  if (statement.claims.metadata_policy_crit !== undefined) {
    const operators = names(statement.claims.metadata_policy_crit);
    if (
      !operators.length ||
      operators.some(
        (operator) =>
          !['value', 'add', 'default', 'one_of', 'subset_of', 'superset_of', 'essential'].includes(
            operator,
          ),
      )
    )
      throw failure('EK_EID_FEDERATION');
  }
}
function subtree(input: string) {
  const suffix = input.startsWith('.'),
    value = suffix ? input.slice(1) : input,
    ascii = domainToASCII(value).toLowerCase();
  if (
    !ascii ||
    ascii.length > 253 ||
    isIP(ascii) ||
    ascii.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  )
    throw failure('EK_EID_FEDERATION');
  return { suffix, ascii };
}
function constrainedName(entity: string, input: unknown) {
  const value = fields(input, ['permitted', 'excluded']),
    host = new URL(entity).hostname.toLowerCase();
  const matches = (entry: string) => {
    const { suffix, ascii } = subtree(entry);
    return suffix ? host.endsWith('.' + ascii) : host === ascii;
  };
  const permitted = value.permitted === undefined ? undefined : names(value.permitted),
    excluded = value.excluded === undefined ? [] : names(value.excluded);
  // Validate every entry, even when an earlier match would short-circuit the decision.
  for (const entry of [...(permitted ?? []), ...excluded]) subtree(entry);
  if (excluded.some(matches) || (permitted !== undefined && !permitted.some(matches)))
    throw failure('EK_EID_FEDERATION');
}
function constrain(
  entity: string,
  metadata: Record<string, unknown>,
  input: unknown,
  remaining: number,
  leaf: boolean,
) {
  const value = fields(input);
  if (value.max_path_length !== undefined) {
    if (
      !Number.isSafeInteger(value.max_path_length) ||
      (value.max_path_length as number) < 0 ||
      remaining > (value.max_path_length as number)
    )
      throw failure('EK_EID_FEDERATION');
  }
  if (value.naming_constraints !== undefined) constrainedName(entity, value.naming_constraints);
  if (value.allowed_entity_types !== undefined) {
    const allowed = names(value.allowed_entity_types);
    if (allowed.includes('federation_entity')) throw failure('EK_EID_FEDERATION');
    for (const role of Object.keys(metadata))
      if (role !== 'federation_entity' && !allowed.includes(role)) delete metadata[role];
  }
  if (value.allowed_leaf_entity_types !== undefined) {
    const allowed = names(value.allowed_leaf_entity_types);
    if (
      leaf &&
      Object.keys(metadata).some((role) => role !== 'federation_entity' && !allowed.includes(role))
    )
      throw failure('EK_EID_FEDERATION');
  }
  // Unknown noncritical constraints are ignored, as required by Federation 1.0.
}
function metadata(configuration: SignedStatement, delegation?: SignedStatement) {
  const result = fields(configuration.claims.metadata ?? {});
  for (const [role, parameters] of Object.entries(result)) result[role] = fields(parameters);
  if (delegation?.claims.metadata !== undefined)
    for (const [role, parameters] of Object.entries(fields(delegation.claims.metadata))) {
      const overrides = fields(parameters);
      if (Object.hasOwn(result, role)) result[role] = { ...fields(result[role]), ...overrides };
    }
  return result;
}
/** Owned evidence covers signatures, path constraints and metadata; live membership is separate. */
export class FederationChainVerifier {
  private readonly profile: FederationProfileV1;
  private readonly evidence = new WeakMap<ChainEvidence, readonly ChainNode[]>();
  constructor(profile: FederationProfileV1) {
    this.profile = captureProfile(profile);
  }
  async verify(call: FederationCall, input: FederationPath): Promise<ChainEvidence> {
    try {
      call.check();
      const value = fields(input, ['anchor', 'configuration', 'descendants']),
        anchor = url(value.anchor),
        policy = this.profile.metadata,
        descendants = list(value.descendants, Math.min(policy.maxChainDepth, 64)).map((item) => {
          const node = fields(item, ['entity', 'statement', 'configuration']);
          return {
            entity: url(node.entity),
            statement: node.statement,
            configuration: node.configuration,
          };
        });
      const identifiers = [anchor, ...descendants.map((item) => item.entity)];
      if (
        new Set(identifiers).size !== identifiers.length ||
        !this.profile.expectedIssuers.includes(identifiers.at(-1)!)
      )
        throw failure('EK_EID_FEDERATION');
      let bytes = 0;
      for (const token of [
        value.configuration,
        ...descendants.flatMap((item) => [item.statement, item.configuration]),
      ]) {
        if (typeof token !== 'string') throw failure('EK_EID_FEDERATION');
        bytes += Buffer.byteLength(token);
        if (bytes > policy.maxBytes) throw failure('EK_EID_FEDERATION');
      }
      const signed = (
        token: unknown,
        issuer: string,
        subject: string,
        keys: readonly StatementKey[],
      ) =>
        call.step((options) =>
          verifyStatement(
            token as string,
            { issuer, subject, keys, maxBytes: policy.maxBytes, track: call.track },
            options,
          ),
        );
      const pinned = anchorKeys(policy.trustAnchors, anchor),
        root = await signed(value.configuration, anchor, anchor, pinned);
      supported(root);
      await signed(value.configuration, anchor, anchor, root.keys);
      const rootConstraints = fields(root.claims.constraints);
      if (!Object.hasOwn(rootConstraints, 'max_path_length')) throw failure('EK_EID_FEDERATION');
      const nodes: ChainNode[] = [Object.freeze({ configuration: root, keys: pinned })],
        constraints: { value: unknown; remaining: number }[] = [],
        policies: unknown[] = [];
      // The Italian profile also publishes the root's path bound in its configuration.
      constraints.push({ value: rootConstraints, remaining: descendants.length - 1 });
      let resolved: Readonly<Record<string, unknown>> = {};
      for (let index = 0; index < descendants.length; index++) {
        call.check();
        const node = descendants[index]!,
          parent = nodes.at(-1)!,
          issuer = parent.configuration.subject,
          delegation = await signed(node.statement, issuer, node.entity, parent.keys);
        // A self-published rotation alone cannot expand keys delegated by the superior.
        await signed(node.statement, issuer, node.entity, parent.configuration.keys);
        supported(delegation);
        if (delegation.claims.authority_hints !== undefined) throw failure('EK_EID_FEDERATION');
        const configuration = await signed(
          node.configuration,
          node.entity,
          node.entity,
          delegation.keys,
        );
        supported(configuration);
        await signed(node.configuration, node.entity, node.entity, configuration.keys);
        const hints = names(configuration.claims.authority_hints);
        if (!hints.includes(issuer)) throw failure('EK_EID_FEDERATION');
        for (const hint of hints) url(hint);
        if (delegation.claims.constraints !== undefined)
          constraints.push({
            value: delegation.claims.constraints,
            remaining: descendants.length - index - 1,
          });
        if (delegation.claims.metadata_policy !== undefined)
          policies.push(delegation.claims.metadata_policy);
        const current = metadata(configuration, delegation);
        for (const constraint of constraints)
          constrain(
            node.entity,
            current,
            constraint.value,
            constraint.remaining,
            index === descendants.length - 1,
          );
        resolved = applyMetadataPolicies(current, policies, policy.maxBytes);
        nodes.push(Object.freeze({ configuration, delegation, keys: delegation.keys }));
      }
      call.check();
      const expiresAt = Math.min(
        ...nodes.flatMap((node) => [
          node.configuration.expiresAt,
          node.delegation?.expiresAt ?? Infinity,
        ]),
      );
      if (expiresAt <= Date.now() / 1000) throw failure('EK_EID_FEDERATION');
      const result = freezeData({
        anchor,
        subject: identifiers.at(-1)!,
        expiresAt,
        metadata: resolved,
      });
      this.evidence.set(result, Object.freeze(nodes));
      return result;
    } catch (error) {
      if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code))
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  /** Only this verifier's live evidence can provide keys to the later membership checks. */
  nodes(proof: ChainEvidence): readonly ChainNode[] {
    const nodes = this.evidence.get(proof);
    if (!nodes || proof.expiresAt <= Date.now() / 1000) throw failure('EK_EID_FEDERATION');
    return nodes;
  }
}
