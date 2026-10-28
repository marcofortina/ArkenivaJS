// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  TenantOperationDefinition,
  TenantOperationSchemas,
  TenantOperationBinding,
  TenantImplementation,
  TenantOperationHandler,
} from './contracts.js';
import type { Settings } from './settings.js';
import { validateRegistry } from './registry.js';
import { OperationSchemas } from './schemas.js';
import { jsonSnapshot } from './json.js';
import { routingFailure } from './errors.js';

export interface SelectedOperation {
  readonly operation: TenantOperationDefinition;
  readonly implementation: TenantImplementation;
  readonly binding: TenantOperationBinding;
  readonly handler: TenantOperationHandler;
}

/** Immutable startup indexes; no request performs provider I/O or selects a default tenant. */
export class RoutingTable {
  readonly snapshot;
  readonly definitions;
  private readonly operations = new Map<string, TenantOperationDefinition>();
  private readonly implementations = new Map<
    string,
    { definition: TenantImplementation; handler: TenantOperationHandler }
  >();
  private readonly bindings = new Map<string, ReadonlyMap<string, TenantOperationBinding>>();
  private readonly inFlight = new Map<string, number>();
  private readonly schemas: OperationSchemas;
  constructor(source: unknown, settings: Settings) {
    this.snapshot = validateRegistry(source, 134217728);
    this.definitions = this.snapshot.operations;
    this.schemas = new OperationSchemas(this.definitions);
    for (const operation of this.definitions) {
      if (operation.path === settings.capabilitiesPath) throw routingFailure('EK_TROUTE_COLLISION');
      this.operations.set(operation.id, operation);
    }
    for (const implementation of this.snapshot.implementations) {
      // HTTP bindings are admitted only by the separately implemented fixed-upstream adapter.
      if (implementation.kind !== 'handler') throw routingFailure('EK_TROUTE_REGISTRY');
      const handler = settings.handlers.get(implementation.handlerKey);
      if (!handler) throw routingFailure('EK_TROUTE_REGISTRY');
      this.implementations.set(implementation.id, { definition: implementation, handler });
    }
    const tenants = new Map<string, Map<string, TenantOperationBinding>>();
    for (const binding of this.snapshot.bindings) {
      let tenant = tenants.get(binding.tenantId);
      if (!tenant) {
        tenant = new Map();
        tenants.set(binding.tenantId, tenant);
      }
      tenant.set(binding.operationId, binding);
    }
    for (const [tenant, bindings] of tenants) this.bindings.set(tenant, bindings);
  }
  select(operationId: string, tenantId: string): SelectedOperation | null {
    const operation = this.operations.get(operationId),
      binding = this.bindings.get(tenantId)?.get(operationId);
    if (!operation || !binding?.enabled) return null;
    const selected = this.implementations.get(binding.implementationId);
    if (!selected) throw routingFailure('EK_TROUTE_REGISTRY');
    return Object.freeze({
      operation,
      implementation: selected.definition,
      binding,
      handler: selected.handler,
    });
  }
  candidates(tenantId: string): readonly SelectedOperation[] {
    return [...(this.bindings.get(tenantId)?.keys() ?? [])].sort().flatMap((id) => {
      const selected = this.select(id, tenantId);
      return selected?.binding.discoverable === false || !selected ? [] : [selected];
    });
  }
  /** Admission is acquired by the caller only after authentication and operation authorization. */
  acquire(operationId: string): () => void {
    const operation = this.operations.get(operationId),
      current = this.inFlight.get(operationId) ?? 0;
    if (!operation) throw routingFailure('EK_TROUTE_UNMAPPED');
    if (current >= operation.maxConcurrency) throw routingFailure('EK_TROUTE_CAPACITY');
    this.inFlight.set(operationId, current + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const count = this.inFlight.get(operationId)! - 1;
      if (count) this.inFlight.set(operationId, count);
      else this.inFlight.delete(operationId);
    };
  }
  input(
    operation: TenantOperationDefinition,
    slot: Exclude<keyof TenantOperationSchemas, 'response'>,
    value: unknown,
  ): unknown {
    if (slot === 'body' && value === undefined && operation.schemas.body === undefined)
      return undefined;
    try {
      const clean = jsonSnapshot(value, operation.maxBodyBytes);
      if (!this.schemas.accepts(operation.id, slot, clean))
        throw routingFailure('EK_TROUTE_CONTRACT');
      return clean;
    } catch {
      throw routingFailure('EK_TROUTE_CONTRACT');
    }
  }
  response(operation: TenantOperationDefinition, value: unknown): string {
    try {
      const clean = jsonSnapshot(value, operation.maxResponseBytes);
      if (!this.schemas.accepts(operation.id, 'response', clean))
        throw routingFailure('EK_TROUTE_CONTRACT', true);
      return JSON.stringify(clean);
    } catch {
      throw routingFailure('EK_TROUTE_CONTRACT', true);
    }
  }
}
