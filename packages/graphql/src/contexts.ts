// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { failure } from './policy.js';

/** Native context copies retain an opaque reference, never client-declared authorization fields. */
export class OwnedContexts<T extends object> {
  private readonly key = Symbol('graphql.execution.owner');
  private readonly direct = new WeakMap<object, T>();
  private readonly inherited = new WeakMap<object, () => T | undefined>();

  get(context: object): T | undefined {
    if (!context || typeof context !== 'object' || types.isProxy(context)) return undefined;
    const direct = this.direct.get(context);
    if (direct) return direct;
    const descriptor = Object.getOwnPropertyDescriptor(context, this.key);
    if (!descriptor || !('value' in descriptor)) return undefined;
    const anchor: unknown = descriptor.value;
    if (!anchor || typeof anchor !== 'object' || types.isProxy(anchor)) return undefined;
    return this.inherited.get(anchor)?.();
  }

  /** A retired binding remains recognizable so shared native metadata guards still deny access. */
  owns(context: object): boolean {
    return (
      !!context &&
      typeof context === 'object' &&
      !types.isProxy(context) &&
      (this.direct.has(context) || Object.hasOwn(context, this.key))
    );
  }

  set(context: object, value: T): void {
    if (types.isProxy(context) || Object.hasOwn(context, this.key)) throw failure();
    this.direct.set(context, value);
  }

  /** Only an owned binding may follow the engine's shallow copies; retirement invalidates every copy. */
  bind(context: object, read: () => T | undefined): () => void {
    if (
      types.isProxy(context) ||
      this.direct.has(context) ||
      Object.hasOwn(context, this.key) ||
      typeof read !== 'function'
    )
      throw failure();
    const anchor = Object.freeze({});
    Object.defineProperty(context, this.key, { value: anchor, enumerable: true });
    this.inherited.set(anchor, read);
    return () => {
      this.inherited.delete(anchor);
    };
  }
}
