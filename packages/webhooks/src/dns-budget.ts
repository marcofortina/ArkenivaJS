// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { lookup } from 'node:dns/promises';
import { failure } from './validation.js';
type NativeLookup = (
  hostname: string,
  options: { all: true; verbatim: true },
) => Promise<readonly { address: string; family: number }[]>;

/** Native getaddrinfo is not abortable; keep its physical reservation after a caller timeout. */
export class DnsBudget {
  readonly pending = new Set<Promise<unknown>>();
  constructor(
    private readonly maximum: number,
    private readonly check: () => void,
    private readonly resolveHost: NativeLookup = lookup,
  ) {}
  resolve(hostname: string) {
    this.check();
    if (this.pending.size >= this.maximum) throw failure('EK_BACKEND_UNAVAILABLE');
    const task = Promise.resolve().then(async () => {
      this.check();
      const result = await this.resolveHost(hostname, { all: true, verbatim: true });
      this.check();
      return result;
    });
    this.pending.add(task);
    void task.then(
      () => this.pending.delete(task),
      () => this.pending.delete(task),
    );
    return task;
  }
  async drain(): Promise<void> {
    await Promise.allSettled([...this.pending]);
  }
}
