// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';
/** Supported native record families; DNSSEC/DoH/authoritative hosting are outside this API. */
export type DnsRecordType =
  'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'PTR' | 'SOA' | 'SRV' | 'TXT' | 'CAA' | 'NAPTR';
/** Normalized native records preserve TXT segment boundaries and expose TTL only when observed. */
export interface DnsRecordMap {
  readonly A: Readonly<{ address: string; ttlSeconds?: number }>;
  readonly AAAA: Readonly<{ address: string; ttlSeconds?: number }>;
  readonly CNAME: Readonly<{ hostname: string }>;
  readonly MX: Readonly<{ exchange: string; priority: number }>;
  readonly NS: Readonly<{ hostname: string }>;
  readonly PTR: Readonly<{ hostname: string }>;
  readonly SOA: Readonly<{
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
  }>;
  readonly SRV: Readonly<{ name: string; port: number; priority: number; weight: number }>;
  readonly TXT: Readonly<{ segments: readonly string[] }>;
  readonly CAA: Readonly<{ critical: number; tag: string; value: string }>;
  readonly NAPTR: Readonly<{
    order: number;
    preference: number;
    flags: string;
    service: string;
    regexp: string;
    replacement: string;
  }>;
}
/** A stable safe name and explicit literal DNS-server endpoints; never global resolver settings. */
export interface DnsResolverConfig {
  readonly name: string;
  readonly servers: readonly string[];
}
/** Immutable named resolvers, finite physical concurrency and positive default deadline. */
export interface DnsPluginSettings {
  readonly resolvers: readonly DnsResolverConfig[];
  readonly defaultResolver?: string;
  readonly maxConcurrency: number;
  readonly timeoutMs: number;
}
/** A native OS address result, without invented TTL or resolver-server provenance. */
export interface DnsLookupResult {
  readonly address: string;
  readonly family: 4 | 6;
}
/** DNS answers are untrusted data and do not authenticate destinations or enforce SSRF policy. */
export interface DnsService {
  /** Query a named network resolver through Node's DNS API. */
  resolve<T extends DnsRecordType>(
    query: Readonly<{ hostname: string; type: T; resolver?: string }>,
    options?: OperationOptions,
  ): Promise<readonly DnsRecordMap[T][]>;
  /** Use getaddrinfo/hosts semantics; configured network resolver servers do not apply. */
  lookup(
    hostname: string,
    query?: Readonly<{ family?: 0 | 4 | 6; all?: boolean }>,
    options?: OperationOptions,
  ): Promise<readonly DnsLookupResult[]>;
  /** Resolve PTR data for a strict IPv4/IPv6 literal through a named resolver. */
  reverse(
    ip: string,
    query?: Readonly<{ resolver?: string }>,
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Return only configured safe names, never internal DNS server addresses. */
  getResolvers(): readonly string[];
  /** Idempotently stop new work and cancel owned native resolvers where supported. */
  close(options?: OperationOptions): Promise<void>;
}
