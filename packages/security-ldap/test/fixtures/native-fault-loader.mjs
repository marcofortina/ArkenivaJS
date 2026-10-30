// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mock } from 'node:test';
import net from 'node:net';
import tls from 'node:tls';

// This explicit child preloader models driver failures, never directory compatibility.
const mode = process.env.ARKENIVA_LDAP_NATIVE_FAULT;
if (!mode) throw new Error('An explicit isolated LDAP fault scenario is required');
const actual = await import('ldapts');
mock.method(net, 'connect', () => new net.Socket());
mock.method(tls, 'connect', () => new tls.TLSSocket(new net.Socket()));
const userDn = 'uid=owned,ou=people,dc=fixture,dc=invalid';
class FaultClient {
  isConnected = true;
  isBound = false;
  calls = 0;
  constructor(options) {
    this.options = options;
    if (mode === 'plain-twice') {
      options.createConnection();
      options.createConnection();
    }
    if (mode === 'secure-twice') {
      options.createSecureConnection();
      options.createSecureConnection();
    }
    if (mode === 'upgrade-twice') options.createConnection();
  }
  async startTLS() {
    if (mode === 'starttls-failure') throw new Error('Private TLS failure');
    if (mode === 'upgrade-without-plain' || mode === 'upgrade-twice') {
      this.options.createSecureConnection();
      this.options.createSecureConnection();
    }
  }
  async bind(dn) {
    if (mode === 'invalid-user' && dn === userDn)
      throw new actual.InvalidCredentialsError('Private authentication failure');
    if (mode === 'bind-failure' || mode === 'connect-failure') {
      this.isConnected = mode !== 'connect-failure';
      throw new Error('Private directory failure');
    }
    this.isBound = mode !== 'unbound';
  }
  async unbind() {
    this.isBound = false;
    if (mode === 'unbind-failure') throw new Error('Private cleanup failure');
  }
  async *searchPaginated(_base, options) {
    let entry = { dn: userDn, uid: 'owned', cn: 'Owned' };
    let entries;
    if (mode === 'search-failure') throw new Error('Private search failure');
    if (mode === 'lost-binding') this.isBound = false;
    if (mode === 'missing-uid') delete entry.uid;
    if (mode === 'multiple-uids') entry.uid = ['owned', 'other'];
    if (mode === 'alias') entry = { dn: userDn, samaccountname: 'owned', cn: 'Owned' };
    if (mode === 'too-many-attributes')
      entry = Object.fromEntries(Array.from({ length: 66 }, (_, index) => [`a${index}`, 'x']));
    if (mode === 'unrequested') entry.description = 'Private';
    if (mode === 'duplicate-case') entry.CN = 'Other';
    if (mode === 'too-many-values') entry.cn = Array(129).fill('x');
    if (mode === 'large-value') entry.cn = 'x'.repeat(16385);
    if (mode === 'bad-utf8') entry.cn = Buffer.from([0xff]);
    if (mode === 'buffer-value') entry.cn = Buffer.from('Owned');
    if (mode === 'bad-dn') entry.dn = '';
    if (mode.startsWith('group-')) {
      const index = this.calls++;
      if (mode === 'group-cycle')
        entries = [
          { dn: `cn=${index ? 'b' : 'a'},ou=groups,dc=fixture,dc=invalid`, cn: index ? 'B' : 'A' },
        ];
      else if (mode === 'group-missing-name') entries = [{ dn: 'cn=a,dc=fixture,dc=invalid' }];
      else if (mode === 'group-many-names')
        entries = [{ dn: 'cn=a,dc=fixture,dc=invalid', cn: ['A', 'B'] }];
      else entries = [{ dn: `cn=${index},dc=fixture,dc=invalid`, cn: String(index) }];
    } else if (mode === 'empty') entries = [];
    else if (mode === 'ambiguous') entries = [entry, { ...entry, dn: `uid=other,${userDn}` }];
    else if (mode === 'page-overflow') entries = Array(options.sizeLimit + 1).fill(entry);
    else entries = [entry];
    yield {
      searchEntries: entries,
      searchReferences: mode === 'referral' ? ['ldap://untrusted.invalid'] : [],
    };
    if (mode === 'count-overflow') yield { searchEntries: [entry], searchReferences: [] };
  }
}
mock.module('ldapts', { namedExports: { ...actual, Client: FaultClient } });
