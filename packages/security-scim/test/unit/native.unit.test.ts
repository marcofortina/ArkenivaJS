// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import SCIMMY from 'scimmy';
import { record, filter, patch, apply, page, descriptions } from '../../dist/codec.js';
import type { ScimRecord } from '../../dist/index.js';

const userSchema = 'urn:ietf:params:scim:schemas:core:2.0:User',
  groupSchema = 'urn:ietf:params:scim:schemas:core:2.0:Group',
  patchSchema = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const user: ScimRecord = {
  id: 'owned-user',
  schemas: [userSchema],
  userName: 'fixture-user',
  active: true,
  externalId: 'external-fixture',
  meta: { version: '"version-1"', resourceType: 'User' },
};
const group: ScimRecord = {
  id: 'owned-group',
  schemas: [groupSchema],
  displayName: 'Fixture group',
  members: [{ value: 'removed-member' }],
};
const operation = (op: 'add' | 'replace' | 'remove', path?: string, value?: unknown) =>
  patch({
    schemas: [patchSchema],
    Operations: [
      { op, ...(path === undefined ? {} : { path }), ...(value === undefined ? {} : { value }) },
    ],
  });

test('Actual native schemas validate required values and keep write-only passwords out of responses', () => {
  const value = record('Users', { ...user, password: 'synthetic-password-for-redaction' });
  assert.equal(value.userName, 'fixture-user');
  assert.equal(value.password, undefined);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(record('Groups', group).displayName, 'Fixture group');
  assert.throws(() => record('Users', { id: 'invalid', schemas: [userSchema] }), {
    code: 'EK_SCIM_BAD_REQUEST',
  });
  assert.throws(() => record('Users', { ...user, schemas: [groupSchema] }));
  assert.throws(() => record('Users', { ...user, active: {} }));
  assert.throws(() => record('Groups', { ...group, id: '' }));
  assert.equal(descriptions().length, 2);
});

test('Native filter grammar retains conjunctions, disjunctions, value paths and quoted punctuation', () => {
  for (const expression of [
    'userName eq "fixture-user" and active eq true',
    'userName sw "fixture" or userName ew "user"',
    'emails[type eq "work" and value co "@fixture.invalid"]',
    'not (active eq false)',
    'userName eq "constructor [quoted]"',
  ])
    assert.equal(filter(expression), expression);
  assert.equal(
    new SCIMMY.Types.Filter(filter('userName eq "fixture-user" and active eq true')).match([
      user,
      { ...user, active: false },
    ]).length,
    1,
  );
  for (const expression of [
    '',
    'userName unknown "value"',
    '(((((((((active pr)))))))))',
    'active eq true or '.repeat(9) + 'active eq false',
    'emails[constructor eq "x"]',
    'userName eq "unterminated',
    'active pr]',
  ])
    assert.throws(() => filter(expression));
});

test('Corrected native pathless replacement removes stale group membership and clears collections', async () => {
  const replaced = await apply(
    'Groups',
    group,
    operation('replace', undefined, { members: [{ value: 'retained-member' }] }),
  );
  assert.deepEqual(
    (replaced.members as { value: string }[]).map((item) => item.value),
    ['retained-member'],
  );
  assert.equal(replaced.displayName, group.displayName);
  const cleared = await apply('Groups', group, operation('replace', undefined, { members: [] }));
  assert.deepEqual(cleared.members ?? [], []);
  assert.deepEqual(group.members, [{ value: 'removed-member' }]);
});

test('Actual native add, replace and filtered remove preserve ordered atomic patch intent', async () => {
  const value = await apply(
    'Users',
    user,
    patch({
      schemas: [patchSchema],
      Operations: [
        {
          op: 'add',
          path: 'emails',
          value: [
            { type: 'work', value: 'old@fixture.invalid' },
            { type: 'home', value: 'home@fixture.invalid' },
          ],
        },
        { op: 'replace', path: 'emails[type eq "work"].value', value: 'new@fixture.invalid' },
        { op: 'remove', path: 'emails[type eq "home"]' },
        { op: 'replace', path: 'active', value: false },
      ],
    }),
  );
  assert.equal(value.active, false);
  assert.deepEqual(
    (value.emails as { value: string }[]).map((item) => item.value),
    ['new@fixture.invalid'],
  );
  assert.equal(user.active, true);
  await assert.rejects(apply('Users', user, operation('remove', 'userName')), {
    code: 'EK_SCIM_BAD_REQUEST',
  });
});

test('Patch validation rejects unknown paths and malformed commands before provider dispatch', () => {
  for (const value of [
    null,
    {},
    { schemas: [], Operations: [] },
    { schemas: [patchSchema], Operations: [{ op: 'replace', path: 'active' }] },
    { schemas: [patchSchema], Operations: [{ op: 'replace', value: [] }] },
    { schemas: [patchSchema], Operations: [{ op: 'replace', value: { unknownAttribute: true } }] },
    { schemas: [patchSchema], Operations: [{ op: 'remove' }] },
    { schemas: [patchSchema], Operations: [{ op: 'remove', path: 'active', value: true }] },
    { schemas: [patchSchema], Operations: [{ op: 'move', path: 'active', value: true }] },
    {
      schemas: [patchSchema],
      Operations: [{ op: 'add', path: '__proto__.polluted', value: true }],
    },
    { schemas: [patchSchema], Operations: [{ op: 'add', path: 'active"suffix"', value: true }] },
    {
      schemas: [patchSchema],
      Operations: [{ op: 'replace', path: 'unknownAttribute', value: 'x' }],
    },
    {
      schemas: [patchSchema],
      Operations: [{ op: 'replace', path: 'active', value: false, unknown: true }],
    },
  ])
    assert.throws(() => patch(value), { code: 'EK_SCIM_BAD_REQUEST' });
  assert.equal(operation('replace', 'active', false).Operations[0]!.op, 'replace');
});

test('Provider pages remain exactly one-based and native out-of-range pages stay empty', () => {
  assert.equal(
    page('Users', { startIndex: 11, itemsPerPage: 1, totalResults: 11, Resources: [user] })
      .Resources[0]!.id,
    user.id,
  );
  assert.deepEqual(
    page('Users', { startIndex: 12, itemsPerPage: 0, totalResults: 11, Resources: [] }).Resources,
    [],
  );
  const native = new SCIMMY.Messages.ListResponse([new SCIMMY.Schemas.User(user)], {
    startIndex: 20,
    count: 10,
    totalResults: 1,
  });
  assert.deepEqual(native.Resources, []);
  for (const change of [
    { startIndex: 0 },
    { startIndex: 1.5 },
    { itemsPerPage: 2 },
    { totalResults: -1 },
    { startIndex: 20 },
    { Resources: [user, user] },
  ])
    assert.throws(() =>
      page('Users', {
        startIndex: 1,
        itemsPerPage: 1,
        totalResults: 1,
        Resources: [user],
        ...change,
      }),
    );
});

test('Native schema-aware comparisons respect caseExact and preserve value-path resource values', async () => {
  const input = new SCIMMY.Schemas.User({
    ...user,
    id: 'Owned-Identifier',
    userName: 'MixedCase',
    emails: [{ type: 'work', value: 'Initial@Fixture.invalid' }],
  });
  assert.equal(
    new SCIMMY.Types.Filter('userName eq "mixedcase"').match(
      [input],
      SCIMMY.Schemas.User.definition,
    ).length,
    1,
  );
  assert.equal(
    new SCIMMY.Types.Filter('userName sw "MIXED"').match([input], SCIMMY.Schemas.User.definition)
      .length,
    1,
  );
  assert.equal(
    new SCIMMY.Types.Filter('id eq "owned-identifier"').match(
      [input],
      SCIMMY.Schemas.User.definition,
    ).length,
    0,
  );
  assert.equal(
    new SCIMMY.Types.Filter('schemas eq "' + userSchema + '"').match(
      [input],
      SCIMMY.Schemas.User.definition,
    ).length,
    1,
  );
  assert.equal(new SCIMMY.Types.Filter('userName eq "mixedcase"').match([input]).length, 0);
  const changed = await apply(
    'Users',
    JSON.parse(JSON.stringify(input)) as ScimRecord,
    operation('replace', 'emails[type eq "WORK"].value', 'Changed@Fixture.invalid'),
  );
  assert.equal(changed.userName, 'MixedCase');
  assert.deepEqual(
    (changed.emails as { value: string; type: string }[]).map((item) => ({
      value: item.value,
      type: item.type,
    })),
    [{ value: 'Changed@Fixture.invalid', type: 'work' }],
  );
});

test('Plain-data boundary rejects accessors, proxies, cycles, pollution and excessive nesting without execution', () => {
  let invoked = 0;
  const accessor = { ...user };
  Object.defineProperty(accessor, 'userName', {
    get() {
      invoked++;
      return 'unsafe';
    },
  });
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const deep: Record<string, unknown> = {};
  let target = deep;
  for (let n = 0; n < 17; n++) {
    const next = {};
    target.next = next;
    target = next;
  }
  for (const value of [
    accessor,
    new Proxy(user, {
      ownKeys() {
        invoked++;
        return [];
      },
    }),
    { ...user, value: cycle },
    { ...user, value: deep },
    { ...user, value: Infinity },
    { ...user, value: new Date() },
    { ...user, value: '\ud800' },
    { ...user, value: 'x'.repeat(262145) },
    { ...user, value: new Array(2) },
    JSON.parse('{"__proto__":{"polluted":true}}') as unknown,
  ])
    assert.throws(() => record('Users', value));
  assert.equal(invoked, 0);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});
