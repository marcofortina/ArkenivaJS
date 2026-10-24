import test from 'node:test';
import assert from 'node:assert/strict';
import type { AuthService, Identity, VerifiedTenantContext } from '@arkenivajs/core';
import type { ManagedAuthService } from '@arkenivajs/security';
import { securityPlugin } from '@arkenivajs/security';

const contract = (auth: ManagedAuthService): AuthService => auth;
const tenant = (auth: AuthService, identity: Identity): VerifiedTenantContext =>
  auth.tenantFrom(identity);
void [contract, tenant];
test('Security public factory retains an explicit authentication capability and logging dependency', () => {
  const plugin = securityPlugin();
  assert.equal(plugin.id, 'security');
  assert.equal(plugin.capabilities.has('auth'), true);
  assert.deepEqual(plugin.dependencies, ['logging']);
});
