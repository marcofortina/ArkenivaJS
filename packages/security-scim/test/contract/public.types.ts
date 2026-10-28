// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createScimService, scimPlugin } from '../../dist/index.js';
import type {
  ScimServiceSettings,
  ScimPluginSettings,
  ScimProvider,
  ScimHttpRequest,
} from '../../dist/index.js';

export function publicContract(
  settings: ScimServiceSettings,
  plugin: ScimPluginSettings,
  users: ScimProvider,
  request: ScimHttpRequest,
): void {
  const service = createScimService(settings);
  service.registerUsers(users);
  service.registerGroups(users);
  void service.handle(request, { timeoutMs: 4000 });
  service.validatePatch({ schemas: [], Operations: [] });
  service.listCapabilities();
  scimPlugin(plugin);
  // @ts-expect-error The public factory has no authentication bypass.
  createScimService({ ...settings, trustTenantObjects: true });
  // @ts-expect-error Plugin bindings require every configured storage operation.
  scimPlugin({ ...plugin, users: { list: users.list } });
  // @ts-expect-error Bulk provisioning is explicitly unsupported.
  scimPlugin({ ...plugin, capabilities: { ...plugin.capabilities, bulk: true } });
}
