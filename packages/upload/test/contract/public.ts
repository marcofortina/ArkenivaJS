// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Plugin, RouteContext } from '@arkenivajs/core';
import { uploadPlugin, UPLOAD_CAPABILITY } from '../../dist/index.js';
import type {
  UploadAuth,
  UploadMethod,
  UploadPolicy,
  UploadRoute,
  UploadRequest,
  MultipartPart,
  MultipartFilePart,
  MultipartFieldPart,
  UploadService,
  UploadStats,
  UploadPluginSettings,
} from '../../dist/index.js';

const auth: UploadAuth = { required: true, scopes: [] },
  method: UploadMethod = 'POST';
const policy: UploadPolicy = {
  maxRequestBytes: 1000000,
  maxFileBytes: 500000,
  maxFiles: 1,
  maxFields: 2,
  maxFieldBytes: 1024,
  maxParts: 3,
  allowedMediaTypes: ['application/pdf'],
};
const route: UploadRoute = {
  path: '/uploads',
  method,
  auth,
  policy,
  responseSchema: { type: 'object' },
  async handler(input: UploadRequest) {
    const context: RouteContext = input.context;
    void context;
    for await (const part of input.parts) {
      const value: MultipartPart = part;
      if (value.kind === 'file') {
        const file: MultipartFilePart = value;
        await file.discard({ timeoutMs: 100 });
      } else {
        const field: MultipartFieldPart = value;
        void field.value;
      }
    }
    return {};
  },
};
const settings: UploadPluginSettings = { routes: [route] };
const plugin: Plugin = uploadPlugin(settings),
  capability: symbol = UPLOAD_CAPABILITY;
function counters(service: UploadService): UploadStats {
  return service.stats();
}
void [plugin, capability, counters];
// @ts-expect-error A public upload needs an explicit reason.
const unsafe: UploadAuth = { required: false };
// @ts-expect-error File streams do not expose native implicit persistence helpers.
const storage = (part: MultipartFilePart) => part.toBuffer();
void [unsafe, storage];
