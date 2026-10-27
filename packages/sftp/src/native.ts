// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import SftpClient from 'ssh2-sftp-client';
import type { Client, ConnectConfig, SFTPWrapper } from 'ssh2';
import { failure } from './validation.js';

/** These members are present in the pinned SDK and absent from its community declarations. */
export interface NativeClient extends SftpClient {
  readonly client: Client;
  readonly sftp: SFTPWrapper & { readonly _extensions?: Readonly<Record<string, string>> };
}
export function nativeClient() {
  // Replace the SDK's default callbacks, which otherwise print unsanitized native errors.
  const native = new SftpClient('managed-sftp', {
    error() {},
    end() {},
    close() {},
  }) as NativeClient;
  const connect = native.connect.bind(native),
    end = native.end.bind(native),
    transport = native.client,
    connectTransport = transport.connect.bind(transport);
  let approved: ConnectConfig | undefined;
  Object.defineProperties(native, {
    client: { value: transport, writable: false, configurable: false },
    connect: {
      value: () => Promise.reject(failure('EK_LIFECYCLE_STATE')),
      writable: false,
      configurable: false,
    },
    end: {
      value: () => (approved ? end() : Promise.reject(failure('EK_LIFECYCLE_STATE'))),
      writable: false,
      configurable: false,
    },
  });
  Object.defineProperty(transport, 'connect', {
    value: (options: ConnectConfig) => {
      if (!approved || options !== approved) throw failure('EK_LIFECYCLE_STATE');
      return connectTransport(options);
    },
    writable: false,
    configurable: false,
  });
  return {
    native,
    connect(options: ConnectConfig) {
      approved = options;
      try {
        return connect(options);
      } finally {
        approved = undefined;
      }
    },
  };
}
