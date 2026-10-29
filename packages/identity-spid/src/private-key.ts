// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPrivateKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { types } from 'node:util';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import { failure, fields, text } from './validation.js';

const length = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'byteLength',
  )!.get!,
  backing = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'buffer',
  )!.get!;
function copy(input: unknown) {
  if (!types.isUint8Array(input) || backing.call(input) instanceof SharedArrayBuffer)
    throw failure('EK_EID_FEDERATION');
  const size: number = length.call(input);
  if (!size || size > 16384) throw failure('EK_EID_FEDERATION');
  const result = Buffer.alloc(size);
  Uint8Array.prototype.set.call(result, input);
  return result;
}
/** Import an approved external reference without returning or retaining raw secret bytes. */
export async function loadPrivateMaterial(
  call: FederationCall,
  settings: Settings,
  reference: string,
) {
  const value = fields(
    await call.step((options) => settings.secretProvider.get(reference, options)),
    ['bytes', 'keyVersion', 'expiresAt'],
  );
  text(value.keyVersion);
  const expiresAt =
    value.expiresAt === undefined ? Infinity : Date.parse(text(value.expiresAt, 32));
  if (expiresAt !== Infinity && (!Number.isSafeInteger(expiresAt) || expiresAt < 0))
    throw failure('EK_EID_FEDERATION');
  const check = () => {
    if (Date.now() >= expiresAt) throw failure('EK_EID_FEDERATION');
  };
  check();
  const material = copy(value.bytes);
  let native: KeyObject;
  try {
    try {
      native = createPrivateKey(material);
    } catch {
      native = createPrivateKey({ key: material, format: 'der', type: 'pkcs8' });
    }
  } finally {
    material.fill(0);
  }
  if (native.type !== 'private') throw failure('EK_EID_FEDERATION');
  call.check();
  check();
  return { native, expiresAt, check };
}
