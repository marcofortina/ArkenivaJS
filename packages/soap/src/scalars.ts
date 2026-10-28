// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { IOptions } from 'soap';
import { failure } from './validation.js';

/** Native deserializer hooks reject lossy numeric conversion without replacing the XML decoder. */
export function scalarOptions(): Pick<IOptions, 'customDeserializer' | 'preserveWhitespace'> {
  const seen = new WeakSet<object>();
  const once = (text: string, context: object) => {
    if (seen.has(context)) throw failure('EK_UNSUPPORTED_CAPABILITY');
    seen.add(context);
    return text.trim();
  };
  const integral = (minimum: number, maximum: number) => (text: string, context: object) => {
    const value = once(text, context);
    if (!/^[+-]?[0-9]+$/.test(value)) throw failure('EK_SOAP_SCHEMA');
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < minimum || number > maximum)
      throw failure('EK_SOAP_SCHEMA');
    return number;
  };
  const precise = (decimal: boolean) => (text: string, context: object) => {
    const value = once(text, context);
    if (!(decimal ? /^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$/ : /^[+-]?[0-9]+$/).test(value))
      throw failure('EK_SOAP_SCHEMA');
    return value;
  };
  const floating = (text: string, context: object) => {
    const value = once(text, context);
    if (!/^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/.test(value))
      throw failure('EK_SOAP_SCHEMA');
    const number = Number(value);
    if (!Number.isFinite(number)) throw failure('EK_SOAP_SCHEMA');
    return number;
  };
  const boolean = (text: string, context: object) => {
    const value = once(text, context);
    if (!['true', 'false', '0', '1'].includes(value)) throw failure('EK_SOAP_SCHEMA');
    return value === 'true' || value === '1';
  };
  const long = (text: string, context: object) => {
    const value = precise(false)(text, context),
      number = BigInt(value);
    if (number < -9223372036854775808n || number > 9223372036854775807n)
      throw failure('EK_SOAP_SCHEMA');
    return value;
  };
  const customDeserializer: NonNullable<IOptions['customDeserializer']> = Object.create(null);
  Object.assign(customDeserializer, {
    int: integral(-2147483648, 2147483647),
    short: integral(-32768, 32767),
    integer: precise(false),
    long,
    decimal: precise(true),
    double: floating,
    float: floating,
    boolean,
    bool: boolean,
  });
  return { preserveWhitespace: true, customDeserializer };
}
