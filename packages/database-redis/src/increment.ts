// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Atomic range checks precede INCRBY, preserve TTL and prevent unsafe results from mutating state. */
export const SAFE_INCREMENT = `
if redis.call('STRLEN', KEYS[1]) > 17 then
  return redis.error_reply('ARKENIVA_INTEGER_RANGE Unsafe integer')
end
local raw = redis.call('GET', KEYS[1])
local current = 0
if raw then
  if raw ~= '0' and not string.match(raw, '^%-?[1-9]%d*$') then
    return redis.error_reply('ARKENIVA_INTEGER_RANGE Unsafe integer')
  end
  local digits = string.gsub(raw, '^%-', '')
  if #digits > 16 or (#digits == 16 and digits > '9007199254740991') then
    return redis.error_reply('ARKENIVA_INTEGER_RANGE Unsafe integer')
  end
  current = tonumber(raw)
end
local amount = tonumber(ARGV[1])
local next = current + amount
if next > 9007199254740991 or next < -9007199254740991 then
  return redis.error_reply('ARKENIVA_INTEGER_RANGE Unsafe integer')
end
return redis.call('INCRBY', KEYS[1], ARGV[1])
`;

/** Check length and fetch within one read-only script, preserving null versus empty text. */
export const BOUNDED_GET = `
if redis.call('STRLEN', KEYS[1]) > tonumber(ARGV[1]) then
  return redis.error_reply('ARKENIVA_VALUE_LIMIT Value exceeds the portable byte limit')
end
return redis.call('GET', KEYS[1])
`;
