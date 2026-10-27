#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu
umask 077
mkdir -p /data
if ! slapadd -f /fixture/slapd.conf -l /fixture/seed.ldif > /tmp/seed-output 2>&1; then
  echo 'Owned LDAP fixture initialization failed' >&2
  exit 1
fi
exec slapd -f /fixture/slapd.conf -h 'ldap://0.0.0.0:1389 ldaps://0.0.0.0:1636' -d 0
