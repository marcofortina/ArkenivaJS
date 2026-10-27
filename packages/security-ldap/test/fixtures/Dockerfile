# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
ENV DEBIAN_FRONTEND=noninteractive
RUN rm /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20261026T000000Z trixie main' \
      'deb http://snapshot.debian.org/archive/debian-security/20261026T000000Z trixie-security main' \
      > /etc/apt/sources.list \
    && printf '%s\n' 'slapd slapd/no_configuration boolean true' | debconf-set-selections \
    && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends slapd ldap-utils openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
