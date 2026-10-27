<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Changelog

## 0.1.0

- Add the opt-in AMQPS plugin with verified TLS, secret references and bounded native recovery.
- Complete the required typed trusted topology and publisher-routing catalog.
- Normalize bounded header values through the pinned native codec with lossless int64 handling.
- Implement native confirm publications, correlated mandatory returns and explicit unknown outcomes without automatic republishing.
- Add bounded manual-ack consumers, generation-scoped acknowledgments, safe handler failure and lifecycle draining.
- Add fixed-label diagnostics and real-broker permission, TLS, recovery and multi-instance tests.
- Document outstanding broker-restart and independent packaged application validation.
