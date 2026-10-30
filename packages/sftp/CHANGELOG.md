<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Changelog

## 0.1.0

- Capture native cancellation independently of later caller hook replacement; reject proxy signals and excessive prototype depth before managed request admission.
- Attach SSH channel output, exit and close handlers inside the native callback before yielding, preserving fast command completion status.
- Add named, host-pinned native SFTP profiles and lifecycle-owned SSH clients.
- Stream bounded transfers, validate remote roots and expose capability-aware rename receipts.
- Restrict SSH commands through trusted catalogs and native shell-quote escaping.
- Add cancellation, secret expiry, safe diagnostics, real OpenSSH tests and a packed consumer.
