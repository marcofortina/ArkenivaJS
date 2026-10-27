<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Changelog

## 0.1.0

- Define optional SOAP client, profile and native ownership contracts.
- Admit bounded offline contracts before using the actual native WSDL compiler.
- Decode versioned SOAP responses in owned workers with deadlines and cleanup.
- Reject implicit imports, hostile XML and native method name collisions.
- Normalize an upstream MIT metadata declaration without altering runtime code.
- Capture bounded local WSDL/XSD import graphs and compile them through the native
  cache without implicit filesystem or network resolution.
