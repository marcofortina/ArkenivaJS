<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Changelog

## 0.1.0

- Capture native cancellation independently of later caller hook changes and reject proxy signals or excessive prototype traversal before workbook admission.
- Verify malformed ZIP/XML entry identity, resource and cell boundaries, missing metadata, unsupported native style fidelity and minimal explicit formatting.
- Add explicitly registered XLSX reading and streaming writing through the native ExcelJS engine.
- Preserve typed values, date epochs, controlled styles and formula caches without formula evaluation.
- Bound ZIP/XML expansion, worksheet resources, temporary storage, child ownership and target backpressure.
- Expose generic workbook failures and content-free SDK diagnostics.
