<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Repository instructions

## Permanent commit message policy

Every commit created by Codex in this repository must follow Conventional
Commits and include both a subject and a meaningful, non-empty body. This
policy has no exceptions, including minor fixes, tests, documentation,
maintenance and CI changes.

Use this structure, omitting the scope and its parentheses only when no
reliable component scope applies:

```text
<type>(<scope>): <imperative subject>

<Explain the actual changes and their technical motivation.>
```

- Write the entire commit message in English.
- Inspect the actual staged diff before choosing the type, scope and text.
- Use the most accurate type: `feat`, `fix`, `refactor`, `perf`, `docs`,
  `test`, `build`, `ci`, `chore`, `style` or `revert`.
- Include a scope whenever the affected component can be identified
  reliably.
- Start the subject with a lowercase imperative verb, preserving the
  correct spelling of proper names and acronyms.
- Keep the subject concise, ideally within 50 characters, and do not end
  it with a period.
- Separate the subject and body with exactly one blank line.
- Wrap body lines at 72 characters.
- Explain what changed and why using details supported by the diff.
  Never invent functionality, fixes, motivations or implementation facts.
- Never use a single-line message, empty body or generic descriptions
  such as "Update code" or "Improve implementation".
- Preserve relevant technical details, attribution and meaningful commit
  trailers.
- Use a `BREAKING CHANGE:` footer only when the actual changes justify it.

Apply this policy automatically in every future development session;
the user does not need to repeat it.
