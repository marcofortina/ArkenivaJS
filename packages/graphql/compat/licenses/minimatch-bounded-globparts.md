# minimatch 10.2.6 preprocessing security backport

This compatibility patch carries only the runtime correction from Isaac Z.
Schlueter's signed upstream commit
[`77a0f5c4b80bdc641c3c930a1d9edf5ad2db57f8`](https://github.com/isaacs/minimatch/commit/77a0f5c4b80bdc641c3c930a1d9edf5ad2db57f8),
"limit **/.. optimization pass to avoid quadratic explosion", for
[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249).
The upstream correction was published in minimatch 11.0.1. This is a local
backport to 10.2.6, not an upstream 10.x release or a version-based advisory waiver.

The correction bounds additional `**/..` optimization alternatives using the
existing `braceExpandMax` option (default 100,000) and skips optional pairwise
pattern deduplication above 1,000 alternatives. It preserves minimatch 10's regex
matcher, AST, declarations and public API; it does not adopt the version 11 matcher
or its dependency. Pattern alternatives are not truncated. These bounds address
the identified preprocessing amplification, not every possible expensive pattern.

The npm archive is pinned by its existing integrity:
`sha512-vpLQEs+VLCr1nU0BXS07maYoFwlDAH0gngQuuttxIwutDFEMHq2blX+8vpgxDdK3J1PwjCJiep77OitTZ4Ll1A==`.
Both CommonJS and ESM JavaScript entrypoints and their embedded TypeScript source
maps are regenerated with the existing TypeScript 6.0.3 compiler. Original inputs
reproduce the published JavaScript, declarations and maps byte for byte. Declaration
text stays unchanged; declaration maps are regenerated for shifted source lines.
The optional explanatory addition to the upstream option's JSDoc is documented
here instead of changing the existing public declarations.

minimatch remains licensed under BlueOak-1.0.0. Upstream license text follows
unchanged; the framework license does not replace this dependency's license.

# Blue Oak Model License

Version 1.0.0

## Purpose

This license gives everyone as much permission to work with
this software as possible, while protecting contributors
from liability.

## Acceptance

In order to receive this license, you must agree to its
rules. The rules of this license are both obligations
under that agreement and conditions to your license.
You must not do anything with this software that triggers
a rule that you cannot or will not follow.

## Copyright

Each contributor licenses you to do everything with this
software that would otherwise infringe that contributor's
copyright in it.

## Notices

You must ensure that everyone who gets a copy of
any part of this software from you, with or without
changes, also gets the text of this license or a link to
<https://blueoakcouncil.org/license/1.0.0>.

## Excuse

If anyone notifies you in writing that you have not
complied with [Notices](#notices), you can keep your
license by taking all practical steps to comply within 30
days after the notice. If you do not do so, your license
ends immediately.

## Patent

Each contributor licenses you to do everything with this
software that would otherwise infringe any patent claims
they can license or become able to license.

## Reliability

No contributor can revoke this license.

## No Liability

**_As far as the law allows, this software comes as is,
without any warranty or condition, and no contributor
will be liable to anyone for any damages related to this
software or this license, under any kind of legal claim._**
