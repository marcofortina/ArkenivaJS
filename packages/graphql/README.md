# @arkenivajs/graphql

GraphQL resolver, field authorization, batching, subscription and administrative service contracts. This foundation exports types and a capability identity; it does not yet register a listener, provide `graphqlPlugin` or execute GraphQL operations.

The selected integration is Mercurius 16.12.1 and GraphQL 16.14.2 over the existing Fastify 5.12.7 server. Core and REST-only applications do not import this optional package. Runtime transport, authorization, resource-limit, loader and subscription evidence must pass before claiming implemented GraphQL support.

Anonymous policy requires an explicit list of public `Query.<field>` roots and a reason. Every resolved field needs an application authorization decision; a tenant argument is never authentication evidence. Batch results retain order, length and null entries. Subscription delivery requires verified tenant provenance and a shared production backend, with bounded transport and periodic revalidation.
