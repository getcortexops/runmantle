# Verified Action Cache

`VerifiedActionCache` is a small in-memory cache of compact, verified execution
recipes. It reduces repeated planning for the same operation; it is not a
general memory system and it does not replay a previous authorization, receipt,
or side effect.

Each `VerifiedActionRecipe` records normalized intent, a tool/capability
sequence, relevant inputs, data-only preconditions, execution strategy,
expected outcome, verification evidence, version, source task/run IDs, and
the original run's token usage. `store()` rejects any recipe not marked both
successful and verified.

`execute_or_fallback()` uses exact intent-and-input matching first. Its simple
`RecipeSimilarityMatcher` interface supports later semantic retrieval; the
built-in matcher only accepts high-overlap wording changes with identical
relevant inputs. Before executing a candidate, the application must provide a
fresh `RecipePreconditionValidator`. A missing or failed check falls back to
normal agent execution. The cache records hits, misses, validation failures,
fallbacks, successful reuses, and tokens avoided versus the recorded baseline.

The supplied `governed_executor` is deliberately required for every reuse.
Route it through `MediatedActionExecutor` or `SafeFunctionTool`; RunMantle will
then apply current policy, permissions, approvals, preconditions, and runtime
confirmation before the action handler runs. Cache reuse never grants an
approval and never calls a side-effect handler itself. The supplied verifier
runs again after both normal and reused executions. If that repeat verification
fails, the result is `REUSE_UNVERIFIED`; the cache does not automatically retry
the side effect.

## File-write demo

`FileWriteCacheDemo` wires this pattern for a small file-write workflow. Supply
an `agent_discovery` callback for the first-run reasoning and a
`governed_writer` callback that uses the mediated action boundary. The demo
stores the initial and desired content hashes. A later identical or reordered-
wording task may reuse the recipe only if the current file is still at one of
those safe states; an unrelated intervening edit invalidates the recipe and
uses normal discovery again. The result's file hash is observed and checked
after every write.

## Hermes integration

The CortexOps Hermes control plugin uses this cache on the real Hermes turn
path. It looks up a verified strategy before LLM planning, validates current
tool, capability, argument, and probe identities at `pre_tool_call`, and then
continues through the normal policy, approval, dispatch, receipt, runtime-
confirmation, and verification sequence. It stores no recipe for failed,
unconfirmed, inconclusive, or unmeasured runs.

Hermes's normalized `post_api_request` usage is the only token source. The
plugin aggregates the provider-reported input and output tokens for the turn
and reports a measured baseline and measured reuse to CortexOps. It never
derives token savings from prompt length or substitutes an estimate when
Hermes did not report usage.
