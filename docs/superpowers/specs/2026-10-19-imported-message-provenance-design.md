# Imported-message provenance for encrypted archives and state.db

Status: proposed design for review; not implemented or an acceptance claim.

## Revision 2026-10-22

The `state.db` adapter and the "Both backends enabled" mode are dropped by owner
decision. Hermes reads imported history only through a Mordred-owned tool
(`mordred_history_search`); nothing is copied into `state.db`. The canonical
store is `<home>/plugin-data/mordred/mordred.db` (SQLCipher only, macOS-only);
Linux and Windows keep the `.enc` archive. The record contract, rendering,
evidence, reader-session and acceptance sections below still apply; the
"### state.db" and "### Both backends enabled" sections are retained for history
only. The authoritative contract is `docs/dev/SPEC.md`
§Imported message provenance (2026-10-22).

## Intent and scope

Apply the user's eight attribution, evidence, and action-safety requirements
to BOTH Mordred's encrypted message archive and imported conversations stored
in Hermes's `state.db`. Neither storage format alone establishes provenance or
instruction authority. Each backend must work independently; enabling support
for both does not authorize duplicating private history into both stores.

Retain the existing Telegram encrypted archive and privacy-model architecture.
Use one source-neutral record contract, two storage adapters, and shared
rendering, evidence validation, and reader-session policy. Telegram is the first
live collector. Google Chat and mail records participate in contract tests;
production collectors for those services are separate work and are not implied
by adding a backend or declaring a source enum.

This proposal crosses extension, privacy-check, and runtime integration owners.
Following AGENTS.md, specification/planning review precedes implementation.
The current contracts in `docs/dev/SPEC.md` and `docs/dev/PLAN.md` are unchanged.
Implementation must reconcile them, TODO, PATHS, CI, and hook-contract documents
without renaming existing headings.

## Observed baseline and compatibility

- `extension/telegram/store.py` stores sender display name, text, outgoing flag,
  reply ID, date, and media kind. It does not preserve stable sender IDs or
  forwarding provenance.
- `extension/telegram/ask.py` emits `chat`, `from`, `date`, and `text`. Owner
  messages use `me`; reply provenance is not emitted. Selection is performed
  after decrypting candidate chats, with a bounded model context.
- `extension/telegram/hermes_tools.py` returns generated answers, coverage, and
  search metadata. It does not return independently validated evidence records.
- `privacy_check/egress.py` currently recognizes the Telegram tools as taint
  sources, treats `session_search` as local, keeps taint in process memory, and
  permits policy `off` to bypass its tool-egress checks.
- The repository venv inspected for this proposal contains Hermes 0.19.0.
  Its `SessionDB.append_message` does not expose `display_metadata`; the separate
  local upstream checkout does. Never assume the checkout is the running wheel.
- Both inspected search implementations omit arbitrary metadata in shaped
  model-visible messages. The checkout additionally has 1,200/2,000/4,000-char
  caps in different paths. Those numbers are compatibility examples, not a
  universal contract or permission to rely only on a body prefix.
- The inspected 0.19.0 plugin API supports explicit tool override with operator
  opt-in. `transform_tool_result` is fail-open and therefore cannot be the sole
  provenance or policy boundary.

Use Mordred-owned code and supported plugin/wrapper interfaces. Do not edit the
installed Hermes package or submit upstream PRs. A backend or retrieval path
whose required contract cannot be enforced is unavailable in protected mode;
it must not silently degrade to an unprotected path. Supporting the package's
Hermes dependency floor does not imply this new feature works on every release.

## Alternatives and selected approach

1. Prefixes and prompt guidance only: small change, but insufficient for missing
   source data, validated citations, replay, or tool-execution controls.
2. Shared provenance contract with separate adapters: selected. It preserves
   each storage option while allowing the same cases and safeguards to exercise
   both paths. Standard Hermes recall needs explicit integration and gates.
3. Consolidate all history into state.db: unnecessary for these requirements
   and would expand the migration and privacy scope. It is not this proposal.

## Canonical record and trust

Each logical message has a versioned record containing:

- Source service, source account, conversation ID, message ID, source revision
  when available, import time, and an idempotent namespaced source UID.
- Sent timestamp with its offset/UTC representation and observed conversation
  title. Missing dates remain unknown rather than using import time as sent time.
- Transport sender identity, typed as user/bot/channel/unknown; stable source ID
  when available; observed display name; and owner classification
  `account_owner`, `other`, or `unknown` with the evidence for that classification.
- Separately attributed authored, quoted, and forwarded parts. Each part has its
  own ID, original author evidence, original time when known, and references to
  the containing message and source message when available.
- Original text and source-provided quote/forward/reply metadata, preserving
  information necessary to revisit a normalization error.
- Explicit provenance quality: API identity, source-claimed identity, heuristic
  segmentation, or unknown. Quoted mail headers and manually typed attributions
  are not authenticated sender identities.

Do not infer identity from a display name. An outgoing flag identifies a sending
event, not authorship of every contained quote/forward. Channel, anonymous,
saved-message, forwarded-message, and missing-ID cases must stay distinguishable.
Do not infer a complete participant list from the speakers observed in a sample.

All imported parts, including the account owner's historic words, are reference
data with no authority to trigger a present action. Content cannot create a
trusted author label, source UID, approval, or policy transition. Display strings
are bounded and escaped; aliases are assigned by stable identity when available,
not by display name. Unknown identities are not merged on a guessed name.

## Storage adapters

### Encrypted archive

Version the JSON payload inside the existing encrypted archive. Retain its
AES-GCM envelope, filename protection, native-key custody, and private-file
rules. No plaintext index or migration dump is introduced. Reading legacy
records produces explicitly incomplete provenance until source data is obtained.

### state.db

Use imported archive sessions distinct from live interactive conversations.
Never inject an import as a new live user turn or automatically run an imported
session's last message. Imported message projections use `role=user`; the role
does not identify the historical speaker or grant instruction authority.
Neither `observed` nor a source tag alone substitutes for a rendered provenance
envelope or an enforced reader boundary.

Keep canonical records and source-to-row mappings in versioned Mordred-owned
tables within the SAME database, with a `mordred_import_` namespace. This allows
state.db-only operation without an `.enc` sidecar. Existing Hermes tables and
columns retain their meanings; preserve unrelated metadata and native messages.
When `display_metadata` is supported, add a namespaced provenance reference as
an additional projection, not the sole authoritative record.

Generate each model-visible projection from the canonical record, starting with
a compact untrusted-history label, source/evidence ID, part kind, author, and
sent date. Each independently returned chunk carries its own attribution. Store
quoted/forwarded parts as separately attributed projections linked to their
container; do not invent unrelated original conversations. Generate titles and
participant labels without a model.

The protected reader exposes only complete, validated imports. A transaction or
durable staging journal must prevent a failed import from exposing native rows
without their canonical records; retries repair or quarantine the partial batch.
Verify Hermes API transaction semantics, schema upgrades, backups, recovery,
FTS rebuilding, and deduplication before enabling this adapter on a version.
Orphaned/mismatched records refuse verified-evidence rendering.

Database encryption is a separate property. Importing private Telegram history
into state.db must not silently weaken the existing encrypted-at-rest contract:
production private imports require verified database protection on a supported
platform. Current SQLCipher support is macOS-only and opt-in; enabling this
feature does not run `databases encrypt` or change production settings. Plain
SQLite fixtures can test attribution, but do not prove equivalent privacy.

### Both backends enabled

Destinations are explicit. If an operator chooses both, source UIDs and part IDs
provide cross-backend deduplication. Two copies are not two independent witnesses.
Revisions and removals must not silently leave an obsolete copy presented as
current evidence. A missing source or conflicting revision is reported rather
than resolved by whichever backend answers first.

## Retrieval and answer boundary

Both adapters return the same canonical evidence objects to a shared selector
and renderer. Include coverage, last import time, missing dependencies, and
truncation; absence from a partial search is not absence from the archive.
Headers must survive chunking and shortening. FTS snippets or middle-of-message
matches must be hydrated from canonical records before being treated as evidence.

Keep the dedicated privacy LLM for synthesis. Its structured answer refers to
IDs from that request's evidence set. Code validates ID membership, source
revision, part attribution, timestamps, and exact quote ranges, then renders
source cards from stored data. Never trust a model-generated author/date/quote
as the authoritative card. Invalid evidence yields a bounded retry or an explicit
unverified/insufficient-evidence result, never a fabricated verified citation.
Correct citations do not prove the semantic correctness of a model's summary.

Hermes receives the answer plus validated, minimal evidence records under the
existing allowed-model and protected-memory rules. The original entire message
archive is not exposed. User-visible evidence must survive the main model's
paraphrasing: a deterministic renderer appends/cards the verified references.
A surface lacking that renderer cannot claim mandatory visible evidence.
Source links resolve through the protected local reader, without credentials or
raw private text in URLs, ordinary logs, temporary files, or metrics.

## Standard Hermes recall and execution controls

state.db support includes discovery/search, browse, scroll, full-session read,
and imported-session open/resume. A standalone safe search tool while leaving
the built-in reader unguarded is not full coverage. Use an explicitly configured
Mordred tool wrapper/override for the built-in name where supported, and verify
normal and deferred-tool/bridge invocations. Bare prefixes and result-transform
hooks are defense in depth only. Unprotected access to imported data is refused
within the protected runtime.

Reader sessions become read-only BEFORE private data can enter model context.
Enforce an explicit allowlist, including argument validation and permitted model
destinations. Block writes, arbitrary execution, outgoing messages/payments,
unknown tools, and delegations that cannot preserve the boundary. Generic egress
`off`, missing session identity, missing guards, or failed provenance lookup must
not permit protected reading with unrestricted actions.

Persist reference-data exposure through trusted application state. Reload,
restart, context compression, session search, copied summaries, and descendant
sessions must preserve the restriction or refuse the transition. Historical
summaries remain derived untrusted data, even when stored with `role=assistant`.
Do not clear the restriction merely because a new user turn arrives.
Parallel tool batches must not race a private read against a previously admitted
side effect; a reader mode is established before dispatch, with incompatible
in-flight work excluded.

Imported archive sessions are browsable records, not runnable instructions.
Resuming a derived conversation requires the protected reader context before
context assembly. If the supported plugin interfaces cannot establish this,
that resume path is disabled. Adoption of additional hook fields requires
changes to the machine hook contract and compatibility tests.

The first version provides reading and answers, not an action-approval system.
Any future action flow needs a separate trusted current-user request and
action-bound authorization. Claims apply to validated Mordred-controlled
runtimes and entry points, not arbitrary same-user programs reading SQLite or
an unmodified Hermes installation with Mordred removed. The zero-PR and OS
containment limits in UPSTREAM and ROADMAP remain in force.

## Eight-requirement acceptance matrix

| Requirement | Shared acceptance condition | Encrypted archive checks | state.db checks |
|---|---|---|---|
| 1. Determine speaker at import | Stable identity and explicit owner/other/unknown; no name-based guessing | New/legacy record round trips and identity-based aliases | Canonical mapping plus visible prefix; missing metadata and old schemas |
| 2. Separate quotes/forwards | Transport sender and part author remain distinct; unknown stays unknown | Forward/reply metadata, manual quotes, absent originals | Separate attributed projections and source links, no duplicate witnesses |
| 3. Do not identify people by role | Historic owner text is reference data, never a current command | Bounded reference envelope, no invented assistant turns | Imported user rows; no live injection or executable imported-session resume |
| 4. Include participants in titles | Deterministic labels with bounded, escaped names and explicit unknowns | Individual/group/channel displays | Session titles, result lists, and independent returned chunks |
| 5. Avoid unnecessary rewriting | Labels and source excerpts come from code; synthesis may use a model | Shared evidence renderer | Same renderer through native recall integration |
| 6. Always expose evidence | Validate allowed IDs, authors, dates, exact quotes; display independently | Selected evidence to privacy LLM to main model/UI | Hydrated FTS/scroll/read evidence to main model/UI, including truncation |
| 7. Prevent actions from imported text | Reader mode enforced before exposure and preserved through replay | Direct tool, UI, and bridge paths | Standard recall, resume, derived summaries, restart, compaction, and bridge |
| 8. Measure actual models | Evaluate attribution and evidence separately from execution denial | Same fixtures through archive pipeline | Same fixtures through database pipeline, including both-store mode |

## Evaluation and migration

Create labeled synthetic threads covering distinct and identical display names,
aliases, owner/other mixed promises, forwards by the owner, nested quotes,
missing original authors, bot/channel identities, unknown dates, partial imports,
long messages, forged labels, and embedded action requests. Reuse identical
logical records across both adapters and both-store mode.

Unit/integration tests prove record preservation, no information promotion,
idempotency, failure recovery, deterministic source cards, cap/chunk behavior,
policy refusal, races, and durable restrictions. Execute the full implicated
security modules and applicable explicitly gated native paths under repository
CI policy. Use isolated homes; never import or alter production history for tests.

Run opt-in evaluations on the actual configured privacy and Hermes models,
recording model/version, prompt version, sampling settings, repetitions, backend,
coverage, and expected answers. Report owner/other swaps, quote/forward
misattribution, unsupported claims, citation validity, and abstention separately.
Missing models or failed runs are unavailable evidence, not passing scores.
The proposed release thresholds are zero critical attribution swaps, at least
95% correct grounded answers on fully answerable cases, valid rendered evidence
for every verified claim, and abstention on required unknown-author cases.
Score all answerable cases, including refusals, so a model cannot pass by
declining every question. Require zero forbidden executed actions in the
adversarial tool suite. Finite tests do not establish zero real-world errors.

Legacy records are not silently relabeled as fully verified. Backfill source
metadata only from authorized source reads; otherwise retain unknowns. Preserve
encrypted originals and use a dry-run migration report before changing existing
data. Ordinary native Hermes conversation rows are not reclassified wholesale.
Unrecognized historic imports require inventory and an explicit source mapping.

## Delivery boundaries

1. Review this cross-component specification and the implementation plan before
   product changes. Establish supported runtime capabilities with synthetic data.
2. Implement the shared record/normalizer and encrypted-archive migration with
   deterministic rendering and source validation.
3. Implement the state.db adapter and guarded native recall/resume integration;
   enable only the capability combinations demonstrated by tests.
4. Complete mandatory reader policy and the same acceptance matrix on both
   backends before claiming end-to-end coverage.
5. Execute real-model evaluation and relevant native acceptance; publish measured
   limitations and update the source-of-truth documentation at integration.

Search-index performance improvements and Google Chat/mail production collectors
remain separate deliveries. They must reuse this contract when introduced.
