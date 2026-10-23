# Codex investigation record: Hermes tool bridge and deferred Mordred tools (2026-10-23)

Investigator: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against Mordred a3215fcea and the production Hermes git install 0.21.5 (df81f54). Absolute links were flattened to `path:line` text for this record. The TODO entries "Deferred-tool bridge with the production model" and "Native helper build cache inside the Hermes home" carry the resulting work items.


Read-only investigation of the permitted sources and `agent.log`. No Hermes commands, tests, configuration reads, database reads, or changes were performed. Inspected source revisions: Mordred `a3215fc`; Hermes `df81f54`. Whether production loaded precisely this Mordred revision is **unknown**.

## 1. Origin of `{"names": mordred_mail_sync}`

**Verdict: (a), malformed model/provider output, is the strongest supported explanation; Hermes’s accumulator preserves argument fragments, and the inspected Mordred components do not rewrite them. Definitive attribution to the model rather than Venice is unknown without raw provider responses.**

The log establishes an OpenAI streaming request to `https://api.venice.ai/api/v1`, two completed searches, **five** identical malformed-argument warnings, and a final `failure_reason=truncated`. See agent.log:2416–2426.

The streamed response follows this path:

1. Hermes calls `request_client.chat.completions.create(..., stream=True)`. See agent/chat_completion_helpers.py:3073 and 3183.
2. The stream passes through the optional Relay pipeline. Unmanaged execution iterates the original stream; managed execution encodes chunks and returns original SDK objects when unchanged. Its structural conversion leaves strings unchanged. Relay can deliver intercepted/transformed chunks, but the log does not establish whether that happened here. See agent/relay_llm.py:336, 516, and 905.
3. Hermes reads `chunk.choices[0].delta.tool_calls` and feeds each delta into `_ToolCallAccumulator`. See agent/chat_completion_helpers.py:3235 and 3314.
4. The accumulator groups calls by index/ID, appends `tc_function.arguments` unchanged, and finally assigns `"".join(parts)`. **It neither parses argument JSON nor strips quotation marks.** See agent/chat_completion_helpers.py:2804–2840.
5. `_assemble_tool_calls()` tries `json.loads(arguments)`. On failure with a terminal finish reason, it passes that string to `_repair_tool_call_arguments()`. See agent/chat_completion_helpers.py:3375.
6. The warning prints `raw_stripped`: the input string with only surrounding whitespace removed—not the attempted repair. The repair code does not quote bare identifiers. See agent/message_sanitization.py:229–284.

For a **complete, nonstreamed response**, Hermes calls the same SDK completion API and takes `choices[0].message.tool_calls`; normalization preserves each `function.arguments` value, substituting `"{}"` only when it is `None`. Subsequent validation parses JSON. Historical calls also undergo outbound canonicalization using `json.loads`/`json.dumps`, falling back to the same repair helper for already-malformed strings. None of these paths converts a quoted string into a bare identifier. See agent/chat_completion_helpers.py:789, agent/transports/chat_completions.py:608–672, agent/turn_tool_validation.py:150, and agent/conversation_loop.py:1001–1053.

**The final truncation diagnosis is misleading here.** When repair returns `"{}"`, this streaming caller retains the original malformed arguments and marks them truncated; it then forces `finish_reason="length"`. Hermes retries the same request up to four times without appending the broken response. That explains the five warnings and failure without any tool execution. It does **not** prove an actual output-token limit was reached. See agent/chat_completion_helpers.py:3391, 3456, and agent/turn_truncation.py:400–445.

The Mordred checks found:

| Component | Relevant behavior |
|---|---|
| `llm_guard` | Checks provider/endpoint policy before requests. Auxiliary wrappers check the resolved client and return the original result. No response-chunk or tool-argument transformation was found. llm_guard/__init__.py:196, auxiliary_guard.py:284. |
| `extension/e2e.py` | Decrypts/encrypts Mordred chat-platform envelopes, such as `🔒ENC:v3`. This is separate from Venice’s model name and the LLM response transport. e2e.py:1, 770. |
| `privacy_check` | Inspects already-parsed tool arguments and returns allow/block/approval decisions. Its bridge JSON parsing extracts nested calls for policy checks; it does not re-emit provider arguments. hooks.py:330, egress.py:559–637. |

One correction to the premise: this checkout registers `pre_llm_call` under **dbcrypt**, not `privacy_check`. See plugin.py:81–87.

No Venice/`e2ee`-specific response decoder was found in Hermes’s inspected agent/provider paths. The runtime log identifies the connection as `provider=custom`; Mordred’s local provider is explicitly declarative and leaves streaming to Hermes. See agent.log:2388 and local_adapter.py:1–7.

Thus, there is no source evidence for **(c)** or quotation removal by **(b)**. Missing/misassigned upstream fragments, Relay interception, and Venice’s own tool-output formatting cannot be conclusively excluded from this INFO log.

## 2. Deferral and supported configuration

**Verdict: ordinary registered plugin tools are always eligible for deferral; with `"auto"`/`"on"` they are deferred. There is no supported per-plugin “direct” exemption. Global `"off"` makes selected tools direct.**

`is_deferrable_tool_name()` checks, in order:

- Bridge names: never deferred.
- Explicitly named in `defer`: eligible.
- Names in `_HERMES_CORE_TOOLS`: otherwise direct.
- Other registered tools: eligible unless their registry toolset is `desktop_ui`, `project`, or `setup`.

Mordred’s tools retain their own names and `mordred_telegram` toolset, so they take the last branch. See tools/tool_search.py:140–162 and hermes_tools.py:621–638.

| Exact configuration | Effect and side effects |
|---|---|
| `platform_toolsets.<platform>` | Selects enabled toolsets; does **not** exempt them from deferral. Ordinary Desktop/TUI resolution uses **`platform_toolsets.cli`**, unless an explicit environment pin or coding selection overrides it. Replacing this list can change other available capabilities. |
| `agent.disabled_toolsets` | Suppresses toolsets; cannot make one direct. |
| `tools.tool_search.defer: []` | Removes the curated deferral of core/GUI tools. **Plugin/MCP tools remain deferred.** More core/GUI schemas become eager. |
| `tools.tool_search.defer: [tool_name, ...]` | Replaces the curated list. Entries are **tool names**, not toolset exemptions. Omitting a plugin name does not make it direct. |
| `tools.tool_search.enabled: "auto"` or `"on"` | Equivalent today: activates whenever a deferrable tool exists, or remote connections require the bridge. |
| `tools.tool_search.enabled: "off"` | Keeps all selected, available local tool schemas direct; removes the search/describe/call bridge. This affects other plugin/MCP tools and normally deferred built-ins too. Remote connector discovery/invocation through that bridge is consequently unavailable. |
| `tools.tool_search.listing: "auto"` or `"on"` | Embeds a budgeted catalog: descriptions/names, degrading to smaller forms. Does not expose full schemas directly. |
| `tools.tool_search.listing: "off"` | Removes the embedded catalog, leaving the bridge. Saves prompt space but increases discovery work. |
| `tools.tool_search.listing_max_tokens` | Catalog budget cap; default `4000`, clamped to `200..60000`. |
| `tools.tool_search.threshold_pct` | Catalog budget percentage; default `5`, range `0..100`. **Not an activation threshold in this version.** |
| `tools.tool_search.search_default_limit`, `max_search_limit` | Search-result counts; defaults `5` and `25`, maximum configurable limit `50`. Affect result size, not deferral. |

Evidence: tools/tool_search.py:40–83, 197–214, 351–386, hermes_cli/tools_config.py:564–639, and tui_gateway/server.py:2046–2081.

The comments saying `[]` keeps “every tool eager” are inaccurate for plugins; the executable predicate above is decisive.

For this session, Hermes reported **22 visible tools, 20 deferred tools, approximately 8,427 tokens of deferred schemas**, and a full catalog listing with a 4,000-token budget. Turning deferral off adds those schemas while removing the bridge/catalog; the exact net prompt increase is unknown. See agent.log:2406.

## 3. Search result, `tool_describe`, and bridge instructions

**Verdict: the 1,920-character result’s exact content is unknown. Search does not return full schemas, but its `required: []` metadata is sufficient to attempt this tool’s valid default `{}` call.**

The INFO log records only the result length. In this Hermes version, `tool_search` returns:

- `queries`, `total_available`;
- `results`, containing each query and matching names;
- a shared `tools` map with `source`, `source_name`, clipped `description`, and **required parameter names**.

It does not include parameter types, optional properties, or complete schemas. See tools/tool_search.py:404–414 and 446–486.

For `mordred_mail_sync`, the registered schema has no required parameters. Its only property is optional `max_messages`, integer `1..2000`; `{}` defaults to `2000`. Therefore, if the result included that tool, the default invocation needs no additional schema lookup. See mail_tool.py:86–122.

`tool_describe.names` is advertised as an **array of strings**, but its description and implementation also accept a single JSON string:

```json
{"names": ["mordred_mail_sync"]}
```

This also works:

```json
{"names": "mordred_mail_sync"}
```

An unquoted identifier is invalid JSON and fails before the string-to-list tolerance can help. See tools/tool_search.py:296–308 and 426–443.

The model learns `tool_call` from its directly supplied bridge schema: `calls` is an array whose entries require string `name` and object `arguments`. Hermes describes `tool_describe` as necessary **when parameters are unknown**; the catalog also encourages describing known names. See tools/tool_search.py:262–333.

Mordred supplies a correctly quoted `tool_call` example for **`telegram_ask`**, but no mail-specific example in `SYSTEM_PROMPT`. Its skill does explain mail sync, using “no arguments, or `max_messages` 1–2000,” without a mail-specific bridge example. See hermes_tools.py:552–562 and skill/SKILL.md:207–226.

**Neither instruction set directs the model to emit a bare identifier.** Hermes’s schema lookup instruction explains choosing `tool_describe`; it does not explain the invalid quoting.

Also, absence of literal `tool tool_call completed` lines alone is not proof of bridge failure: Hermes unwraps valid local bridge calls before execution/logging, so success is logged under the underlying name, such as `mordred_mail_sync`. No completion for the four named Mordred tools was found in the permitted log either. See agent/tool_executor.py:395–429 and 1078–1090.

## 4. Recommended changes

**Verdict: add an explicit mail-sync bridge recipe in Mordred; use global tool-search `"off"` for today’s controlled test. Supported registration alone cannot make these named tools direct.**

**(a) Minimal Mordred-side change**

Add a short mail-specific system-prompt section, with wording along these lines:

> When the user asks to sync, refresh, or import mail, use `mordred_mail_sync`. Its default arguments are `{}`. If directly listed, call it with `{}`. If available through the deferred-tool catalog, invoke `tool_call` with:
>
> `{"calls":[{"name":"mordred_mail_sync","arguments":{}}]}`
>
> If its availability is unknown, first use `tool_search` with `{"queries":["mordred_mail_sync"]}`. For this default invocation, the arguments are already known, so no `tool_describe` call is needed. If another invocation needs schema lookup, use `{"names":["mordred_mail_sync"]}`. Tool names are JSON strings.

This removes the unnecessary failing step while preserving the supported bridge. Hermes’s catalog is stateless; calling through it is not contingent on a previous successful describe. See tools/tool_search.py:1–7 and 558–587.

Gate the new section on **mail availability**, independently of Telegram. The current prompt callback requires `tools_available()`, which requires Telethon and Telegram login; mail availability has separate gates. Simply appending mail text to the existing callback would miss mail-only installations. See hermes_tools.py:151–161, 608–610, and mail_tool.py:138–147.

Mirror the recipe in the existing skill’s mail section and mention mail in its registered description, currently Telegram-focused at hermes_tools.py:647–651.

Validate mail-only prompt visibility, both JSON examples against the schemas, and a mocked bridge invocation reaching the sync handler. Actual success with this model remains **unverified** until a live test.

**(b) Owner’s configuration test today**

Merge this into the existing configuration, preserving other `tools` settings:

```yaml
tools:
  tool_search:
    enabled: "off"
```

Fully restart the Desktop/backend and start a new chat, then repeat the mail-sync request. This bypasses the failing bridge interaction while retaining the tool’s availability, provider/privacy, credential, and store checks. The handler still checks the active model before fetching. See model_tools.py:529–543 and mail_tool.py:251–271.

Judge success from returned counts, `error`, and `partial`, not merely the assistant’s prose. Direct exposure does not establish that all downstream gates will pass.

After testing, restore the previous value. If it was absent/default, remove the added `enabled` override or use:

```yaml
tools:
  tool_search:
    enabled: "auto"
```

Restart again. The broader prompt and remote-connector effects are listed in section 2.

**(c) Legitimate direct registration and zero upstream PRs**

There is **no supported `direct`, `eager`, or `defer=False` registration option** in this version. `ctx.register_tool()` accepts name, toolset, schema, handler, availability and presentation fields, plus controlled overrides—not a deferral exemption. See hermes_cli/plugins.py:457–488.

Keeping Mordred’s names and honest toolset therefore cannot produce direct tools while the bridge is enabled. Adding tools to a composite toolset does not change the classifier’s core-name/registry-toolset checks.

Prompt/skill improvements and documented configuration satisfy Mordred’s public integration boundary without Hermes changes. Mutating `_HERMES_CORE_TOOLS` or `_DIRECT_SURFACE_TOOLSETS` would be an unsupported private-internals workaround, not legitimate direct registration. The project explicitly prefers public plugin hooks/wrappers and prohibits upstream PRs. See docs/dev/UPSTREAM.md:21–33.

## 5. Xcode `build.db` false positive

**Verdict: the reported path is incorrectly included by the current scope rules. Repeated checking is confirmed; a fresh audit on every LLM call is not supported by this checkout.**

The mechanism is:

1. `DENY_DIRS` contains `mordred` and `hermes-agent`, but **not `plugins`**.
2. Both discovery pruning and `in_scope()` inspect the first directory relative to the home/profile home. In the reported path that is `plugins`; the nested `mordred` component does not help.
3. `build.db` matches `looks_like_database_name()`.
4. Discovery classifies a matching SQLite file as plaintext when stdlib SQLite can read its schema.

See _policy.py:21–79, _migrate.py:87–91, and _migrate.py:105–149. The actual database was not inspected.

The build-location explanation is consistent with source: the helper locator can select packaged `_native/sekey-helper`; the CLI runs `build.sh` there; the script changes into its source directory and invokes Swift without an explicit scratch location. See _seckey_helper.py:162–193, keyvault_native_cli.py:74–98, and native/sekey-helper/build.sh:14–63.

The monitor caches deep-discovery paths for 300 seconds and checks candidates for plaintext on subsequent checks. Hooks run at session start and `pre_llm_call`; strict mode refuses, lenient mode supplies warning context. However, `_reported` deduplicates auditing by **event and finding description per process**. Thus repeated warnings/checks are expected, but identical audits every call require another explanation or different deployed code. See _monitor.py:72–98, 133–157, and _hooks.py:94–128.

The narrowest correction is a **shared exclusion for the known helper’s `.build` subtree**, applied consistently to discovery pruning and `in_scope()`, including profile homes. Adding `.build` to the existing top-level `DENY_DIRS` alone would not work.

Adding `plugins` to `DENY_DIRS` is a smaller code change and coherent if all installed plugin source trees are explicitly outside encryption scope, but it is a broader exclusion. Do not exclude `plugin-data`, all files named `build.db`, or all nested databases.

For prevention, give Swift an explicit scratch directory under an already-excluded cache or a temporary build directory, consistently for both binary-path lookup and compilation. Relocation alone does not address existing artifacts.

Tests to add:

- Exact reported path and profile-home equivalent are out of scope and never classified; neighboring legitimate databases remain in scope. Extend tests/test_dbcrypt.py:22 and tests/test_dbcrypt_migrate.py:69.
- A synthetic helper build database causes no monitor violation, while a recreated plaintext `state.db` still does; repeated identical findings retain audit deduplication. Extend tests/test_dbcrypt_monitor.py:41.
- Mocked Swift invocations use the same external scratch directory and leave no source-tree build database, while preserving atomic installation behavior. Extend tests/test_native_helper_build_scripts.py:25.

## What to do today

1. Temporarily set `tools.tool_search.enabled: "off"`, restart, and test mail sync in a new chat.
2. Record counts/errors and check for `mordred_mail_sync` completion; restore the previous deferral setting afterward.
3. Implement the explicit mail bridge recipe and separately fix database build-artifact scope. Increasing `max_tokens` is not supported as the primary remedy by this evidence.