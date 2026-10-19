# Telegram Local LLM Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make Telegram local-model failures actionable, support authenticated loopback servers, and explicitly verify the saved model configuration.

**Architecture:** Retain the existing Telegram service and OpenAI-compatible streaming client. Add sanitized local failure details without changing existing error codes, store an optional local API key in the existing sealed credential record, and add an opt-in doctor probe that uses the same target and streaming client. Normal doctor remains metadata-only.

**Tech Stack:** Python >=3.11, aiohttp, argparse, pytest, existing hardware-sealed Telegram stores.

**Spec:** `docs/dev/SPEC.md` section "Telegram import", and the in-chat design accepted on 2026-10-12 (diagnostics, sealed local authentication, explicit live probe, synthetic tests followed by real-server validation).

## Global Constraints

- Imported text goes only to Venice (fixed URL, private models) or a loopback model.
- No proxy environment variables and no redirects for local requests.
- No production Hermes state or real Telegram content in tests; isolate HERMES_HOME.
- API keys remain sealed and must not occur in metadata, repr, tool errors, audit records, or diagnostic output.
- Diagnostics show scheme, loopback address and port only; arbitrary URL paths may contain secrets.
- Preserve existing top-level error codes, including local_llm_unauthorized for HTTP 401.
- Ordinary doctor does not unseal credentials; only --probe-llm opts into a fresh unseal and local inference.
- No new runtime dependencies, no changes to unrelated plugins, and no upstream PR.
- All repository documentation is English; keep existing headings.

## Review Focus

- Changing endpoints must not silently forward an old endpoint's stored API key.
- HTTP 200 followed by a truncated stream, empty response, or timeout must not report probe success.
- Redirect targets, response bodies, exception strings and arbitrary URL paths must not enter diagnostics.
- Old sealed records without a local key remain readable on every custody backend.
- A probe must load the saved target freshly and never read the message archive or contact a cloud backend.

## Task 1: Preserve safe local failure evidence through telegram_ask

**Files:** `src/mordred_hermes/extension/telegram/venice.py`, `service.py`, `hermes_tools.py`; new `tests/extension/test_telegram_local_llm.py`.

**Interfaces:** `VeniceError(code: str, *, detail: dict[str, str | int] | None = None)`; local details contain `endpoint` (origin only), `failure` (http_error, timeout, connection_failed, transport_error, invalid_response), optional `http_status`, and a constant remediation `hint`. The tool adds `detail` only for this reviewed exception type. `TelegramService.ask` emits `telegram.ask.failed` with code and safe local details.

- [x] Add a real loopback HTTP fixture and synthetic encrypted archive. Through the real service and Hermes tool assert 401 retains its code, 404/500/307 retain unavailable, and closed-port/timeout failures have distinct details. Assert no redirect is followed and secrets in paths/bodies/exceptions are absent.
- [x] Run `uv run pytest -q tests/extension/test_telegram_local_llm.py` and observe missing diagnostic failures.
- [x] Implement the local error details and failure audit event. Leave Venice errors and successful response envelopes compatible. Do not record raw exception messages or response bodies.
- [x] Run the new module plus `test_telegram_tee.py`, `test_telegram_hermes_tools.py`, `test_telegram_api.py`, `test_telegram_dates.py`, and `test_telegram_import.py`; expect all passing.
- [x] Commit as `fix(telegram): retain safe local LLM failure diagnostics`.

## Task 2: Seal and use optional local authentication

**Files:** `src/mordred_hermes/extension/telegram/secrets.py`, `llm.py`, `service.py`, `venice.py`; `src/mordred_hermes/wizard/telegram_cli.py`, `_cli_parsers.py`; `tests/extension/test_telegram_tee.py`, `test_telegram_local_llm.py`.

**Interfaces:** Add `TelegramSecrets.local_api_key: str | None = None` and optional `local_api_key` to `resolve_target`. Extend `telegram local-llm` with mutually exclusive `--api-key` (hidden prompt), `--api-key-env NAME` (one-time import), and `--clear-api-key`. With no key option, retain a key only when the normalized endpoint is unchanged; clear it on an endpoint change. `telegram_local_llm` receives those options plus the existing injectable secret input function.

- [x] Test sealed roundtrip and metadata/repr redaction, legacy decoding, missing/empty environment values refusing before writes, same-endpoint preservation, endpoint-change clearing, and explicit clearing. An authenticated HTTP fixture must reject before configuration and return an answer after the real CLI configuration is stored.
- [x] Run the relevant new tests and observe failure before implementation.
- [x] Implement optional sealed field, endpoint-bound key reuse and request Authorization. Hide keys in target/config repr as well as TelegramSecrets repr.
- [x] Run both complete affected test modules and Windows Telegram custody/CLI modules; expect all passing.
- [x] Commit as `feat(telegram): support sealed local LLM API keys`.

## Task 3: Explicit doctor probe of the saved local model

**Files:** new `src/mordred_hermes/wizard/telegram_llm_probe.py`; `telegram_setup_cli.py`, `_cli_parsers.py`; new `tests/extension/test_telegram_llm_probe.py`.

**Interfaces:** Add `telegram doctor --probe-llm`; `telegram_doctor(*, as_json: bool = False, probe_llm: bool = False) -> int`. A dedicated helper returns the existing `Check` shape and replaces the privacy_llm row. It freshly loads credentials through the platform's default store, resolves the same target as ask, refuses non-local backends without network access, and consumes a fixed synthetic prompt through `venice.stream_chat` with a 30-second total deadline and 512 output tokens. It reports the origin and configured model, sanitized failure detail and a fix hint. Empty visible output is a failed probe.

- [x] Test ordinary doctor never loads credentials or contacts a server and says connection not checked. Test explicit probe CLI exit status/JSON against authenticated success, 401, wrong path, connection failure, empty/truncated stream and timeout. Test unknown/unconfigured/cloud backend and custody refusal without archive access.
- [x] Run `uv run pytest -q tests/extension/test_telegram_llm_probe.py` and observe the missing option/probe failures.
- [x] Implement the opt-in probe and ordinary status wording. Reuse the same URL normalization, sealed key, request builder, direct session and diagnostic classification as ask; close sessions on every outcome.
- [x] Run the new module and complete Telegram setup/Windows doctor modules; expect all passing.
- [x] Commit as `feat(telegram): probe saved local LLM configuration on request`.

## Task 4: Document, validate and review

**Files:** `docs/user/TELEGRAM.md`, `docs/dev/SPEC.md`, `docs/dev/CI.md`, `src/mordred_hermes/extension/telegram/skill/SKILL.md`; explicit live-gated test in `tests/extension/test_telegram_local_llm.py` or a dedicated Telegram integration module.

- [x] Document /v1 base URL semantics, separate Telegram model settings, auth options and endpoint-change behavior, default doctor limitations, opt-in probe and errors. Keep existing headings.
- [x] Add/run an explicitly gated synthetic Telegram-to-real-model roundtrip. Inspect existing Ollama availability first; use a small model if available. For llama.cpp authentication/Linux-specific acceptance, record precisely what ran and any unavailable hardware/server gate; never present mock tests as live evidence.
- [x] Run `uv run ruff check src tests scripts`, `uv run ruff format --check src tests scripts`, `uv run mypy --strict src tools scripts/keyvault_offline_digest.py`, and `shellcheck scripts/*.sh native/*/build.sh`.
- [x] Run one full `uv run pytest --cov=src/mordred_hermes` at final integration, after targeted modules pass. Record all failures and skips.
- [x] Request a fresh whole-change review using the plan and diff, resolve important findings with failing-then-passing regressions, and commit verified changes. Leave the managed worktree for review; do not push or merge into the dirty source checkout.

## Execution record

- Original report's exact stored endpoint is unknown; do not claim its original cause is confirmed.
- A managed worktree was created from dev at `77aa6cbcbf63b8357756b58b442153a22e1ceaee`; original uncommitted documentation changes stay in the source checkout.
- User explicitly requested planning followed by fixes; proceed inline without another approval round.

## Review decisions

- Pre-merge review additionally reproduced response-body/URL-path disclosure from the audit fallback's chained DEBUG traceback after a local transport failure. A real malformed-chunked HTTP regression failed before the fix; fallback diagnostics now include only the exception class. The required endpoint/model placeholders were also added to the authentication remedy.
- A fresh review found that clean HTTP EOF could incorrectly pass the new probe after partial SSE text. Two failing regressions proved the issue; the probe now requires `[DONE]` or a valid finish reason. Existing ask/Venice stream behavior is retained for compatibility, so ordinary ask completion strictness is outside this change.
- Existing CLI success output may include the configured base path, and ordinary doctor still inspects archive filesystem metadata. New failure diagnostics omit arbitrary paths, and the explicit inference probe never decrypts the archive.
- Live model evidence is from macOS and a small Qwen model, using synthetic credentials/archive and test hardware sealing. Linux physical TPM and the reported 27B model remain unverified.

## Final validation

- `uv run pytest --cov=src/mordred_hermes`: 7272 passed, 220 skipped, 50 deselected, 28 warnings; 90.34% coverage; 1286.38 seconds.
- Repository Ruff checks and formatting, strict mypy (260 sources), and shellcheck passed.
- Live llama.cpp authenticated and unauthenticated checks both passed after the review fix. Evidence and repeatable gates are in `docs/dev/CI.md`, "Manual live-device validation log".
- Managed worktree retained for review; no push or merge into the dirty source checkout. Temporary validation model/server assets removed after validation.
