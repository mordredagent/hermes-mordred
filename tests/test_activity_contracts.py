"""Behaviour contract of activity event normalization and batch envelopes."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

import pytest

from mordred_hermes.activity import contracts
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.contracts import (
    DEFAULT_EXCLUDED_SITES,
    MAX_EVENT_BYTES,
    BatchRejected,
    EventRejected,
    canonical_digest,
    check_batch_envelope,
    check_sequence,
    normalize_event,
    scrub_urls,
)

SITES = DEFAULT_EXCLUDED_SITES
#: A JWT-shaped value (header ``{"alg":"HS256"}``, payload ``{"sub":"1"}``).
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
#: Every normalized field that existed before ``query`` / ``page_title`` / ``page_text`` (minus the digest).
V1_FIELDS = frozenset(
    {
        "event_id",
        "seq",
        "episode_id",
        "attempt_id",
        "parent_attempt_id",
        "source",
        "actor",
        "observed_at",
        "phase",
        "op",
        "target",
        "site",
        "route",
        "args_json",
        "result_status",
        "result_method",
        "result_evidence",
        "coverage",
        "exclusions",
        "truncated",
        "page_sig_before",
        "page_sig_after",
        "hermes_session_id",
        "turn_id",
        "run_id",
        "text",
    }
)
#: Hosts an operator chose to exclude through ``plugins.mordred_activity.excluded_sites``.
PRIVATE_SITES = frozenset({"mail.google.com", "web.telegram.org", "app.slack.com"})


def raw_event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "seq": 1,
        "episode_id": "ep-1",
        "attempt_id": None,
        "parent_attempt_id": None,
        "source": "operator",
        "actor": "agent",
        "observed_at": 1760950000.5,
        "phase": "dispatched",
        "action": {"op": "click", "target": "Reports", "site": "example.com", "route": "/reports"},
        "result": {"status": "unknown"},
        "quality": {"coverage": "selected_tab", "exclusions": [], "truncated": False},
        "session_ref": {"run_id": "run-1"},
    }
    event.update(overrides)
    return event


def normalize(**overrides: Any) -> contracts.NormalizedEvent:
    return normalize_event(raw_event(**overrides), excluded_sites=SITES)


# --- URLs: the path is the route, the scrubbed query is kept -----------------------------------------


def test_full_url_route_keeps_its_path_as_route_and_a_scrubbed_query() -> None:
    event = normalize(
        action={
            "op": "navigate",
            "site": "https://Example.COM:8443/a?token=SECRET#frag",
            "route": "https://example.com/inbox//item?id=42&token=SECRET#x",
        }
    )
    assert event.site == "example.com"
    assert event.route == "/inbox/item"
    assert event.query == "?id=42&token=redacted#x"
    assert "url_params_redacted" in event.exclusions
    assert "SECRET" not in json.dumps(event.__dict__)


def test_route_given_as_url_supplies_a_missing_site_and_its_query() -> None:
    event = normalize(action={"op": "navigate", "route": "https://Shop.Example.org/cart?x=1"})
    assert (event.site, event.route, event.query) == ("shop.example.org", "/cart", "?x=1")
    assert "url_params_redacted" not in event.exclusions


@pytest.mark.parametrize(
    ("route", "path", "query"),
    [
        ("/search?q=shoes&page=2#results", "/search", "?q=shoes&page=2#results"),
        ("/docs#install", "/docs", "#install"),
        ("/plain", "/plain", None),
        ("/only?", "/only", None),
    ],
)
def test_a_path_route_splits_into_route_and_query(route: str, path: str, query: str | None) -> None:
    event = normalize(action={"op": "navigate", "site": "example.com", "route": route})
    assert (event.route, event.query) == (path, query)


@pytest.mark.parametrize(
    ("sent", "query"),
    [
        ("?view=list", "?view=list"),
        ("view=list", "?view=list"),
        ("#section", "#section"),
        ("?password=hunter2&view=list", "?password=redacted&view=list"),
    ],
)
def test_a_top_level_query_wins_over_the_routes(sent: str, query: str) -> None:
    event = normalize(action={"op": "navigate", "site": "example.com", "route": "/a?from=route"}, query=sent)
    assert (event.route, event.query) == ("/a", query)


def test_an_empty_top_level_query_falls_back_to_the_routes() -> None:
    event = normalize(action={"op": "navigate", "site": "example.com", "route": "/a?from=route"}, query="  ")
    assert event.query == "?from=route"


@pytest.mark.parametrize(
    ("url", "scrubbed"),
    [
        ("https://x.example/a?token=s1", "https://x.example/a?token=redacted"),
        ("https://x.example/a?API_KEY=s1&q=1", "https://x.example/a?API_KEY=redacted&q=1"),
        ("https://x.example/a?q=1&code=s1&sid=s2", "https://x.example/a?q=1&code=redacted&sid=redacted"),
        ("https://x.example/a?csrf_token=s1&page=2", "https://x.example/a?csrf_token=redacted&page=2"),
        (
            "https://x.example/a?db_password=s1&X-Signature=s2",
            "https://x.example/a?db_password=redacted&X-Signature=redacted",
        ),
        ("https://x.example/cb#access_token=s1&state=ok", "https://x.example/cb#access_token=redacted&state=ok"),
        ("https://x.example/#/cb?code=s1&state=ok", "https://x.example/#/cb?code=redacted&state=ok"),
        (f"https://x.example/a?v={JWT}&q=1", "https://x.example/a?v=redacted&q=1"),
        (f"https://x.example/reset/{JWT}", "https://x.example/reset/redacted"),
        ("https://user:s1@x.example/a", "https://user:redacted@x.example/a"),
        (
            "https://x.example/login?next=https%3A%2F%2Fy.example%2Fcb%3Ftoken%3Ds1",
            "https://x.example/login?next=https%3A%2F%2Fy.example%2Fcb%3Ftoken%3Dredacted",
        ),
        ("https://x.example/a?a=1;token=abc", "https://x.example/a?a=1&token=redacted"),
        ("https://x.example/a?a=1&b=2;token=s1&c=3;d=4", "https://x.example/a?a=1&b=2&token=redacted&c=3&d=4"),
        ("https://x.example/cb#x=1;access_token=abc", "https://x.example/cb#x=1&access_token=redacted"),
        ("https://x.example/#/cb?state=ok;code=s1", "https://x.example/#/cb?state=ok&code=redacted"),
        (
            "https://x.example/login?next=https%3A%2F%2Fy.example%2Fcb%3Fa%3D1%3Btoken%3Ds1",
            "https://x.example/login?next=https%3A%2F%2Fy.example%2Fcb%3Fa%3D1%26token%3Dredacted",
        ),
        ("https://user:p@ss:w0rd@x.example/x", "https://user:redacted@x.example/x"),
        ("https://:s1@x.example/a", "https://:redacted@x.example/a"),
        ("https://u:s@1@x.example:8443/a?q=1", "https://u:redacted@x.example:8443/a?q=1"),
    ],
)
def test_credentials_in_urls_are_redacted(url: str, scrubbed: str) -> None:
    assert scrub_urls(f"see {url} now") == f"see {scrubbed} now"
    event = normalize(phase="correction", action={"op": "other"}, text=url)
    assert event.text == scrubbed
    assert "url_params_redacted" in event.exclusions


@pytest.mark.parametrize(
    "url",
    [
        "https://x.example/a?b=2&a=1&q=red+shoes&empty=&flag",
        "https://x.example/a?q=a%20b#frag",
        "https://x.example/a?token=",
        "https://x.example/p#SECTION-2",
        "https://x.example/a?monkey=1&keyboard=2&sessions=3",
        "https://x.example/a?a=1;b=2&c=3#x=1;y=2",
        "https://user@x.example/a;v=1?q=a;b",
        "https://user:@x.example/a",
        "https://x.example:8443/@name:handle/a@b",
    ],
)
def test_urls_without_credentials_are_kept_verbatim(url: str) -> None:
    assert scrub_urls(url) == url
    event = normalize(phase="correction", action={"op": "other"}, text=url)
    assert event.text == url
    assert "url_params_redacted" not in event.exclusions


def test_non_credential_parameters_keep_their_values_and_order_beside_a_redaction() -> None:
    url = "https://x.example/a?b=2&token=s1&a=1&q=shoes"
    assert scrub_urls(url) == "https://x.example/a?b=2&token=redacted&a=1&q=shoes"


def test_a_userinfo_password_holding_at_and_colon_is_redacted_whole() -> None:
    secret = "p@ss:w0rd@:x"
    scrubbed = scrub_urls(f"https://user:{secret}@Host.Example:8443/x?q=1")

    assert scrubbed == "https://user:redacted@Host.Example:8443/x?q=1"
    assert not any(part in scrubbed for part in ("p@ss", "ss:w", "w0rd", "@:x"))
    parts = urlsplit(scrubbed)
    assert (parts.hostname, parts.port, parts.username, parts.password) == ("host.example", 8443, "user", "redacted")


def test_deeply_nested_redirect_urls_are_redacted_without_unbounded_recursion() -> None:
    nested = "https://x.example/?next=" * 5000 + "done"
    assert scrub_urls(nested).endswith("redacted")


@pytest.mark.parametrize(
    "text",
    [
        "a." * 131072,
        "https://x.example/?v=" + "eyJ" * 87000,
        "https://" + "a:" * 131072,
        "https://x.example/?token=1 " * 9000,
    ],
    ids=["dotted-run", "eyj-run", "userinfo-run", "many-urls"],
)
def test_scrubbing_hostile_text_stays_fast(text: str) -> None:
    # Raw strings reach the scrubber before they are bounded; a quadratic pattern takes minutes here.
    started = time.perf_counter()
    scrub_urls(text)
    assert time.perf_counter() - started < 5


def test_urls_inside_target_and_text_keep_their_query() -> None:
    event = normalize(
        phase="correction",
        action={"op": "other", "target": "open https://a.example/x?session=SECRET&tab=2"},
        text="use https://b.example/p?view=list#totals instead",
    )
    assert event.target == "open https://a.example/x?session=redacted&tab=2"
    assert event.text == "use https://b.example/p?view=list#totals instead"
    assert "url_params_redacted" in event.exclusions


def test_long_fields_are_bounded_and_marked_truncated() -> None:
    event = normalize(
        phase="boundary",
        action={"op": "task_start", "target": "t" * 500, "route": "/" + "r" * 500},
        text="x" * 5000,
    )
    assert len(event.target or "") == 120
    assert len(event.route or "") == 200
    assert len(event.text or "") == 4000
    assert event.truncated is True


def test_a_long_query_is_bounded_and_marked_truncated() -> None:
    event = normalize(action={"op": "navigate", "site": "example.com", "route": "/a?q=" + "x" * 2000})
    assert len(event.query or "") == contracts.MAX_QUERY_CHARS == 1000
    assert event.truncated is True


# --- free text and typed text ------------------------------------------------------------------------


def test_text_is_kept_for_correction_and_boundary_and_dropped_elsewhere() -> None:
    assert normalize(phase="correction", action={"op": "other"}, text="use the switcher").text == "use the switcher"
    dropped = normalize(phase="observed", text="page said something private")
    assert dropped.text is None
    assert "text_dropped" in dropped.exclusions


@pytest.mark.parametrize("op", ["type", "search"])
@pytest.mark.parametrize("field_kind", ["text", "search", "other"])
def test_typed_text_is_kept_for_a_non_sensitive_field(op: str, field_kind: str) -> None:
    event = normalize(action={"op": op, "args": {"field_kind": field_kind}}, text="quarterly report")
    assert event.text == "quarterly report"
    assert json.loads(event.args_json) == {"field_kind": field_kind}
    assert "typed_text_dropped" not in event.exclusions


@pytest.mark.parametrize(
    "action",
    [
        {"op": "type", "args": {"field_kind": "sensitive"}},
        {"op": "type", "args": {"field_kind": "Sensitive"}},
        {"op": "search", "args": {"field_kind": "sensitive"}},
        {"op": "type"},
        {"op": "type", "args": {"field_kind": "x" * 33}},
    ],
)
def test_typed_text_of_a_sensitive_or_unclassified_field_is_dropped(action: dict[str, Any]) -> None:
    event = normalize(action=action, text="hunter2")
    assert event.text is None
    assert "typed_text_dropped" in event.exclusions
    assert "hunter2" not in repr(event)


def test_a_collector_sensitive_mark_withholds_typed_text() -> None:
    event = normalize(
        action={"op": "type", "args": {"field_kind": "text"}},
        quality={"coverage": "selected_tab", "exclusions": ["sensitive_field"]},
        text="hunter2",
    )
    assert event.text is None
    assert "typed_text_dropped" in event.exclusions


@pytest.mark.parametrize(
    ("args", "kept"),
    [
        ({"field_kind": "search", "text": "red shoes"}, "red shoes"),
        ({"field_kind": "search", "value": "red shoes"}, "red shoes"),
        ({"field_kind": "search", "text": "from text", "value": "from value"}, "from text"),
        ({"field_kind": "search", "text": 7, "value": "from value"}, "from value"),
    ],
)
def test_typed_text_is_lifted_from_args_and_never_stored_as_an_argument(args: dict[str, Any], kept: str) -> None:
    event = normalize(action={"op": "type", "args": args})
    assert event.text == kept
    assert json.loads(event.args_json) == {"field_kind": "search"}


def test_a_top_level_text_wins_over_typed_args() -> None:
    event = normalize(action={"op": "type", "args": {"field_kind": "text", "text": "args"}}, text="top level")
    assert event.text == "top level"


def test_typed_args_of_a_sensitive_field_are_dropped() -> None:
    event = normalize(action={"op": "type", "args": {"field_kind": "sensitive", "text": "hunter2", "value": "hunter2"}})
    assert (event.text, json.loads(event.args_json)) == (None, {"field_kind": "sensitive"})
    assert "typed_text_dropped" in event.exclusions
    assert "hunter2" not in repr(event)


def test_a_type_event_without_typed_text_has_no_text_exclusion() -> None:
    event = normalize(action={"op": "type", "args": {"field_kind": "text"}})
    assert event.text is None
    assert not {"typed_text_dropped", "text_dropped"} & set(event.exclusions)


# --- secret-shaped typed values (withheld whatever the field kind) -------------------------------------------

SECRET_VALUES = [
    pytest.param(JWT, id="jwt"),
    pytest.param(f"my token is {JWT} thanks", id="jwt-in-sentence"),
    pytest.param("sk-proj-Ab3dEf6hIj9kLm", id="openai-key"),
    pytest.param("use sk-live1234abcd5678 here", id="key-prefix-in-sentence"),
    pytest.param("ghp_" + "a1B2" * 9, id="github-classic"),
    pytest.param("github_pat_11ABCDEFG0123456789_abcdefghij", id="github-fine-grained"),
    pytest.param("AKIAIOSFODNN7EXAMPLE", id="aws-access-key-id"),
    pytest.param("xoxb-123456789012-abcdefghijkl", id="slack-bot"),
    pytest.param("xoxp-1234-5678-abcdefgh", id="slack-user"),
    pytest.param("Tr0ub4dor&3horse!", id="mixed-password"),
    pytest.param("aB3dE5fG7hJ9kL1mN", id="random-alnum"),
    pytest.param("  correct#horse$battery  ", id="symbols-surrounding-space-ignored"),
    pytest.param("risk-assessment-2026-final", id="long-identifier-with-digits"),
    pytest.param("sk_live_51HxAbCdEfGhIjKl", id="stripe-live"),
    pytest.param("my gitlab token glpat-AbCdEfGh12345678", id="gitlab-in-sentence"),
    pytest.param("key AIzaSyA1b2C3d4E5f6G7h8I9j0", id="google-api-key-in-sentence"),
    pytest.param("ya29.a0AfH6SMBxyz12345678", id="google-oauth"),
    pytest.param("npm_AbCdEfGh1234567890", id="npm"),
    pytest.param("hf_AbCdEfGhIjKlMnOp", id="hugging-face"),
    pytest.param("xapp-1-A0123456789-abcdef", id="slack-app"),
    pytest.param("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n", id="pem"),
    pytest.param("password: Xk9#mP2", id="labelled-password"),
    pytest.param("PIN=4821", id="labelled-pin"),
    pytest.param("4111111111111111", id="card"),
    pytest.param("4111 1111 1111 1111", id="card-grouped"),
    pytest.param("5500-0000-0000-0004", id="card-dashed"),
    pytest.param("Password2024.Autumn", id="host-shaped-password"),
    pytest.param("MyP4ssw0rd.example", id="host-shaped-mixed-case"),
    pytest.param("john@Secr3tPass.word", id="email-shaped-password"),
    pytest.param("login with Xk9mP2vLqR8sT4wY6zA1 now", id="long-token-in-sentence"),
]

ORDINARY_VALUES = [
    pytest.param("quarterly report", id="words"),
    pytest.param("Please send the October invoice to accounting by Friday 5pm", id="sentence"),
    pytest.param("hunter2", id="short-word-with-digit"),
    pytest.param("passwordpassword1"[:15], id="fifteen-chars"),
    pytest.param("12345678901234567890", id="number"),
    pytest.param("+81 90-1234-5678", id="phone"),
    pytest.param("2026-10-22", id="date"),
    pytest.param("2026-10-22T14:02:00+09:00", id="iso-datetime"),
    pytest.param("https://example.com/reports/2026?month=10&view=full", id="url"),
    pytest.param("www.example.com/reports/2026", id="host-and-path"),
    pytest.param("app.example.co.jp:8443/billing", id="host-with-port"),
    pytest.param("john.doe+billing@example.com", id="email"),
    pytest.param("/Users/me/Documents/report2026.pdf", id="file-path"),
    pytest.param("hello-world-again-and-again", id="hyphenated-words"),
    pytest.param("correcthorsebatterystaple", id="long-letters-only"),
    pytest.param("ask-me-anything-please", id="sk-inside-a-word"),
    pytest.param("xoxo-hugs-and-kisses", id="xoxo-is-not-a-slack-token"),
    pytest.param("月次の経理レポートを出力する", id="cjk-sentence"),
    pytest.param("2026年10月22日の請求書を経理部に送付する件について", id="cjk-sentence-with-digits"),
    pytest.param("1234567812345678", id="sixteen-digits-failing-luhn"),
    pytest.param("call me at 0312345678 tomorrow", id="phone-in-sentence"),
    pytest.param("the token count is low", id="token-word-without-value"),
    pytest.param("password manager reviews", id="keyword-before-an-interface-word"),
    pytest.param("pin the tab to the left", id="pin-as-a-verb"),
    pytest.param("see https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p for details", id="url-in-sentence"),
]


@pytest.mark.parametrize("value", SECRET_VALUES)
@pytest.mark.parametrize("field_kind", ["text", "search", "other"])
def test_secret_shaped_typed_text_is_withheld_whatever_the_field(value: str, field_kind: str) -> None:
    assert contracts.looks_like_secret(value)
    event = normalize(action={"op": "type", "args": {"field_kind": field_kind}}, text=value)
    assert event.text is None
    assert "typed_text_dropped" in event.exclusions
    assert value.strip() not in repr(event)


@pytest.mark.parametrize("value", SECRET_VALUES[:3])
def test_secret_shaped_values_lifted_from_args_are_withheld(value: str) -> None:
    event = normalize(action={"op": "search", "args": {"field_kind": "search", "value": value}})
    assert (event.text, json.loads(event.args_json)) == (None, {"field_kind": "search"})
    assert "typed_text_dropped" in event.exclusions


@pytest.mark.parametrize("value", ORDINARY_VALUES)
def test_ordinary_typed_text_is_kept(value: str) -> None:
    assert not contracts.looks_like_secret(value)
    event = normalize(action={"op": "type", "args": {"field_kind": "text"}}, text=value)
    assert event.text is not None
    assert "typed_text_dropped" not in event.exclusions


def test_the_value_check_applies_to_typed_text_only() -> None:
    correction = normalize(phase="correction", action={"op": "other"}, text="aB3dE5fG7hJ9kL1mN")
    assert correction.text == "aB3dE5fG7hJ9kL1mN"
    assert contracts.SECRET_TOKEN_MIN_CHARS == 16


def test_text_on_a_click_is_still_dropped() -> None:
    event = normalize(action={"op": "click", "args": {"field_kind": "text", "text": "x"}}, text="clicked label")
    assert event.text is None
    assert "text_dropped" in event.exclusions
    assert "typed_text_dropped" not in event.exclusions


# --- page title and text ------------------------------------------------------------------------------


def test_page_title_and_text_are_kept_whitespace_normalized_and_scrubbed() -> None:
    event = normalize(
        page_title="  Monthly\n  report ",
        page_text="Totals\n\n\tfor  May https://x.example/dl?file=a.csv&sig=s1",
    )
    assert event.page_title == "Monthly report"
    assert event.page_text == "Totals for May https://x.example/dl?file=a.csv&sig=redacted"
    assert "url_params_redacted" in event.exclusions


def test_page_fields_are_bounded_and_marked_truncated() -> None:
    event = normalize(page_title="t" * 400, page_text="w" * 9000)
    assert len(event.page_title or "") == contracts.MAX_PAGE_TITLE_CHARS == 300
    assert len(event.page_text or "") == contracts.MAX_PAGE_TEXT_CHARS == 8000
    assert event.truncated is True


def test_blank_page_fields_are_absent() -> None:
    event = normalize(page_title=" \n ", page_text="")
    assert (event.page_title, event.page_text, event.truncated) == (None, None, False)


@pytest.mark.parametrize(
    "overrides",
    [{"page_title": 1}, {"page_text": ["text"]}, {"page_text": {"a": 1}}, {"query": 5}],
)
def test_non_string_page_fields_and_query_are_malformed(overrides: dict[str, Any]) -> None:
    with pytest.raises(EventRejected) as caught:
        normalize(**overrides)
    assert caught.value.code == "malformed"


def test_args_keep_only_allowlisted_well_typed_keys() -> None:
    event = normalize(
        action={
            "op": "key",
            "args": {"keys": ["Enter"], "pixels": 400, "cookie": "abc", "count": "3", "duration_s": 1.5},
        }
    )
    assert json.loads(event.args_json) == {"keys": ["Enter"], "pixels": 400, "duration_s": 1.5}


def test_oversized_args_are_dropped_not_stored() -> None:
    args = {
        "keys": ["k" * 32] * 8,
        "reason": "r" * 64,
        "tier": "t" * 32,
        "verdict": "v" * 32,
        "tab_action": "a" * 32,
        "field_kind": "f" * 32,
    }
    event = normalize(action={"op": "key", "args": args})
    assert event.args_json == "{}"
    assert "args_dropped" in event.exclusions


@pytest.mark.parametrize("status", ["verified_success", "verified_failure"])
def test_collector_verification_is_downgraded_to_a_claim(status: str) -> None:
    event = normalize(result={"status": status, "method": "page_signature_change", "evidence": ["e-1"]})
    assert event.result_status == status.replace("verified_", "claimed_")
    assert "verification_claim_dropped" in event.exclusions
    assert event.result_evidence == ("e-1",)


@pytest.mark.parametrize(
    "overrides",
    [
        {"phase": "finished"},
        {"source": "page"},
        {"actor": "robot"},
        {"action": {"op": "purchase"}},
        {"result": {"status": "done"}},
        {"result": {"method": "model_said_so"}},
        {"quality": {"coverage": "everything"}},
        {"event_id": None},
        {"event_id": "has spaces"},
        {"seq": -1},
        {"seq": True},
        {"observed_at": float("nan")},
        {"quality": {"page_sig_before": "not-hex"}},
        {"action": "click"},
    ],
)
def test_unknown_or_invalid_values_are_malformed(overrides: dict[str, Any]) -> None:
    with pytest.raises(EventRejected) as caught:
        normalize(**overrides)
    assert caught.value.code == "malformed"


@pytest.mark.parametrize("site", ["mail.google.com", "https://web.telegram.org/k/#@someone", "eu.app.slack.com"])
def test_private_sources_refuse(site: str) -> None:
    with pytest.raises(EventRejected) as caught:
        normalize_event(raw_event(action={"op": "navigate", "site": site}), excluded_sites=PRIVATE_SITES)
    assert caught.value.code == "source_excluded"


def test_no_site_is_excluded_by_default() -> None:
    assert not DEFAULT_EXCLUDED_SITES
    assert not ActivityConfig.from_mapping({}).excluded_sites
    event = normalize_event(
        raw_event(action={"op": "navigate", "site": "mail.google.com"}), excluded_sites=ActivityConfig().excluded_sites
    )
    assert event.site == "mail.google.com"


def test_configured_exclusions_add_to_the_defaults() -> None:
    config = ActivityConfig.from_mapping({"excluded_sites": ["Bank.Example"]})
    assert config.excluded_sites >= DEFAULT_EXCLUDED_SITES
    assert config.excluded_sites == frozenset({"bank.example"})
    with pytest.raises(EventRejected):
        normalize_event(raw_event(action={"op": "click", "site": "bank.example"}), excluded_sites=config.excluded_sites)


def test_event_over_the_size_limit_is_refused() -> None:
    with pytest.raises(EventRejected) as caught:
        normalize_event(raw_event(phase="correction", text="z" * 900), excluded_sites=SITES, max_event_bytes=600)
    assert caught.value.code == "event_too_large"


def test_the_default_event_limit_fits_every_field_at_its_bound() -> None:
    assert MAX_EVENT_BYTES == 16384
    assert ActivityConfig().max_event_bytes == MAX_EVENT_BYTES
    widest = {
        "phase": "boundary",
        "action": {"op": "task_start", "site": "example.com", "route": "/r?q=" + "a" * 2000, "target": "t" * 500},
        "text": "x" * 5000,
        "page_title": "p" * 400,
        "page_text": "w" * 9000,
    }
    assert contracts.event_size(normalize(**widest)) <= MAX_EVENT_BYTES
    with pytest.raises(EventRejected) as caught:
        normalize(**{**widest, "text": "\u00e9" * 5000, "page_text": "\u00e9" * 9000})
    assert caught.value.code == "event_too_large"


def test_digest_is_stable_and_covers_content() -> None:
    raw = raw_event()
    first = normalize_event(raw, excluded_sites=SITES)
    again = normalize_event(json.loads(json.dumps(raw)), excluded_sites=SITES)
    assert first.content_digest == again.content_digest == canonical_digest(first)
    assert len(first.content_digest) == 64
    changed = normalize_event({**raw, "action": {**raw["action"], "target": "Other"}}, excluded_sites=SITES)
    assert changed.content_digest != first.content_digest


def test_digest_omits_absent_new_fields_so_earlier_digests_still_verify() -> None:
    event = normalize()
    assert (event.query, event.page_title, event.page_text) == (None, None, None)
    assert set(contracts._canonical_fields(event)) == V1_FIELDS
    # The digest as computed before the three fields existed.
    earlier = {key: value for key, value in dataclasses.asdict(event).items() if key in V1_FIELDS}
    expected = hashlib.sha256(contracts.canonical_json(earlier).encode("ascii")).hexdigest()
    assert event.content_digest == canonical_digest(event) == expected


@pytest.mark.parametrize("overrides", [{"query": "?a=1"}, {"page_title": "Title"}, {"page_text": "Body"}])
def test_digest_covers_each_new_field_when_present(overrides: dict[str, Any]) -> None:
    raw = raw_event()
    plain = normalize_event(raw, excluded_sites=SITES)
    extended = normalize_event({**raw, **overrides}, excluded_sites=SITES)
    assert set(contracts._canonical_fields(extended)) == V1_FIELDS | set(overrides)
    assert extended.content_digest != plain.content_digest


def batch(events: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": 1,
        "producer_id": str(uuid.uuid4()),
        "producer_kind": "operator",
        "events": events,
    }
    body.update(overrides)
    return body


def test_envelope_accepts_a_valid_batch() -> None:
    envelope = check_batch_envelope(batch([raw_event()]), max_events=100, max_bytes_raw=262144)
    assert envelope.producer_kind == "operator"
    assert len(envelope.events) == 1


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (batch([raw_event()], schema_version=2), "unsupported_schema"),
        (batch([raw_event()], schema_version="1"), "malformed"),
        (batch([raw_event()], producer_kind="page"), "malformed"),
        (batch([raw_event()], producer_id="x" * 65), "malformed"),
        ({**batch([raw_event()]), "events": "nope"}, "malformed"),
        (batch([raw_event(seq=i) for i in range(4)]), "batch_too_large"),
        (batch([raw_event(phase="correction", text="y" * 900)]), "batch_too_large"),
    ],
)
def test_envelope_refusals(body: dict[str, Any], code: str) -> None:
    with pytest.raises(BatchRejected) as caught:
        check_batch_envelope(body, max_events=3, max_bytes_raw=800)
    assert caught.value.code == code


def test_sequence_must_strictly_increase() -> None:
    check_sequence([normalize(seq=1), normalize(seq=2)])
    with pytest.raises(BatchRejected) as caught:
        check_sequence([normalize(seq=2), normalize(seq=2)])
    assert caught.value.code == "sequence_regression"


def test_rejections_carry_codes_not_content() -> None:
    with pytest.raises(EventRejected) as caught:
        normalize_event(
            raw_event(action={"op": "navigate", "site": "mail.google.com", "target": "SECRET-SUBJECT"}),
            excluded_sites=PRIVATE_SITES,
        )
    assert "SECRET" not in str(caught.value)
    assert str(caught.value) == "source_excluded"


def test_config_defaults_are_off_and_bad_values_fall_back() -> None:
    assert ActivityConfig().collecting is False
    config = ActivityConfig.from_mapping(
        {"enabled": "yes", "max_batch_events": 1000, "collection_enabled": True, "mystery": 1}
    )
    assert config.enabled is False
    assert config.max_batch_events == 100
    assert config.collection_enabled is True
    assert config.warnings == ("invalid value for enabled", "invalid value for max_batch_events", "unknown key mystery")


def test_secret_tokens_are_redacted_for_display() -> None:
    text = f"use {JWT} or sk-proj-Ab3dEf6hIj9kLm, see -----BEGIN RSA PRIVATE KEY-----"
    assert contracts.redact_secret_tokens(text) == "use redacted or redacted, see redacted"
    assert contracts.redact_secret_tokens("nothing secret here") == "nothing secret here"


def test_the_secret_rule_is_linear_on_hostile_input() -> None:
    started = time.monotonic()
    for text in ("4" * 250_000, "a-" * 125_000, "eyJ" + "a." * 100_000, "password" + " " * 100_000 + "x"):
        contracts.looks_like_secret(text)
    assert time.monotonic() - started < 5.0


# --- secrets in free text (live finding 2026-10-22) ----------------------------------------------------

#: The operator collector's task text that was stored verbatim before free text was redacted.
LIVE_TASK = "Log in with the username demo-user and the password Hunter2-fake-pw"
LIVE_SECRET = "Hunter2-fake-pw"
FULLWIDTH_COLON = chr(0xFF1A)

REDACTED_TEXTS = [
    pytest.param(LIVE_TASK, "Log in with the username demo-user and the password redacted", id="live"),
    pytest.param("password: hunter2", "password: redacted", id="colon"),
    pytest.param("PIN=4821", "PIN=redacted", id="equals"),
    pytest.param("my password is Hunter2-fake-pw.", "my password is redacted.", id="is-trailing-dot-kept"),
    pytest.param("the passcode was 99-red-balloons, okay", "the passcode was redacted, okay", id="was"),
    pytest.param("my PIN is 4821", "my PIN is redacted", id="pin-is-digits"),
    pytest.param("passphrase 'correct horse battery staple' please", "passphrase 'redacted' please", id="quoted"),
    pytest.param('use password="s3cr3t!" here', 'use password="redacted" here', id="label-and-quotes"),
    pytest.param("API key: abc123def", "API key: redacted", id="api-key"),
    pytest.param("DB_PASSWORD=xyz", "DB_PASSWORD=redacted", id="env-style"),
    pytest.param("Your one-time code is 482913", "Your one-time code is redacted", id="one-time-code"),
    pytest.param("otp 123456 expires soon", "otp redacted expires soon", id="otp-space"),
    pytest.param("pin code 0000", "pin code redacted", id="pin-code"),
    pytest.param("access token: abcdef", "access token: redacted", id="access-token"),
    pytest.param("the secret: swordfish", "the secret: redacted", id="labelled-secret"),
    pytest.param("(password Hunter2)", "(password redacted)", id="closing-bracket-kept"),
    pytest.param("パスワードはHunter2です", "パスワードはredactedです", id="ja-no-space"),
    pytest.param("パスワード「abc123」で", "パスワード「redacted」で", id="ja-brackets"),
    pytest.param("パスワードは abc123", "パスワードは redacted", id="ja-particle-space"),
    pytest.param(f"認証コード{FULLWIDTH_COLON}123456", f"認証コード{FULLWIDTH_COLON}redacted", id="ja-fullwidth-colon"),
    pytest.param("暗証番号は1234です。", "暗証番号はredactedです。", id="ja-pin"),
    pytest.param("ワンタイムパスワード 482913 を入力", "ワンタイムパスワード redacted を入力", id="ja-otp"),
    pytest.param("パスコードを『x9y8』に変更", "パスコードを『redacted』に変更", id="ja-passcode-quoted"),
    pytest.param(f"use {JWT} to call", "use redacted to call", id="jwt"),
    pytest.param("my key sk-proj-Ab3dEf6hIj9kLm works", "my key redacted works", id="key-prefix"),
    pytest.param("token ghp_" + "a1B2" * 9, "token redacted", id="keyword-and-key-prefix"),
]

KEPT_TEXTS = [
    pytest.param("click the password field", id="password-field"),
    pytest.param("reset password page", id="reset-password-page"),
    pytest.param("Open the password manager and pick the work vault", id="password-manager"),
    pytest.param("パスワード欄に入力する", id="ja-password-field"),
    pytest.param("パスワードリセット画面を開く", id="ja-reset-screen"),
    pytest.param("パスワードを忘れた場合はこちら", id="ja-forgot"),
    pytest.param("Forgot password?", id="forgot"),
    pytest.param("Email Password Sign in", id="login-labels"),
    pytest.param("Password: ******** Show", id="masked"),
    pytest.param("pin the tab to the left", id="pin-verb"),
    pytest.param("the token count is low", id="token-count"),
    pytest.param("the secret is out", id="secret-word"),
    pytest.param("a password of at least 8 characters", id="policy-sentence"),
    pytest.param("the password was changed yesterday", id="changed"),
    pytest.param("send the October report on 2026-10-22 for 1234 items", id="dates-and-numbers"),
    pytest.param("call +81 90-1234-5678 at 10:30", id="phone-and-time"),
    pytest.param("see https://example.com/reset-password?step=2 for details", id="url"),
    pytest.param('type "password" in the "Password" box', id="quoted-keyword"),
    pytest.param("password_reset was clicked", id="identifier"),
    pytest.param("the password is redacted", id="already-redacted"),
    pytest.param("月次の経理レポートを出力する", id="ja-sentence"),
]


def _task_start(text: str, **overrides: Any) -> contracts.NormalizedEvent:
    return normalize(
        phase="boundary", actor="human", action={"op": "task_start", "site": "example.com"}, text=text, **overrides
    )


def test_the_live_task_text_keeps_everything_but_the_password() -> None:
    event = _task_start(LIVE_TASK)

    assert event.text == "Log in with the username demo-user and the password redacted"
    assert "text_secrets_redacted" in event.exclusions
    assert LIVE_SECRET not in json.dumps(dataclasses.asdict(event))
    assert event.content_digest == canonical_digest(event)


def test_redaction_happens_before_the_digest() -> None:
    raw = raw_event(phase="boundary", actor="human", action={"op": "task_start", "site": "example.com"})
    first = normalize_event({**raw, "text": LIVE_TASK}, excluded_sites=SITES)
    other = normalize_event({**raw, "text": LIVE_TASK.replace(LIVE_SECRET, "Other-pw-99")}, excluded_sites=SITES)
    # The digest covers the stored (redacted) content, so a replay of the same event still verifies.
    assert first.content_digest == other.content_digest == canonical_digest(first)


@pytest.mark.parametrize(("text", "expected"), REDACTED_TEXTS)
def test_secrets_in_free_text_are_replaced_and_the_rest_kept(text: str, expected: str) -> None:
    assert contracts.redact_text_secrets(text) == (expected, True)
    event = normalize(phase="correction", action={"op": "other"}, text=text)
    assert event.text == expected
    assert "text_secrets_redacted" in event.exclusions


@pytest.mark.parametrize("text", KEPT_TEXTS)
def test_interface_talk_and_ordinary_sentences_are_untouched(text: str) -> None:
    assert contracts.redact_text_secrets(text) == (text, False)
    event = _task_start(text)
    assert event.text == text
    assert "text_secrets_redacted" not in event.exclusions


def test_every_free_text_field_is_redacted_at_ingest() -> None:
    event = normalize(
        phase="boundary",
        action={"op": "task_end", "site": "example.com", "target": "submit with password: hunter2"},
        text="done; the new PIN is 4821",
        page_title="Welcome, your password is Hunter2-fake-pw",
        page_text="Your one-time code is 482913. Do not share it.",
    )

    assert event.target == "submit with password: redacted"
    assert event.text == "done; the new PIN is redacted"
    assert event.page_title == "Welcome, your password is redacted"
    assert event.page_text == "Your one-time code is redacted. Do not share it."
    assert "text_secrets_redacted" in event.exclusions
    stored = json.dumps(dataclasses.asdict(event))
    assert not any(secret in stored for secret in ("hunter2", "4821", LIVE_SECRET, "482913"))


def test_a_correction_with_a_password_is_redacted() -> None:
    event = normalize(
        phase="correction",
        source="user_correction",
        actor="human",
        action={"op": "other", "site": "example.com"},
        text="wrong account; the password is Winter-2026 for the finance login",
    )
    assert event.text == "wrong account; the password is redacted for the finance login"
    assert "text_secrets_redacted" in event.exclusions


def test_key_prefixes_and_jwts_in_task_text_are_redacted() -> None:
    event = _task_start(f"call the API with sk-proj-Ab3dEf6hIj9kLm and bearer {JWT}")
    assert event.text == "call the API with redacted and bearer redacted"
    assert "text_secrets_redacted" in event.exclusions


def test_a_secret_cut_by_the_bound_is_redacted_before_the_cut() -> None:
    text = "x" * (contracts.MAX_TEXT_CHARS - 20) + " the password is Hunter2-fake-pw-long-enough"
    event = _task_start(text)
    assert event.truncated is True
    assert "Hunter2" not in (event.text or "")
    assert "text_secrets_redacted" in event.exclusions


@pytest.mark.parametrize(
    "value", ["my password is Hunter2-fake-pw", "パスワードは abc123", "the pin is 4821", "password hunter-2"]
)
def test_typed_keyword_and_value_is_withheld_without_a_label(value: str) -> None:
    assert contracts.looks_like_secret(value)
    event = normalize(action={"op": "type", "args": {"field_kind": "text"}}, text=value)
    assert event.text is None
    assert "typed_text_dropped" in event.exclusions
    assert "text_secrets_redacted" not in event.exclusions


def test_kept_typed_text_is_never_rewritten() -> None:
    event = normalize(action={"op": "type", "args": {"field_kind": "search"}}, text="password manager reviews")
    assert event.text == "password manager reviews"
    assert "text_secrets_redacted" not in event.exclusions


def test_the_text_redactor_is_linear_on_hostile_input() -> None:
    started = time.monotonic()
    for text in (
        "password " * 30_000,
        "pin:" * 60_000,
        "pin:a://" * 30_000,
        "pin:1://" * 30_000,
        'password "' * 25_000,
        "パスワードは" * 40_000,
        "token: " + "a" * 250_000,
    ):
        contracts.redact_text_secrets(text)
    assert time.monotonic() - started < 5.0


@pytest.mark.parametrize("cut", [0, 1, 255, 256, 257])
def test_a_long_unquoted_value_is_redacted_to_its_end(cut: int) -> None:
    blob = ("Ab1" * 200)[:cut] + "." + "Cd2" * 100  # a closing mark at or near the inspection cap
    assert contracts.redact_text_secrets(f"api key: {blob}. end") == ("api key: redacted. end", True)


# --- credential parameters and userinfo ------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "x_key",
        "apiKey",
        "X-Api-Key",
        "Access-Key",
        "auth_code",
        "authCode",
        "code_verifier",
        "client_assertion",
        "SAMLResponse",
        "SAMLRequest",
        "RelayState",
        "ID_TOKEN",
        "refresh_token",
        "user[password]",
        "password[]",
        "token[0]",
        "x-pass",
        "req_sig",
        "basicAuth",
        "aws_credentials",
        "service_ticket",
        "passkey",
    ],
)
def test_credential_parameter_names(name: str) -> None:
    assert contracts.credential_param(name)


@pytest.mark.parametrize(
    "name",
    [
        *("q", "query", "page", "sort", "lang", "monkey", "keyboard", "barcode", "zipcode", "country_code"),
        *("currencyCode", "sort_key", "sessions", "page[size]", "codename"),
    ],
)
def test_ordinary_parameter_names(name: str) -> None:
    assert not contracts.credential_param(name)


def test_ordinary_search_parameters_stay_while_secret_values_go() -> None:
    url = (
        "https://x.example/s?q=red+shoes&query=boots&page=2&sort=price_asc&lang=ja"
        "&ref=aB3dE5fG7hJ9kL1mN&x_key=s1&SAMLResponse=PHNhbWw%2B&user%5Bpassword%5D=s2"
    )
    assert scrub_urls(url) == (
        "https://x.example/s?q=red+shoes&query=boots&page=2&sort=price_asc&lang=ja"
        "&ref=redacted&x_key=redacted&SAMLResponse=redacted&user%5Bpassword%5D=redacted"
    )


@pytest.mark.parametrize(
    ("url", "scrubbed"),
    [
        ("https://x.example/s?q=password+is+Hunter2&page=2", "https://x.example/s?q=redacted&page=2"),
        ("https://x.example/s?q=4111+1111+1111+1111", "https://x.example/s?q=redacted"),
        (f"https://x.example/s?state=ok&note=use+{JWT}", "https://x.example/s?state=ok&note=redacted"),
    ],
)
def test_a_secret_shaped_value_is_redacted_whatever_its_name(url: str, scrubbed: str) -> None:
    assert scrub_urls(url) == scrubbed
    event = normalize(action={"op": "navigate", "site": "x.example", "route": url})
    assert "url_params_redacted" in event.exclusions


@pytest.mark.parametrize(
    ("url", "scrubbed"),
    [
        ("https://ghp_" + "a1B2" * 9 + "@github.com/o/r.git", "https://redacted@github.com/o/r.git"),
        ("https://x-access-token:ghs_abc123@github.com/o/r", "https://x-access-token:redacted@github.com/o/r"),
        ("https://0123456789abcdef0123456789abcdef@o1.ingest.example/42", "https://redacted@o1.ingest.example/42"),
        ("https://glpat-AbCdEfGh12345678:x@gitlab.example/a", "https://redacted:redacted@gitlab.example/a"),
        ("https://" + "q" * 30 + "@hooks.example/a", "https://redacted@hooks.example/a"),
    ],
)
def test_a_user_name_that_is_a_credential_is_redacted(url: str, scrubbed: str) -> None:
    assert scrub_urls(url) == scrubbed
    event = normalize(phase="correction", action={"op": "other"}, text=url)
    assert event.text == scrubbed
    assert "url_params_redacted" in event.exclusions


@pytest.mark.parametrize("url", ["https://git@github.com/o/r", "https://john.doe@example.com/a"])
def test_an_ordinary_user_name_is_kept(url: str) -> None:
    assert scrub_urls(url) == url


# --- hosts: the site must agree with its URL, and every named host is checked against exclusions ----------


@pytest.mark.parametrize(
    ("site", "route"),
    [("safe.example", "https://mail.google.com/mail/u/0"), ("example.com", "https://app.example.com/x")],
)
def test_a_site_that_contradicts_its_url_is_malformed(site: str, route: str) -> None:
    with pytest.raises(EventRejected) as caught:
        normalize(action={"op": "navigate", "site": site, "route": route})
    assert caught.value.code == "malformed"


@pytest.mark.parametrize(
    ("site", "route"),
    [
        ("www.example.com", "https://example.com/a"),
        ("Example.COM.", "https://example.com/a"),
        ("example.com", "https://WWW.example.com./a"),
    ],
)
def test_case_trailing_dots_and_www_are_no_contradiction(site: str, route: str) -> None:
    assert normalize(action={"op": "navigate", "site": site, "route": route}).route == "/a"


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "action": {
                "op": "navigate",
                "site": "accounts.example",
                "route": "/signin?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F",
            }
        },
        {
            "action": {"op": "navigate", "site": "accounts.example", "route": "/signin"},
            "query": "next=https://web.telegram.org/k/",
        },
        {"action": {"op": "click", "site": "news.example", "target": "open https://app.slack.com/client/T1"}},
        {
            "action": {
                "op": "navigate",
                "route": "https://r.example/?u=https%3A%2F%2Fx.example%2F%3Fnext%3Dhttps%253A%252F%252Fmail.google.com",
            }
        },
    ],
    ids=["redirect-in-route", "top-level-query", "target-label", "nested-redirect"],
)
def test_an_excluded_host_anywhere_in_the_event_refuses(overrides: dict[str, Any]) -> None:
    with pytest.raises(EventRejected) as caught:
        normalize_event(raw_event(**overrides), excluded_sites=PRIVATE_SITES)
    assert caught.value.code == "source_excluded"
    # Without exclusions the same events are stored.
    normalize_event(raw_event(**overrides), excluded_sites=SITES)


def test_a_site_contradicting_an_excluded_url_never_passes() -> None:
    raw = raw_event(action={"op": "navigate", "site": "safe.example", "route": "https://mail.google.com/mail"})
    with pytest.raises(EventRejected) as caught:
        normalize_event(raw, excluded_sites=PRIVATE_SITES)
    assert caught.value.code == "malformed"


def test_hosts_named_by_an_event() -> None:
    hosts = contracts.event_hosts(
        {"site": "a.example", "route": "/x?next=https%3A%2F%2Fb.example%2F", "target": "see https://c.example/p"},
        "?back=https://d.example/",
    )
    assert hosts == {"b.example", "c.example", "d.example"}


def test_host_collection_is_linear_on_hostile_input() -> None:
    started = time.monotonic()
    for text in ("https://x.example/?next=" * 5000 + "done", "a." * 131072, "?u=https%3A%2F%2F" * 20000):
        contracts.event_hosts({"route": text, "target": text}, text)
    assert time.monotonic() - started < 5.0
