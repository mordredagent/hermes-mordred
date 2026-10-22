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
from tests._activity_redaction_baseline import BASE_SPANS

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


# --- a value named before its keyword (B2 live check 2026-10-22, D1) --------------------------------------

#: Hermes's user message that the B2 live check found stored verbatim in a task start and shown to later sessions.
B2_LIVE_MESSAGE = (
    "Open http://127.0.0.1:8499/login.html, type demo-user as the username and Hunter2-fake-pw as the password, "
    "then log in."
)

VALUE_FIRST_TEXTS = [
    pytest.param(
        B2_LIVE_MESSAGE,
        "Open http://127.0.0.1:8499/login.html, type demo-user as the username and redacted as the password, "
        "then log in.",
        id="b2-live",
    ),
    pytest.param("use Hunter2-fake-pw for the password", "use redacted for the password", id="for-the"),
    pytest.param("Hunter2-fake-pw as my password", "redacted as my password", id="as-my-no-verb"),
    pytest.param("enter 4821 for the PIN", "enter redacted for the PIN", id="pin-after-a-verb"),
    pytest.param("type Hunter2-fake-pw into the password field", "type redacted into the password field", id="into"),
    pytest.param("put Winter-2026 in the passcode box.", "put redacted in the passcode box.", id="in-box"),
    pytest.param("use swordfish as the password", "use redacted as the password", id="plain-word-after-a-verb"),
    pytest.param(
        "I used Spring-2026 for my password, then logged in",
        "I used redacted for my password, then logged in",
        id="past-tense",
    ),
    pytest.param("enter 482913 for the one-time code.", "enter redacted for the one-time code.", id="one-time-code"),
    pytest.param(
        "fill in 'correct horse battery' as the passphrase",
        "fill in 'redacted' as the passphrase",
        id="quoted-with-spaces",
    ),
    pytest.param('paste "s3cr3t!" into the API key field', 'paste "redacted" into the API key field', id="api-key"),
    pytest.param("(Hunter2) as the password", "(redacted) as the password", id="bracketed"),
    pytest.param(
        "type X9-ab into the field for the password",
        "type redacted into the field for the password",
        id="field-for-the",
    ),
    pytest.param("enter gh0st-7 for the token", "enter redacted for the token", id="token-after-a-verb"),
    pytest.param("Hunter2-fake-pwをパスワードに入力して", "redactedをパスワードに入力して", id="ja-object-target"),
    pytest.param("Hunter2 を パスワード欄に入力", "redacted を パスワード欄に入力", id="ja-object-field-spaces"),
    pytest.param("abc123をパスワードとして使う", "redactedをパスワードとして使う", id="ja-object-as"),
    pytest.param(
        "ログイン画面でHunter2をパスワードに入れる", "ログイン画面でredactedをパスワードに入れる", id="ja-ascii-run"
    ),
    pytest.param("Hunter2というパスワード", "redactedというパスワード", id="ja-called"),
    pytest.param("「Hunter2 x」というパスコードで", "「redacted」というパスコードで", id="ja-called-quoted"),
    pytest.param("パスワードにHunter2を入力", "パスワードにredactedを入力", id="ja-keyword-target-object"),
    pytest.param("パスワード欄にHunter2-xを入れて", "パスワード欄にredactedを入れて", id="ja-field-target-object"),
    pytest.param("暗証番号に「1234」を入力", "暗証番号に「redacted」を入力", id="ja-target-quoted"),
    pytest.param("次にパスワードとしてHunter2を入力", "次にパスワードとしてredactedを入力", id="ja-keyword-as-object"),
    pytest.param("1234をPINに入力", "redactedをPINに入力", id="ja-ascii-keyword-value-first"),
    pytest.param("PIN欄に「0000」を入力", "PIN欄に「redacted」を入力", id="ja-ascii-keyword-target-object"),
]

VALUE_FIRST_KEPT = [
    pytest.param("I forgot my password", id="forgot-my"),
    pytest.param("reset the password for my account", id="reset-for"),
    pytest.param("click Forgot password", id="click-forgot"),
    pytest.param("the password field is empty", id="field-empty"),
    pytest.param("change your password", id="change-your"),
    pytest.param("use the search box for the query", id="no-keyword"),
    pytest.param("type demo-user as the username", id="username"),
    pytest.param("pin the tab", id="pin-verb"),
    pytest.param("the token count", id="token-count"),
    pytest.param("log in as admin with the password redacted", id="already-redacted"),
    pytest.param("use swordfish as the token", id="plain-word-ambiguous-keyword"),
    pytest.param("add v2 to the token list", id="token-list"),
    pytest.param("Add 2FA to the password manager", id="password-manager"),
    pytest.param("set up 2FA in the password settings", id="password-settings"),
    pytest.param("same as the password", id="same-as"),
    pytest.param("type it into the password field", id="pronoun"),
    pytest.param("type something into the password field", id="something"),
    pytest.param("click in the password field", id="click-in"),
    pytest.param("type a value into the password field", id="a-value"),
    pytest.param("Welcome to the password reset page", id="welcome-to"),
    pytest.param("Type your password into the password field", id="your-password-into"),
    pytest.param("open https://example.com/a?b=1 as the password page", id="url"),
    pytest.param("Use Face-ID as the password alternative", id="password-alternative"),
    pytest.param("Add Bob-2 to the password sharing group", id="password-sharing-group"),
    pytest.param("After you log in, as the password expires, change it", id="clause-before-as"),
    pytest.param("ログインしてパスワードを変更する", id="ja-change"),
    pytest.param("メールアドレスをパスワードに含めない", id="ja-japanese-value"),
    pytest.param("パスワードに関する設定", id="ja-about"),
    pytest.param("名前というパスワード", id="ja-called-japanese-word"),
    pytest.param("パスワードリセット画面を開く", id="ja-reset-screen"),
    pytest.param("abcをtokenに変換", id="ja-ambiguous-ascii-keyword-plain-value"),
]


@pytest.mark.parametrize(("text", "expected"), VALUE_FIRST_TEXTS)
def test_a_value_named_before_its_keyword_is_replaced(text: str, expected: str) -> None:
    assert contracts.redact_text_secrets(text) == (expected, True)
    event = _task_start(text)
    assert event.text == expected
    assert "text_secrets_redacted" in event.exclusions


@pytest.mark.parametrize("text", VALUE_FIRST_KEPT)
def test_ordinary_text_with_a_keyword_after_a_word_is_untouched(text: str) -> None:
    assert contracts.redact_text_secrets(text) == (text, False)
    assert "text_secrets_redacted" not in _task_start(text).exclusions


def test_the_b2_live_message_keeps_the_username_and_drops_the_password() -> None:
    event = _task_start(B2_LIVE_MESSAGE)
    assert event.text is not None and "demo-user" in event.text
    assert LIVE_SECRET not in json.dumps(dataclasses.asdict(event))
    assert event.content_digest == canonical_digest(event)


@pytest.mark.parametrize(
    "value", ["Hunter2-fake-pw as the password", "use swordfish for my password", "Hunter2をパスワードに"]
)
def test_typed_value_first_secrets_are_withheld(value: str) -> None:
    assert contracts.looks_like_secret(value)
    event = normalize(action={"op": "type", "args": {"field_kind": "text"}}, text=value)
    assert event.text is None and "typed_text_dropped" in event.exclusions


def test_both_values_around_one_keyword_are_replaced() -> None:
    text = "use Hunter2-x as the password, not the password Hunter3-y"
    assert contracts.redact_text_secrets(text) == ("use redacted as the password, not the password redacted", True)
    assert contracts.redact_text_secrets("password Hunter2-x as the password") == (
        "password redacted as the password",
        True,
    )


def test_value_first_redaction_is_linear_on_hostile_input() -> None:
    started = time.monotonic()
    for text in (
        "x as the password " * 20_000,
        "a" * 250_000 + " as the password",
        "as " * 100_000 + "password",
        "type '" + "a " * 100_000 + "' as the password",
        '"' * 100_000 + " as the password",
        "aをパスワードに" * 40_000,
        "a" * 250_000 + "をパスワードに",
        "パスワードにa" * 40_000,
        "パスワードに" + "a" * 250_000 + "を",
        "」というパスワード" * 30_000,
    ):
        contracts.redact_text_secrets(text)
    assert time.monotonic() - started < 5.0


# --- a value after "to" or after a short qualifier (follow-up to D1) ------------------------------------------

QUALIFIED_TEXTS = [
    pytest.param("set the password to Hunter2-x", "set the password to redacted", id="set-to"),
    pytest.param("change my password to 'abc def'", "change my password to 'redacted'", id="change-to-quoted"),
    pytest.param("update the PIN to 4821", "update the PIN to redacted", id="update-pin-digits"),
    pytest.param(
        "I changed the admin password to Spring-2026 yesterday",
        "I changed the admin password to redacted yesterday",
        id="changed-qualified-keyword",
    ),
    pytest.param("reset the token to abc123def456", "reset the token to redacted", id="reset-token-long"),
    pytest.param(
        "the password for the bank is Hunter2-x", "the password for the bank is redacted", id="for-the-bank-is"
    ),
    pytest.param(
        "my password on example.com is: abc123!", "my password on example.com is: redacted!", id="on-host-is-colon"
    ),
    pytest.param("password for admin = s3cr3t!", "password for admin = redacted!", id="for-admin-equals"),
    pytest.param("My password for GitHub: Github2024!", "My password for GitHub: redacted!", id="for-colon"),
    pytest.param(
        'the passcode of my work account was "x y z"',
        'the passcode of my work account was "redacted"',
        id="of-four-words-quoted",
    ),
    pytest.param("the PIN for my card is 4821.", "the PIN for my card is redacted.", id="pin-for-is-digits"),
    pytest.param("パスワードをHunter2-xに変更して", "パスワードをredactedに変更して", id="ja-object-to-change"),
    pytest.param("パスワードを 「abc def」 に設定", "パスワードを 「redacted」 に設定", id="ja-object-quoted-set"),
    pytest.param("PINを1234に変更", "PINをredactedに変更", id="ja-ascii-pin-change"),
]

QUALIFIED_KEPT = [
    pytest.param("set the password to expire", id="set-to-expire"),
    pytest.param("change your password to something stronger", id="something-stronger"),
    pytest.param("the password for the account is required", id="is-required"),
    pytest.param("the password for the bank is in my notes", id="is-in-notes"),
    pytest.param("update the token to the latest version", id="token-latest"),
    pytest.param("password for admin is redacted", id="already-redacted"),
    pytest.param("set the pin to the top", id="pin-top"),
    pytest.param("change the password to 12 characters", id="length-unit"),
    pytest.param("the password for this site is 8-64 characters", id="range-unit"),
    pytest.param("set the token to v2", id="token-short"),
    pytest.param("the PIN for the map is A1", id="pin-short"),
    pytest.param("Add the password to 1Password", id="no-set-verb"),
    pytest.param("send the password to alice@example.com", id="send-to"),
    pytest.param("reset the password to default", id="plain-default"),
    pytest.param("set the PIN to ABCD", id="pin-letters"),
    pytest.param("the password for the bank, is Hunter2-x", id="comma-in-qualifier"),
    pytest.param("the password for my old work account at home is Hunter2-x", id="qualifier-too-long"),
    pytest.param("a password of at least 8 characters", id="policy"),
    pytest.param("the password for your account is now changed", id="now-changed"),
    pytest.param("set it up so the password to Hunter2-x works", id="verb-too-far"),
    pytest.param("パスワードを変更する", id="ja-change"),
]


@pytest.mark.parametrize(("text", "expected"), QUALIFIED_TEXTS)
def test_a_value_after_to_or_a_short_qualifier_is_replaced(text: str, expected: str) -> None:
    assert contracts.redact_text_secrets(text) == (expected, True)
    assert _task_start(text).text == expected


@pytest.mark.parametrize("text", QUALIFIED_KEPT)
def test_ordinary_text_after_to_or_a_qualifier_is_untouched(text: str) -> None:
    assert contracts.redact_text_secrets(text) == (text, False)


def test_qualified_redaction_is_linear_on_hostile_input() -> None:
    started = time.monotonic()
    for text in (
        "set the password to " * 20_000,
        "the password for a b c is " * 20_000,
        "password for " + "a" * 250_000 + " is x1",
        "set " + "a" * 250_000 + " password to x1",
        "password for: " * 30_000,
        "update the PIN to " + "1" * 250_000,
    ):
        contracts.redact_text_secrets(text)
    assert time.monotonic() - started < 5.0


# --- every keyword is read on its own: no match hides another (Codex review P1) ------------------------------

NESTED_TEXTS = [
    pytest.param(
        "password for account PIN=4821 is Hunter2-x",
        "password for account PIN=redacted is redacted",
        id="qualifier-holds-a-pin",
    ),
    pytest.param(
        "set the password for PIN=4821 to Hunter2-x",
        "set the password for PIN=redacted to redacted",
        id="to-form-qualifier-holds-a-pin",
    ),
    pytest.param(
        "type Hunter2-x as the password for token=abcd1234efgh",
        "type redacted as the password for token=redacted",
        id="value-first-then-a-token",
    ),
    pytest.param(
        "set the password for the bank to Hunter2-x", "set the password for the bank to redacted", id="to-qualified"
    ),
    pytest.param("update the PIN for my card to 4821", "update the PIN for my card to redacted", id="to-qualified-pin"),
    pytest.param(
        "password: pin=4821 token=x9y8z7w6", "password: redacted token=redacted", id="keywords-inside-a-value"
    ),
    # A keyword inside a long value is skipped only when it cannot name anything outside the value; each way out
    # is still read: an opening quote, a Japanese field word, a label mark the value ends in.
    pytest.param('password: abcdefgh-token"x y" end', 'password: redacted" end', id="inner-quote-with-a-space"),
    pytest.param(
        "password: abcdefgh-パスワード欄にxyz12を入力", "password: redactedにredactedを入力", id="inner-japanese-field"
    ),
    pytest.param("password: abcdefgh-pin= 4821 end", "password: redacted redacted end", id="inner-label-at-the-end"),
    pytest.param("password: abcdefgh-pin:4821-token:abcd end", "password: redacted end", id="inner-closed"),
]


@pytest.mark.parametrize(("text", "expected"), NESTED_TEXTS)
def test_a_credential_inside_another_match_is_redacted_too(text: str, expected: str) -> None:
    assert contracts.redact_text_secrets(text) == (expected, True)
    assert _task_start(text).text == expected


@pytest.mark.parametrize(
    "text", ["set the password for 30 days to expire", "change the password for your account to something stronger"]
)
def test_a_qualified_to_form_needs_a_secret_value(text: str) -> None:
    assert contracts.redact_text_secrets(text) == (text, False)


@pytest.mark.parametrize(("text", "spans"), sorted(BASE_SPANS.items()))
def test_every_value_the_base_revision_redacted_stays_redacted(text: str, spans: tuple[tuple[int, int], ...]) -> None:
    """A newer rule only adds redactions: each value span the base revision (efe9bb27d) replaced lies inside a
    span replaced now (spans of the text after JWTs, key-prefixed tokens and PEM lines are replaced)."""
    clean = contracts.redact_secret_tokens(text)
    now = contracts._secret_spans(clean)
    for start, end in spans:
        assert any(lo <= start and end <= hi for lo, hi in now), (clean[start:end], now)


def test_nested_keyword_redaction_is_linear_on_hostile_input() -> None:
    started = time.monotonic()
    for text in (  # "pin:" * 60_000 (every keyword inside one long value) is in the test above
        "password for a pin=1 is " * 10_000,
        "set the password for a pin=1 to " * 7_500,
        "token=" * 40_000,
        "password: " + "x" * 300 + "-pin:" * 40_000,
    ):
        contracts.redact_text_secrets(text)
    assert time.monotonic() - started < 5.0


# --- the user's own words: secret-shaped tokens without a keyword (live B2 re-run, N4) ----------------------

USER_WORDS_REDACTED = [
    pytest.param(
        "log in as demo-user with Kx9-Hunter2-fake-pw-77 please",
        "log in as demo-user with redacted please",
        id="no-keyword",
    ),
    pytest.param("(use Kx9Hunter2fakepw77xyz!)", "(use redacted!)", id="marks-kept"),
    pytest.param("トークンはAbC123dEf456GhI789jKl0です", "トークンはredactedです", id="ja-ascii-run"),
    # the trade-off, as for typed text: a long identifier mixing letters and digits is redacted too
    pytest.param("find order-2026-000123-final", "find redacted", id="identifier"),
]

USER_WORDS_KEPT = [
    pytest.param("log in as demo-user at http://127.0.0.1:8499/login.html", id="username-and-url"),
    pytest.param("send the report to alice.smith@example-corp.com tomorrow", id="email"),
    pytest.param("open /Users/me/Documents/report-2026-final.pdf", id="path"),
    pytest.param("meet on 2026-10-22T10:00:00+09:00", id="date-time"),
    pytest.param("the project-management-dashboard-overview page", id="hyphenated-words"),
    pytest.param("check www.example.com/reports?id=1234 again", id="host-path"),
    pytest.param("Hunter2-fake-pw is short", id="under-twenty-characters"),
]


@pytest.mark.parametrize(("text", "expected"), USER_WORDS_REDACTED)
def test_a_secret_shaped_token_in_the_users_words_is_redacted(text: str, expected: str) -> None:
    assert contracts.redact_secret_shaped_tokens(text) == (expected, True)
    event = _task_start(text)
    assert event.text == expected and "text_secrets_redacted" in event.exclusions
    correction = normalize(
        phase="correction", source="user_correction", actor="human", action={"op": "other"}, text=text
    )
    assert correction.text == expected


@pytest.mark.parametrize("text", USER_WORDS_KEPT)
def test_ordinary_tokens_in_the_users_words_are_kept(text: str) -> None:
    assert contracts.redact_secret_shaped_tokens(text) == (text, False)
    assert _task_start(text).text == text


def test_secret_shaped_tokens_are_kept_outside_the_users_words() -> None:
    text = "log in as demo-user with Kx9-Hunter2-fake-pw-77 please"
    agent = normalize(phase="boundary", actor="agent", action={"op": "task_start", "site": "example.com"}, text=text)
    page = normalize(action={"op": "navigate", "site": "example.com"}, page_text=text)
    assert agent.text == text and page.page_text == text


# --- a two-word keyword joined by any same-line whitespace (operator parity, 2026-10-22) -------------------

SPACED_KEYWORD_TEXTS = [
    pytest.param("api key: abc123def", "api key: redacted", id="one-space"),
    pytest.param("api  key: abc123def", "api  key: redacted", id="two-spaces"),
    pytest.param("api\tkey: abc123def", "api\tkey: redacted", id="tab"),
    pytest.param("api\xa0key: abc123def", "api\xa0key: redacted", id="nbsp"),
    pytest.param("api\u3000key: abc123def", "api\u3000key: redacted", id="ideographic-space"),
    pytest.param("access\t\ttoken = abcdef", "access\t\ttoken = redacted", id="access-token"),
    pytest.param("one time  code 482913", "one time  code redacted", id="one-time-code"),
    pytest.param("pin  code 0000", "pin  code redacted", id="pin-code"),
    # the first word read on its own too: the base revision read "code=1234" as the value after "pin"
    pytest.param("pin  code=1234", "pin  redacted", id="pin-reading-kept"),
    pytest.param("パスワードにHun\x01ter2-xを入力", "パスワードにredactedを入力", id="ja-forward-control-character"),
]


@pytest.mark.parametrize(("text", "expected"), SPACED_KEYWORD_TEXTS)
def test_a_two_word_keyword_is_joined_by_any_same_line_whitespace(text: str, expected: str) -> None:
    assert contracts.redact_text_secrets(text) == (expected, True)
    assert contracts.looks_like_secret(text)


def test_a_keyword_never_spans_a_line_break() -> None:
    assert contracts.redact_text_secrets("api\nkey: abc123def") == ("api\nkey: abc123def", False)


# --- the values the redactor replaces, and replacing given values (live B2 re-run, N1 / N5) -------------------


def test_secret_values_are_the_values_the_redactor_replaces() -> None:
    text = f"type Zebra-77-fake as the password, PIN: 4821, key sk-proj-Ab3dEf6hIj9kLm and {JWT}"
    values = contracts.secret_values(text)
    assert {"Zebra-77-fake", "4821", "sk-proj-Ab3dEf6hIj9kLm", JWT} <= set(values)
    assert contracts.REDACTED not in values
    assert contracts.secret_values("pin the tab to the left") == []


def test_given_values_are_replaced_as_whole_words_never_in_a_url_host() -> None:
    text = "sign in at https://example.com/example?u=example with example, not xexample or example2 or EXAMPLE."
    assert contracts.redact_values(text, ["example"]) == (
        "sign in at https://example.com/redacted?u=redacted with redacted, not xexample or example2 or redacted.",
        True,
    )
    assert contracts.redact_values("nothing here", ["example"]) == ("nothing here", False)
    assert contracts.redact_values("a-b+c", ["b+c", "a-b+c"]) == ("redacted", True)  # the longest first


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


#: What an event without a page host carries about the page it may have been on.
PAGE_CONTENT: dict[str, Any] = {
    "page_title": "Acme Portal Home",
    "page_text": "HOME-PAGE-TEXT-7731 Search invoices; the password: Hunter2-fake-pw",
    "query": "?q=Contoso",
}
#: (phase, op, source, actor, the text is the user's own words): the attribution rule of the history surfaces.
HOSTLESS_TEXTS = [
    ("boundary", "task_start", "operator", "human", True),
    ("boundary", "task_start", "hermes", "agent", False),
    ("boundary", "task_end", "operator", "agent", False),
    ("boundary", "task_end", "operator", "human", False),
    ("correction", "other", "user_correction", "human", True),
    ("correction", "other", "operator", "human", False),
    ("correction", "other", "user_correction", "unknown", False),
]


def _hostless(phase: str, op: str, source: str, actor: str) -> dict[str, Any]:
    """A boundary or correction event as an operator sends it for the page a task started or ended on: no site,
    no route, the page's title and text (D1 of the 2026-10-22 live check)."""
    action = {"op": op, "target": "link Invoice INV-1001", "site": None, "route": None, "args": {}}
    return raw_event(phase=phase, source=source, actor=actor, action=action, text="Search for Contoso", **PAGE_CONTENT)


@pytest.mark.parametrize(("phase", "op", "source", "actor", "own"), HOSTLESS_TEXTS)
def test_an_event_without_a_page_host_keeps_only_the_users_words_while_sites_are_excluded(
    phase: str, op: str, source: str, actor: str, own: bool
) -> None:
    event = normalize_event(_hostless(phase, op, source, actor), excluded_sites=PRIVATE_SITES)

    assert contracts.EXCLUSION_PAGE_HOST_UNKNOWN == "page_host_unknown"
    assert (event.page_title, event.page_text, event.query, event.target) == (None, None, None, None)
    assert event.text == ("Search for Contoso" if own else None)
    # Only the drop is marked: nothing that was dropped leaves a redaction or truncation mark behind.
    assert event.exclusions == ("page_host_unknown",)
    assert not event.truncated
    assert (event.phase, event.op, event.site, event.route) == (phase, op, None, None)  # the boundary itself stays


def test_without_exclusions_an_event_without_a_page_host_keeps_its_content() -> None:
    event = normalize_event(_hostless("boundary", "task_end", "operator", "agent"), excluded_sites=SITES)

    assert (event.page_title, event.query, event.target, event.text) == (
        "Acme Portal Home",
        "?q=Contoso",
        "link Invoice INV-1001",
        "Search for Contoso",
    )
    assert event.page_text is not None and "HOME-PAGE-TEXT-7731" in event.page_text
    assert "page_host_unknown" not in event.exclusions


@pytest.mark.parametrize(
    "action",
    [
        {"op": "task_end", "site": "example.com"},
        {"op": "task_end", "route": "https://example.com/search?q=Contoso"},
    ],
    ids=["site", "full-url-route"],
)
def test_an_event_on_a_known_host_keeps_its_content_while_other_sites_are_excluded(action: dict[str, Any]) -> None:
    raw = raw_event(phase="boundary", action=action, text="I searched for Contoso", page_title="Invoice Search Results")

    event = normalize_event(raw, excluded_sites=PRIVATE_SITES)

    assert (event.site, event.text, event.page_title) == (
        "example.com",
        "I searched for Contoso",
        "Invoice Search Results",
    )
    assert "page_host_unknown" not in event.exclusions


def test_an_event_without_a_page_host_and_without_content_is_not_marked() -> None:
    gap = raw_event(phase="gap", action={"op": "other", "args": {"reason": "source_excluded"}})

    event = normalize_event(gap, excluded_sites=PRIVATE_SITES)

    assert event.exclusions == ()
    assert json.loads(event.args_json) == {"reason": "source_excluded"}


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
