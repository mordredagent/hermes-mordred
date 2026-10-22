"""Behaviour contract of activity event normalization and batch envelopes."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
import uuid
from typing import Any

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
        {"enabled": "yes", "max_batch_events": 1000, "review_mode": "task_boundary", "mystery": 1}
    )
    assert config.enabled is False
    assert config.max_batch_events == 100
    assert config.review_mode == "task_boundary"
    assert config.warnings == ("invalid value for enabled", "invalid value for max_batch_events", "unknown key mystery")
