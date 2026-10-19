"""Pure settings changes bind retained local keys to the full loopback endpoint."""

from dataclasses import replace

import pytest

from mordred_hermes.extension.telegram.llm import LlmConfigError
from mordred_hermes.extension.telegram.secrets import TelegramSecrets


@pytest.fixture
def current():
    return TelegramSecrets(
        api_id=123,
        api_hash="ab" * 16,
        store_key=b"k" * 32,
        session="synthetic-session",
        backend="venice",
        venice_api_key="synthetic-venice-key",
        venice_model="venice-model",
        local_endpoint="http://localhost:8080/v1/",
        local_model="old-model",
        local_api_key="synthetic-local-key",
    )


@pytest.mark.parametrize(
    ("old_endpoint", "endpoint", "want_key"),
    [
        ("http://localhost:8080/v1/", "http://127.0.0.1:8080/v1", "synthetic-local-key"),
        ("http://127.0.0.1:8080/v1", " http://localhost:8080/v1/// ", "synthetic-local-key"),
        ("http://127.0.0.1:8080/v1", "https://127.0.0.1:8080/v1", None),
        ("http://127.0.0.1:8080/v1", "http://[::1]:8080/v1", None),
        ("http://127.0.0.1:8080/v1", "http://127.0.0.1:8081/v1", None),
        ("http://127.0.0.1:8080/v1", "http://127.0.0.1:8080/other", None),
        (None, "http://127.0.0.1:8080/v1", None),
        ("not a URL", "http://127.0.0.1:8080/v1", None),
        ("http://127.0.0.1:bad/v1", "http://127.0.0.1:8080/v1", None),
        ("http://example.com:8080/v1", "http://127.0.0.1:8080/v1", None),
    ],
)
def test_local_omitted_key_requires_same_normalized_full_endpoint(current, old_endpoint, endpoint, want_key):
    from mordred_hermes.extension.telegram.llm_settings import with_local_settings

    current = replace(current, local_endpoint=old_endpoint)
    result = with_local_settings(current, endpoint=endpoint, model=" new-model ")
    assert result.local_api_key == want_key
    assert result.backend == "local" and result.local_model == "new-model"
    assert (
        replace(
            result,
            backend=current.backend,
            local_endpoint=current.local_endpoint,
            local_model=current.local_model,
            local_api_key=current.local_api_key,
        )
        == current
    )
    assert result is not current


@pytest.mark.parametrize(("key", "want"), [(None, None), (" new-token ", "new-token")])
def test_local_explicit_key_replaces_or_clears_on_changed_endpoint(current, key, want):
    from mordred_hermes.extension.telegram.llm_settings import with_local_settings

    result = with_local_settings(current, endpoint="http://127.0.0.1:8081/v1/", model=" m ", api_key=key)
    assert result.local_endpoint == "http://127.0.0.1:8081/v1"
    assert result.local_api_key == want


@pytest.mark.parametrize("key", ["", "bad token", "bad\r\nheader", "非ASCII"])
def test_local_replacement_key_is_validated(current, key):
    from mordred_hermes.extension.telegram.llm_settings import with_local_settings

    with pytest.raises(LlmConfigError, match=r"^local_api_key_invalid$"):
        with_local_settings(current, endpoint="http://127.0.0.1:8080/v1", model="m", api_key=key)


def test_local_new_endpoint_is_validated(current):
    from mordred_hermes.extension.telegram.llm_settings import with_local_settings

    with pytest.raises(LlmConfigError, match=r"^local_endpoint_invalid$"):
        with_local_settings(current, endpoint="http://example.com:8080/v1", model="m")


@pytest.mark.parametrize("model", [None, "", " new-model "])
@pytest.mark.parametrize("replace_key", [False, True])
def test_venice_retains_or_replaces_key_and_preserves_model_whitespace(current, model, replace_key):
    from mordred_hermes.extension.telegram.llm_settings import KEEP_KEY, with_venice_settings

    key = "new-venice-key" if replace_key else KEEP_KEY
    result = with_venice_settings(current, api_key=key, model=model)
    assert result.venice_api_key == ("new-venice-key" if replace_key else "synthetic-venice-key")
    assert result.venice_model == (" new-model " if model else "venice-model")
    assert result.backend == "venice"
    assert replace(result, venice_api_key=current.venice_api_key, venice_model=current.venice_model) == current


@pytest.mark.parametrize("old_key", [None, ""])
def test_venice_missing_key_is_a_stable_config_error(current, old_key):
    from mordred_hermes.extension.telegram.llm_settings import with_venice_settings

    with pytest.raises(LlmConfigError, match=r"^venice_not_configured$"):
        with_venice_settings(replace(current, venice_api_key=old_key))
