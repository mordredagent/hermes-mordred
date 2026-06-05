"""Tests for ``hermes mordred network init`` -- on-demand network privacy setup.

The six network prompts (default path, Tor binary/port, Mullvad
account/relay/killswitch) used to live inside ``hermes mordred configure``.
They now live behind this dedicated command so first-run setup stays short and
privacy is opt-in via an explicit command (user request 2026-06-05).

Contract:
- ``collect_network_answers`` runs the six prompts, seeding each prompt's
  default from the existing on-disk ``plugins.mordred_network`` section so a
  re-run with Enter keeps current values.
- The Mullvad secret never lands in :class:`NetworkAnswers` (env-var REFERENCE
  only) and is redacted from the transient inputs object's repr.
- A blank Mullvad answer KEEPS the existing secret (re-run safe) rather than
  stripping the ``.env`` line.
- ``run_init`` merges (never whole-replaces) ``plugins.mordred_network`` so
  unrelated user fields survive, routes the secret to the env writer, and the
  relay/killswitch indirection to the credentials writer.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter
from mordred_hermes.wizard.env_file_writer import DotEnvFileWriter
from mordred_hermes.wizard.network_cli import (
    NetworkAnswers,
    collect_network_answers,
    handle_init,
    run_init,
)
from mordred_hermes.wizard.policy_writer import PolicyWriter

# --------------------------------------------------------------------------- #
# Test doubles                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class _ScriptedPromptIO:
    """Pops a pre-recorded answer per call; records (kind, label, default)."""

    answers: list[object]
    seen: list[tuple[str, str, object]] = field(default_factory=list)

    def _pop(self, kind: str, label: str, default: object) -> object:
        if not self.answers:
            raise AssertionError(f"_ScriptedPromptIO ran out of answers at {kind}({label!r})")
        a = self.answers.pop(0)
        self.seen.append((kind, label, default))
        return a

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        return str(self._pop("choice", label, default))

    def ask_text(self, label: str, default: str = "") -> str:
        return str(self._pop("text", label, default))

    def ask_bool(self, label: str, default: bool) -> bool:
        return bool(self._pop("bool", label, default))

    def ask_password(self, label: str, default: str = "") -> str:
        return str(self._pop("password", label, default))


@dataclass
class _DefaultEchoPromptIO:
    """Returns the supplied default for every prompt (simulates pressing Enter)."""

    def ask_choice(self, label: str, choices: Sequence[str], default: str) -> str:
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        return default

    def ask_bool(self, label: str, default: bool) -> bool:
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        return default


class _SpyEnvFileWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, str]] = []

    def upsert(self, path: Path, *, key: str, value: str) -> None:
        self.calls.append((path, key, value))


class _SpyCredentialsWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, str, str, bool]] = []

    def write_network(
        self,
        path: Path,
        *,
        mullvad_account_id_env: str,
        mullvad_relay_country: str,
        mullvad_killswitch: bool,
    ) -> None:
        self.calls.append((path, mullvad_account_id_env, mullvad_relay_country, mullvad_killswitch))


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


# Full six-prompt answer set: path, tor binary, tor port, mullvad secret,
# relay country, killswitch.
_ANSWERS_FULL: list[object] = ["vpn", "/usr/bin/tor", "9150", "MULL-secret-99", "jp", True]


# --------------------------------------------------------------------------- #
# collect_network_answers                                                     #
# --------------------------------------------------------------------------- #


class TestCollectNetworkAnswers:
    def test_collects_six_prompts_into_network_answers(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        inputs = collect_network_answers(prompts)
        na = inputs.network_answers
        assert isinstance(na, NetworkAnswers)
        assert na.default_network_path == "vpn"
        assert na.tor_binary_path == "/usr/bin/tor"
        assert na.tor_socks_port == 9150
        assert na.mullvad_account_id_env == "MORDRED_MULLVAD_ACCOUNT"
        assert na.mullvad_relay_country == "jp"
        assert na.mullvad_killswitch is True

    def test_secret_captured_separately_not_in_network_answers(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        inputs = collect_network_answers(prompts)
        # The secret rides the transient inputs object, never NetworkAnswers.
        import dataclasses

        na_values = [getattr(inputs.network_answers, f.name) for f in dataclasses.fields(inputs.network_answers)]
        assert "MULL-secret-99" not in na_values
        assert inputs._mullvad_account_secret == "MULL-secret-99"

    def test_tor_socks_port_coerced_to_int(self) -> None:
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "9150", "", "auto", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9150
        assert isinstance(inputs.network_answers.tor_socks_port, int)

    def test_invalid_tor_socks_port_falls_back_to_default(self) -> None:
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "not-a-port", "", "auto", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9050

    def test_out_of_range_tor_socks_port_falls_back_to_default(self) -> None:
        prompts = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "70000", "", "auto", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.tor_socks_port == 9050

    def test_invalid_relay_country_falls_back_to_auto(self) -> None:
        prompts = _ScriptedPromptIO(answers=["clearnet", "/usr/bin/tor", "9050", "", "unitedstates", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.mullvad_relay_country == "auto"

    def test_2letter_relay_country_lowercased(self) -> None:
        prompts = _ScriptedPromptIO(answers=["clearnet", "/usr/bin/tor", "9050", "", "JP", False])
        inputs = collect_network_answers(prompts)
        assert inputs.network_answers.mullvad_relay_country == "jp"

    def test_prompt_labels_carry_no_phase_jargon(self) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        collect_network_answers(prompts)
        labels = [label for _, label, _ in prompts.seen]
        assert len(labels) == 6
        for label in labels:
            assert "Phase" not in label, f"user-facing label leaks internal jargon: {label!r}"


class TestCollectNetworkAnswersSeedsDefaults:
    """Re-run safety: each prompt's default comes from the existing on-disk
    section, so pressing Enter keeps the current value."""

    def test_existing_section_seeds_prompt_defaults(self) -> None:
        existing: Mapping[str, Any] = {
            "default_path": "tor",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
            "mullvad_relay_country": "se",
            "mullvad_killswitch": True,
        }
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing=existing)
        na = inputs.network_answers
        assert na.default_network_path == "tor"
        assert na.tor_binary_path == "/opt/tor/bin/tor"
        assert na.tor_socks_port == 19050
        assert na.mullvad_relay_country == "se"
        assert na.mullvad_killswitch is True

    def test_no_existing_section_uses_safe_defaults(self) -> None:
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing=None)
        na = inputs.network_answers
        assert na.default_network_path == "clearnet"
        assert na.tor_binary_path == "tor"
        assert na.tor_socks_port == 9050
        assert na.mullvad_relay_country == "auto"
        assert na.mullvad_killswitch is False

    def test_hand_edited_string_false_killswitch_seed_is_false(self) -> None:
        """A hand-edited quoted ``"false"`` must not flip the killswitch default
        to True on a re-run (plain ``bool("false")`` would). Codex review 2026-06-05."""
        echo = _DefaultEchoPromptIO()
        inputs = collect_network_answers(echo, existing={"mullvad_killswitch": "false"})
        assert inputs.network_answers.mullvad_killswitch is False


class TestNetworkInitInputsRedactsSecret:
    """The transient inputs object must not leak the Mullvad secret through
    ``repr``/``str`` (tracebacks, --showlocals, debuggers call repr)."""

    def test_repr_does_not_contain_secret(self) -> None:
        prompts = _ScriptedPromptIO(answers=["vpn", "/usr/bin/tor", "9050", "DO-NOT-LEAK-XYZ", "auto", True])
        inputs = collect_network_answers(prompts)
        assert "DO-NOT-LEAK-XYZ" not in repr(inputs)
        assert "DO-NOT-LEAK-XYZ" not in str(inputs)


# --------------------------------------------------------------------------- #
# NetworkAnswers dataclass (rehomed into network_cli)                         #
# --------------------------------------------------------------------------- #


class TestNetworkAnswersDataclass:
    def test_fields_present(self) -> None:
        import dataclasses

        names = {f.name for f in dataclasses.fields(NetworkAnswers)}
        assert names == {
            "default_network_path",
            "tor_binary_path",
            "tor_socks_port",
            "mullvad_account_id_env",
            "mullvad_relay_country",
            "mullvad_killswitch",
        }

    def test_to_config_yaml_section_shape(self) -> None:
        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/opt/tor/bin/tor",
            tor_socks_port=19050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=True,
        )
        assert na.to_config_yaml_section() == {
            "default_path": "vpn",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
            "mullvad_account_id_env": "MORDRED_MULLVAD_ACCOUNT",
            "mullvad_relay_country": "jp",
            "mullvad_killswitch": True,
        }

    def test_is_frozen(self) -> None:
        import dataclasses

        na = NetworkAnswers(
            default_network_path="clearnet",
            tor_binary_path="tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            na.default_network_path = "tor"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# run_init: persistence routing                                              #
# --------------------------------------------------------------------------- #


class TestRunInitPersistsConfig:
    def test_merges_network_section_into_config(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        w = _writer(tmp_path)
        rc = run_init(
            prompt_io=prompts,
            policy_writer=w,
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert rc == 0

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "vpn"
        assert section["tor_binary_path"] == "/usr/bin/tor"
        assert section["tor_socks_port"] == 9150
        assert section["mullvad_relay_country"] == "jp"
        assert section["mullvad_killswitch"] is True
        # Atomic-write contract: PolicyWriter adds the 5 plugin names.
        assert "mordred_network" in data["plugins"]["enabled"]

    def test_merge_preserves_unrelated_fields(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n"
            "  mordred_privacy_check:\n    policy: strict\n"
            "  mordred_network:\n    default_path: tor\n    custom_user_field: keep-me\n",
            encoding="utf-8",
        )
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        w = _writer(tmp_path)
        run_init(
            prompt_io=prompts,
            policy_writer=w,
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "strict"
        # The custom field the user hand-added must survive the merge.
        assert data["plugins"]["mordred_network"]["custom_user_field"] == "keep-me"
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"


class TestRunInitRoutesSecret:
    def test_env_writer_receives_secret(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        env_w = _SpyEnvFileWriter()
        env_path = tmp_path / ".env"
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=env_w,
            credentials_writer=_SpyCredentialsWriter(),
            env_path=env_path,
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert env_w.calls == [(env_path, "MORDRED_MULLVAD_ACCOUNT", "MULL-secret-99")]

    def test_credentials_writer_receives_relay_and_killswitch(self, tmp_path: Path) -> None:
        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        cred_w = _SpyCredentialsWriter()
        creds_path = tmp_path / "credentials" / "network.json"
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=cred_w,
            env_path=tmp_path / ".env",
            credentials_path=creds_path,
        )
        assert cred_w.calls == [(creds_path, "MORDRED_MULLVAD_ACCOUNT", "jp", True)]

    def test_blank_secret_does_not_touch_env_writer(self, tmp_path: Path) -> None:
        """Re-run safety: a blank Mullvad answer keeps the existing secret
        instead of stripping the .env line (Codex review 2026-06-05)."""
        prompts = _ScriptedPromptIO(answers=["clearnet", "/usr/bin/tor", "9050", "", "auto", False])
        env_w = _SpyEnvFileWriter()
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=env_w,
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert env_w.calls == [], "blank secret must NOT call the env writer (would wipe the existing line)"

    def test_blank_secret_preserves_existing_env_line(self, tmp_path: Path) -> None:
        env_path = tmp_path / ".env"
        env_path.write_text("MORDRED_MULLVAD_ACCOUNT=OLD-SECRET-KEEP\n", encoding="utf-8")
        prompts = _ScriptedPromptIO(answers=["clearnet", "/usr/bin/tor", "9050", "", "auto", False])
        run_init(
            prompt_io=prompts,
            policy_writer=_writer(tmp_path),
            env_writer=DotEnvFileWriter(),
            credentials_writer=JSONCredentialsWriter(),
            env_path=env_path,
            credentials_path=tmp_path / "credentials" / "network.json",
        )
        assert "MORDRED_MULLVAD_ACCOUNT=OLD-SECRET-KEEP" in env_path.read_text(encoding="utf-8")


class TestRunInitSeedsDefaultsFromDisk:
    """End-to-end re-run: with values already on disk, pressing Enter on every
    prompt must leave the config unchanged."""

    def test_enter_on_every_prompt_keeps_existing_values(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text(
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: tor\n"
            "    tor_binary_path: /opt/tor/bin/tor\n"
            "    tor_socks_port: 19050\n"
            "    mullvad_relay_country: se\n"
            "    mullvad_killswitch: true\n",
            encoding="utf-8",
        )
        run_init(
            prompt_io=_DefaultEchoPromptIO(),
            policy_writer=_writer(tmp_path),
            env_writer=_SpyEnvFileWriter(),
            credentials_writer=_SpyCredentialsWriter(),
            env_path=tmp_path / ".env",
            credentials_path=tmp_path / "credentials" / "network.json",
        )

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "tor"
        assert section["tor_binary_path"] == "/opt/tor/bin/tor"
        assert section["tor_socks_port"] == 19050
        assert section["mullvad_relay_country"] == "se"
        assert section["mullvad_killswitch"] is True


# --------------------------------------------------------------------------- #
# handle_init: CLI adapter                                                    #
# --------------------------------------------------------------------------- #


class TestInitSummary:
    """UX scope B: the post-init summary echoes the resolved settings so the
    user can confirm what was saved (and whether the Mullvad secret changed)."""

    def _na(self, *, path: str = "tor", killswitch: bool = True) -> NetworkAnswers:
        return NetworkAnswers(
            default_network_path=path,
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9150,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=killswitch,
        )

    def test_summary_echoes_settings_when_secret_written(self) -> None:
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(), secret_written=True)
        assert "tor" in out
        assert "/usr/bin/tor" in out
        assert "9150" in out
        assert "jp" in out
        assert "enabled" in out.lower()  # killswitch True
        assert "stored" in out.lower()  # secret written

    def test_summary_marks_secret_unchanged_and_clearnet_note(self) -> None:
        from mordred_hermes.wizard.network_cli import _init_summary

        out = _init_summary(self._na(path="clearnet", killswitch=False), secret_written=False)
        assert "unchanged" in out.lower()
        assert "disabled" in out.lower()  # killswitch False
        assert "clearnet" in out.lower()

    def test_run_init_prints_resolved_settings(self, tmp_path: Path) -> None:
        """End-to-end: run_init's printed summary reflects the saved path."""
        import io
        from contextlib import redirect_stdout

        prompts = _ScriptedPromptIO(answers=list(_ANSWERS_FULL))
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_init(
                prompt_io=prompts,
                policy_writer=_writer(tmp_path),
                env_writer=_SpyEnvFileWriter(),
                credentials_writer=_SpyCredentialsWriter(),
                env_path=tmp_path / ".env",
                credentials_path=tmp_path / "credentials" / "network.json",
            )
        out = buf.getvalue()
        assert "vpn" in out  # _ANSWERS_FULL default_path
        assert "9150" in out
        assert "stored" in out.lower()  # _ANSWERS_FULL has a non-blank secret


class TestHandleInit:
    def test_non_interactive_returns_exit_code_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        ns = argparse.Namespace(non_interactive=True)
        rc = handle_init(ns)
        assert rc == 2
        assert "non-interactive" in capsys.readouterr().err.lower()

    def test_interactive_path_persists_and_prints(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """End-to-end production wiring: real writers, scripted prompts, with
        ``.env`` / credentials paths resolved from a patched HERMES_BASE."""
        from mordred_hermes.wizard import network_cli as nc

        scripted = _ScriptedPromptIO(answers=["tor", "/usr/bin/tor", "9050", "MULL-xyz", "jp", True])
        monkeypatch.setattr(nc, "PromptToolkitIO", lambda: scripted)
        monkeypatch.setattr(nc, "HERMES_BASE", tmp_path)

        ns = argparse.Namespace(non_interactive=False, config_path=tmp_path / "config.yaml")
        rc = handle_init(ns)
        assert rc == 0

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"
        # Secret + credentials resolved relative to the patched HERMES_BASE.
        assert "MORDRED_MULLVAD_ACCOUNT=MULL-xyz" in (tmp_path / ".env").read_text(encoding="utf-8")
        assert (tmp_path / "mordred" / "credentials" / "network.json").exists()
        assert "default path" in capsys.readouterr().out.lower()
