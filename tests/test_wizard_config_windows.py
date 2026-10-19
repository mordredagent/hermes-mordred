"""Windows writer consumers over the real canonical coordinator."""

from __future__ import annotations

import json

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes import _config_text_io, _dotenv_io
from mordred_hermes.wizard import _uninstall_config as cleanup
from mordred_hermes.wizard import configure, egress_cli
from mordred_hermes.wizard import credentials_writer as credentials
from mordred_hermes.wizard import env_file_writer as env
from mordred_hermes.wizard import policy_writer as pw
from tests.test_config_io import fs as fs
from tests.test_openclaw_migration import windows_source as windows_source


@pytest.fixture
def writer(fs, monkeypatch):
    backend, paths = fs
    monkeypatch.setattr(pw, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(_config_text_io, "_windows", lambda: True)
    monkeypatch.setattr(env, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(_dotenv_io, "_windows", lambda: True)
    return backend, pw.PolicyWriter(
        paths.home / paths.config_name, paths.home / "mordred" / "policy.json", paths.home / "mordred"
    )


def put(directory, name, data):
    directory.files[name] = data, directory.backend.identity()


def test_write_preserves_yaml_overrides_and_noop_identity(writer):
    b, w = writer
    put(b.home, "config.yaml", b'# retained\nmodel: "quoted"\nplugins:\n  enabled: [other, mordred_network]\n')
    put(b.policy, "policy.json", b'{"provider_overrides": ["opaque-invalid"]}')
    w.write(pw.PolicySnapshot("strict"))
    config = b.home.files["config.yaml"][0].decode()
    assert "# retained" in config and 'model: "quoted"' in config
    assert "other" in config and "mordred_network" not in config
    assert json.loads(b.policy.files["policy.json"][0])["provider_overrides"] == ["opaque-invalid"]
    before = b.home.files.copy(), b.policy.files.copy()
    w.write(pw.PolicySnapshot("strict"))
    assert (b.home.files, b.policy.files) == before
    assert ".policy-write.pending" not in b.policy.files


@pytest.mark.parametrize(
    "member,data", [("config", b"[unterminated"), ("config", b"[]"), ("policy", b"{oops"), ("policy", b"[]")]
)
@pytest.mark.parametrize("operation", ["write", "emit", "upsert", "merge", "migrate"])
def test_whole_malformed_pair_refused_without_publication(writer, member, data, operation):
    b, w = writer
    put(b.home, "config.yaml", b"{}")
    put(b.policy, "policy.json", b"{}")
    put(b.home if member == "config" else b.policy, "config.yaml" if member == "config" else "policy.json", data)
    before = b.home.files.copy(), b.policy.files.copy()
    with pytest.raises(ValueError):
        invoke(w, operation)
    assert (b.home.files, b.policy.files) == before


def invoke(w, operation):
    if operation == "write":
        w.write(pw.PolicySnapshot("strict"))
    elif operation == "emit":
        w.emit_policy_json(pw.PolicySnapshot("strict"))
    elif operation == "migrate":
        w.migrate_plugin_identity(create_missing=True)
    else:
        getattr(w, f"{operation}_mordred_sections")({"mordred_wizard": {"done": True}})


@pytest.mark.parametrize("operation", ["emit", "upsert", "merge", "migrate"])
def test_only_full_write_recovers_pending_pair(writer, operation):
    b, w = writer
    put(b.policy, ".policy-write.pending", b"prior interrupted update")
    with pytest.raises(cio.PolicyPendingError):
        invoke(w, operation)
    w.write(pw.PolicySnapshot("strict"))
    assert ".policy-write.pending" not in b.policy.files


def test_dotenv_checked_rmw_preserves_export_style(writer):
    b, w = writer
    put(b.home, ".env", b"# retained\nexport MORDRED_TOKEN=old\nOTHER=value\n")
    env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_TOKEN", value="new")
    assert b.home.files[".env"][0] == b"# retained\nexport MORDRED_TOKEN=new\nOTHER=value\n"


def test_dotenv_surrogate_rejected_before_any_filesystem_work(writer):
    b, w = writer
    with pytest.raises(UnicodeError):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="MORDRED_TOKEN", value="\ud800")
    assert b.events == []


def test_cleanup_rereads_and_backs_up_current_pair(writer, monkeypatch):

    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True, raising=False)
    put(b.home, "config.yaml", b"plugins:\n  enabled: [mordred, other]\n")
    plan = cleanup.plan_config_cleanup(w.config_path)
    assert plan.changed
    put(b.home, "config.yaml", b"# new edit\nmodel: newer\nplugins:\n  enabled: [mordred, other]\n")
    result = cleanup.apply_config_cleanup(w.config_path, lock_dir=w.mordred_dir, stamp="now")
    assert result.error is None
    assert b"newer" in b.home.files["config.yaml"][0]
    assert b"mordred" not in b.home.files["config.yaml"][0]
    assert b.home.files["config.yaml.mordred-uninstall-now.bak"][0].startswith(b"# new edit")


def test_cleanup_plan_malformed_yaml_preserves_checked_pair(writer, monkeypatch):
    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True)
    put(b.home, "config.yaml", b"plugins: [unclosed\n")
    put(b.policy, "policy.json", b'{"mode": "strict"}')
    before = b.home.files.copy(), b.policy.files.copy()

    plan = cleanup.plan_config_cleanup(w.config_path)

    assert plan.error is not None and not plan.changed
    assert plan.removed == [] and plan.unknowns == [] and plan.backup is None
    assert (b.home.files, b.policy.files) == before


def test_cleanup_env_preserves_published_backup_path_and_collision_source(writer, monkeypatch):

    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True, raising=False)
    put(b.home, ".env", b"OTHER=kept\nMORDRED_TOKEN=secret\n")
    result = cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir, stamp="now")
    assert result.saved_to == w.mordred_dir / "env-removed-now.env"
    assert b.home.files[".env"][0] == b"OTHER=kept\n"
    assert b"MORDRED_TOKEN=secret" in b.policy.files["env-removed-now.env"][0]
    put(b.home, ".env", b"MORDRED_TOKEN=new\n")
    with pytest.raises(cio.PrivateFSError, match="exists"):
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir, stamp="now")
    assert b.home.files[".env"][0] == b"MORDRED_TOKEN=new\n"


@pytest.fixture
def child(writer, monkeypatch):
    from contextlib import contextmanager

    from tests.test_config_io import Directory

    b, w = writer
    d = Directory(b, "child")

    @contextmanager
    def opener(path, *, create=False):
        assert b.home.locked and b.policy.locked
        assert path not in (w.mordred_dir, w.config_path.parent)
        yield d

    monkeypatch.setattr(credentials, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(cleanup, "_windows", lambda: True, raising=False)
    monkeypatch.setattr(pw, "open_private_directory", opener, raising=False)
    return b, w, d


def test_credentials_checked_child_and_noop(child):
    from mordred_hermes.wizard.credentials_writer import JSONCredentialsWriter

    _b, w, d = child
    target = w.mordred_dir / "credentials" / "network.json"
    kwargs = dict(mullvad_account_id_env="MORDRED_ACCOUNT", mullvad_relay_country="auto", mullvad_killswitch=True)
    JSONCredentialsWriter().write_network(target, **kwargs)
    before = d.files.copy()
    JSONCredentialsWriter().write_network(target, **kwargs)
    assert d.files == before
    assert json.loads(d.files["network.json"][0])["mullvad"]["account_id_env"] == "MORDRED_ACCOUNT"


def test_explicit_backup_directory_kept_and_outer_cleanup_uncertain(child):

    b, w, d = child
    put(b.home, ".env", b"MORDRED_TOKEN=secret\n")
    savedir = w.mordred_dir / "backups"
    b.fault = "home:close"
    with pytest.raises(cio.PrivateFSError) as error:
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=savedir, stamp="now")
    assert d.files["env-removed-now.env"][0].endswith(b"MORDRED_TOKEN=secret\n")
    assert error.value.commit_state == "uncertain"


def test_configure_flags_resolve_from_locked_current_pair(writer, monkeypatch):
    import argparse

    b, w = writer
    put(b.policy, "policy.json", b'{"policy":"lenient", "local_llm_model_id":"kept"}')
    put(b.home, "config.yaml", b"plugins:\n  mordred_llm_guard:\n    harness_primary: other\n")
    monkeypatch.setattr(configure, "PolicyWriter", lambda: w)
    monkeypatch.setattr(configure, "_windows", lambda: True, raising=False)
    assert configure.cli_handler(argparse.Namespace(non_interactive=True, policy="strict")) == 0
    body = json.loads(b.policy.files["policy.json"][0])
    assert body["policy"] == "strict" and body["local_llm_model_id"] == "kept"


def test_egress_edits_preserve_checked_unrelated_fields(writer, monkeypatch):

    b, w = writer
    put(
        b.home,
        "config.yaml",
        b"plugins:\n  mordred_privacy_check:\n    tool_egress:\n      taint: false\n      blocklist: [example.org]\n",
    )
    monkeypatch.setattr(egress_cli, "_windows", lambda: True, raising=False)
    assert egress_cli.egress_set("ask", config_path=w.config_path) == 0
    assert b"example.org" in b.home.files["config.yaml"][0]
    assert b"taint: false" in b.home.files["config.yaml"][0]
    assert b"level: ask" in b.home.files["config.yaml"][0]


def test_generic_windows_writer_does_not_enable_unmigrated_lifecycle(writer):
    _, w = writer
    with pytest.raises(cio.PrivateFSError, match="unsupported"):
        pw._atomic_write_text(w.mordred_dir / "memory-enabled", "enabled")


@pytest.mark.parametrize("data", [b"", b"null", b"42", b"\xff"])
def test_present_nonmapping_config_never_becomes_fresh_state(writer, data):
    b, w = writer
    put(b.home, "config.yaml", data)
    with pytest.raises((ValueError, UnicodeError)):
        w.write(pw.PolicySnapshot("strict"))
    assert b.home.files["config.yaml"][0] == data
    assert "policy.json" not in b.policy.files


@pytest.mark.parametrize("fault", ["policy:create:policy.json", "policy:delete:.policy-write.pending", "home:close"])
def test_public_writer_publication_fault_keeps_uncertainty(writer, fault):
    b, w = writer
    b.fault = fault
    with pytest.raises(cio.PrivateFSError) as error:
        w.write(pw.PolicySnapshot("strict"))
    assert error.value.commit_state == "uncertain"
    if fault != "home:close":
        assert ".policy-write.pending" in b.policy.files


@pytest.mark.parametrize("data", [b"\xff", b"x" * (cio.DOTENV_LIMIT + 1)], ids=["invalid_utf8", "oversize"])
def test_bad_dotenv_source_stays_unchanged(writer, data):
    b, w = writer
    put(b.home, ".env", data)
    with pytest.raises((UnicodeError, cio.PrivateFSError)):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="KEY", value="new")
    assert b.home.files[".env"][0] == data


def test_custom_pair_names_and_split_roots(writer):
    b, w = writer
    custom = pw.PolicyWriter(
        w.config_path.with_name("custom.yaml"), w.policy_json_path.with_name("custom.json"), w.mordred_dir
    )
    custom.write(pw.PolicySnapshot("strict"))
    assert b"policy: strict" in b.home.files["custom.yaml"][0]
    assert json.loads(b.policy.files["custom.json"][0])["policy"] == "strict"
    custom.mordred_dir = custom.mordred_dir / "elsewhere"
    with pytest.raises(ValueError):
        custom.write(pw.PolicySnapshot("off"))


@pytest.mark.parametrize("stamp", ["../escape", "x.y", "", "colon:stream"])
def test_cleanup_stamp_rejected_before_reads(writer, monkeypatch, stamp):

    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True)
    with pytest.raises(ValueError):
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir, stamp=stamp)
    assert not b.events


def test_dotenv_newline_key_is_rejected_before_mutation(writer):
    b, w = writer
    with pytest.raises(ValueError):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="KEY\n", value="secret")
    assert not b.events


def test_credentials_newline_reference_is_rejected_before_mutation(child):
    b, w, _d = child
    with pytest.raises(ValueError):
        credentials.JSONCredentialsWriter().write_network(
            w.mordred_dir / "credentials" / "network.json",
            mullvad_account_id_env="MORDRED_ACCOUNT\n",
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
    assert not b.events


def test_credentials_rejection_does_not_disclose_secret_candidate(child):
    _b, w, _d = child
    secret = "1234-5678-private-account"
    with pytest.raises(ValueError) as error:
        credentials.JSONCredentialsWriter().write_network(
            w.mordred_dir / "credentials" / "network.json",
            mullvad_account_id_env=secret,
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
    assert secret not in str(error.value)


def test_busy_explicit_backup_destination_refuses_without_wait_or_source_change(child, monkeypatch):
    from contextlib import contextmanager

    b, w, d = child
    put(b.home, ".env", b"MORDRED_TOKEN=secret\n")

    @contextmanager
    def held_destination(*, blocking=True):
        if blocking:
            raise AssertionError("explicit backup acquisition would wait while holding canonical locks")
        raise cio.PrivateFSError("busy", "private_lock")
        yield  # pragma: no cover

    monkeypatch.setattr(d, "transaction", held_destination)
    with pytest.raises(cio.PrivateFSError, match="busy"):
        cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir / "custom-backup", stamp="now")
    assert b.home.files[".env"][0] == b"MORDRED_TOKEN=secret\n"
    assert d.files == {}


@pytest.mark.parametrize("operation", ["credentials", "backup"])
@pytest.mark.parametrize("child_stage", ["verify", "unlock", "close"])
def test_child_uncertainty_survives_canonical_cleanup_failure(child, monkeypatch, operation, child_stage):
    from contextlib import contextmanager

    b, w, d = child
    leaf = "network.json" if operation == "credentials" else "env-removed-now.env"
    original_failure = cio.PrivateFSError("unsafe", f"child_{child_stage}")
    cleanup_failure = cio.PrivateFSError("io", "canonical_close")
    put(b.home, ".env", b"MORDRED_TOKEN=secret\n")

    def fail(event):
        if event == "home:close":
            raise cleanup_failure
        if (child_stage == "verify" and event == f"child:read:{leaf}") or (
            child_stage == "unlock" and event == "child:unlock"
        ):
            raise original_failure

    b.hook = fail
    if child_stage == "close":

        @contextmanager
        def opener(path, *, create=False):
            assert b.home.locked and b.policy.locked
            yield d
            raise original_failure

        monkeypatch.setattr(pw, "open_private_directory", opener)

    with pytest.raises(cio.PrivateFSError) as error:
        if operation == "credentials":
            credentials.JSONCredentialsWriter().write_network(
                w.mordred_dir / "credentials" / "network.json",
                mullvad_account_id_env="MORDRED_ACCOUNT",
                mullvad_relay_country="auto",
                mullvad_killswitch=True,
            )
        else:
            cleanup.apply_env_cleanup(w.config_path.parent / ".env", save_dir=w.mordred_dir / "uninstall", stamp="now")
    assert leaf in d.files
    assert error.value is original_failure
    assert error.value.commit_state == "uncertain"
    assert b.home.files[".env"][0] == b"MORDRED_TOKEN=secret\n"


def test_interactive_configure_preserves_overrides_at_owning_transaction(writer, monkeypatch):
    from contextlib import contextmanager

    from mordred_hermes import _policy_io
    from tests.test_configure import _core_answers, _ScriptedPromptIO, _SetupRunnerSpy

    b, w = writer
    put(b.home, "config.yaml", b"{}")
    put(b.policy, "policy.json", b'{"provider_overrides": {"operator":"old"}}')
    monkeypatch.setattr(configure, "_windows", lambda: True)
    monkeypatch.setattr(_policy_io, "_platform", "nt")
    original_session = pw.canonical_session

    @contextmanager
    def concurrent_update(paths, **kwargs):
        # Another cooperating writer commits after any preflight read, before
        # this writer acquires its session. Both operations use the real C2 API.
        with original_session(paths, scope="policy", create=True) as operator, operator.policy_update() as update:
            update.put_policy(b'{"provider_overrides": ["new-invalid-but-opaque"]}')
            update.commit()
        with original_session(paths, **kwargs) as session:
            yield session

    monkeypatch.setattr(pw, "canonical_session", concurrent_update)

    class Prompts(_ScriptedPromptIO):
        def _pop(self, kind, label, default):
            assert not b.home.locked and not b.policy.locked
            return super()._pop(kind, label, default)

    result = configure.run(
        setup_runner=_SetupRunnerSpy(),
        prompt_io=Prompts(_core_answers(policy="strict")),
        policy_writer=w,
    )
    assert json.loads(b.policy.files["policy.json"][0])["provider_overrides"] == ["new-invalid-but-opaque"]
    assert result.snapshot.provider_overrides == ["new-invalid-but-opaque"]


def test_dotenv_oversize_value_rejected_before_any_filesystem_work(writer):
    b, w = writer
    with pytest.raises(ValueError, match="configuration exceeds its byte limit"):
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="KEY", value="x" * (cio.DOTENV_LIMIT + 1))
    assert b.events == []


def test_dotenv_cleanup_failure_keeps_publication_uncertain(writer):
    b, w = writer
    b.fault = "home:close"
    with pytest.raises(cio.PrivateFSError) as error:
        env.DotEnvFileWriter().upsert(w.config_path.parent / ".env", key="KEY", value="new")
    assert error.value.commit_state == "uncertain"
    assert b.home.files[".env"][0] == b"KEY=new\n"


def test_dotenv_noncanonical_name_rejected_before_session_open(writer):
    b, w = writer
    with pytest.raises(ValueError, match=r"canonical dotenv filename must be \.env"):
        env.DotEnvFileWriter().upsert(w.config_path.parent / "other.env", key="KEY", value="new")
    assert b.events == []


@pytest.mark.parametrize("reason", ["unsafe", "access_denied", "busy", "io"])
def test_cleanup_plan_preserves_checked_storage_refusal(writer, monkeypatch, reason):
    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True)
    put(b.home, "config.yaml", b"plugins: [unclosed\n")
    before = b.home.files.copy(), b.policy.files.copy()
    failure = cio.PrivateFSError(reason, "read_checked_config", commit_state="uncertain")

    def refuse(*args, **kwargs):
        raise failure

    monkeypatch.setattr(cleanup, "read_canonical_snapshot", refuse)
    with pytest.raises(cio.PrivateFSError) as raised:
        cleanup.plan_config_cleanup(w.config_path)
    assert raised.value is failure
    assert (b.home.files, b.policy.files) == before


def test_cleanup_plan_preserves_pending_policy_error(writer, monkeypatch):
    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True)
    put(b.home, "config.yaml", b"plugins: [unclosed\n")
    put(b.policy, ".policy-write.pending", b"retain pending evidence")
    before = b.home.files.copy(), b.policy.files.copy()
    with pytest.raises(cio.PolicyPendingError):
        cleanup.plan_config_cleanup(w.config_path)
    assert (b.home.files, b.policy.files) == before


def test_cleanup_plan_preserves_malformed_policy_error(writer, monkeypatch):
    b, w = writer
    monkeypatch.setattr(cleanup, "_windows", lambda: True)
    put(b.home, "config.yaml", b"plugins: [unclosed\n")
    put(b.policy, "policy.json", b"{invalid policy")
    before = b.home.files.copy(), b.policy.files.copy()
    with pytest.raises(json.JSONDecodeError):
        cleanup.plan_config_cleanup(w.config_path)
    assert (b.home.files, b.policy.files) == before


@pytest.fixture
def network_home(child, monkeypatch, tmp_path):
    """Keep real coordination, admitting only the explicitly selected home."""
    from contextlib import contextmanager

    from mordred_hermes import _dotenv_io
    from mordred_hermes.wizard import network_cli

    b, w, d = child
    home = tmp_path / "selected home 日本語"
    w.config_path = home / "config.yaml"
    w.mordred_dir = home / "mordred"
    w.policy_json_path = w.mordred_dir / "policy.json"
    monkeypatch.setattr(_dotenv_io, "_windows", lambda: True)
    monkeypatch.setattr(network_cli, "_runtime_registered", lambda: False)

    @contextmanager
    def open_home(path, *, create=False):
        assert path == home, "network persistence reached another home"
        with b.open_home(path, create=create) as directory:
            yield directory

    @contextmanager
    def open_policy(path, *, create=False):
        assert path == home / "mordred", "network persistence reached another policy root"
        with b.open_policy(path, create=create) as directory:
            yield directory

    @contextmanager
    def open_credentials(path, *, create=False):
        assert path == home / "mordred" / "credentials"
        assert b.home.locked and b.policy.locked
        yield d

    for name in ("open_confidential_directory", "open_optional_confidential_directory"):
        monkeypatch.setattr(cio, name, open_home)
    for name in ("open_private_directory", "open_optional_private_directory"):
        monkeypatch.setattr(cio, name, open_policy)
    monkeypatch.setattr(pw, "open_private_directory", open_credentials)
    return b, w, d


def test_network_use_merges_only_selected_checked_home(network_home):
    import argparse

    from mordred_hermes.wizard import network_cli

    b, w, _d = network_home
    put(
        b.home,
        "config.yaml",
        b"# retained\nplugins:\n  mordred_network:\n    custom_user_field: keep\n    tor_socks_port: 9150\n",
    )
    assert network_cli.handle_use(argparse.Namespace(path="clearnet", config_path=w.config_path)) == 0
    config = b.home.files["config.yaml"][0]
    assert b"default_path: clearnet" in config
    assert b"custom_user_field: keep" in config and b"tor_socks_port: 9150" in config
    assert not w.config_path.parent.exists()


@pytest.mark.parametrize("mode", ["secret", "clear", "blank"])
def test_network_init_uses_selected_checked_home(network_home, monkeypatch, capsys, mode):
    import argparse

    from mordred_hermes.wizard import network_cli
    from tests.test_wizard_network_init import _ScriptedPromptIO

    b, w, d = network_home
    put(b.home, "config.yaml", b"plugins:\n  mordred_network:\n    custom_user_field: keep\n")
    put(b.home, ".env", b"OTHER=keep\nMORDRED_MULLVAD_ACCOUNT=old\n")
    prompts = _ScriptedPromptIO(["vpn", "mullvad", "selected-secret" if mode == "secret" else "", "jp", True])
    monkeypatch.setattr(network_cli, "PromptToolkitIO", lambda: prompts)
    args = argparse.Namespace(
        config_path=w.config_path, non_interactive=mode == "clear", path="vpn", clear_mullvad=mode == "clear"
    )
    assert network_cli.handle_init(args) == 0
    config = b.home.files["config.yaml"][0]
    assert b"default_path: vpn" in config and b"custom_user_field: keep" in config
    assert (
        b.home.files[".env"][0]
        == (
            {
                "secret": b"OTHER=keep\nMORDRED_MULLVAD_ACCOUNT=selected-secret\n",
                "clear": b"OTHER=keep\n",
                "blank": b"OTHER=keep\nMORDRED_MULLVAD_ACCOUNT=old\n",
            }[mode]
        )
    )
    assert json.loads(d.files["network.json"][0])["mullvad"] == {
        "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
        "relay_country": "auto" if mode == "clear" else "jp",
        "killswitch": mode != "clear",
    }
    captured = capsys.readouterr()
    assert "selected-secret" not in captured.out + captured.err
    assert not w.config_path.parent.exists()


@pytest.mark.parametrize(
    "invalid",
    [
        "env_home",
        "env_leaf",
        "credentials_home",
        "credentials_leaf",
        "split_policy",
        "mordred",
        "relative",
        "config_leaf",
        "unsafe_config_leaf",
    ],
)
def test_network_path_admission_precedes_every_writer(writer, monkeypatch, capsys, invalid):
    from pathlib import Path

    from mordred_hermes.wizard import network_cli

    b, w = writer
    home = w.config_path.parent
    env_path = home / ".env"
    credentials_path = home / "mordred" / "credentials" / "network.json"
    if invalid == "env_home":
        env_path = home / "other" / ".env"
    elif invalid == "env_leaf":
        env_path = home / "private-secret-sentinel.env"
    elif invalid == "credentials_home":
        credentials_path = home / "other" / "mordred" / "credentials" / "network.json"
    elif invalid == "credentials_leaf":
        credentials_path = credentials_path.with_name("private-secret-sentinel.json")
    elif invalid == "split_policy":
        w.policy_json_path = home / "other" / "policy.json"
    elif invalid == "mordred":
        w.mordred_dir = home / "other"
        w.policy_json_path = w.mordred_dir / "policy.json"
    elif invalid == "relative":
        w.config_path = Path("relative/config.yaml")
        w.mordred_dir = Path("relative/mordred")
        w.policy_json_path = w.mordred_dir / "policy.json"
    elif invalid == "unsafe_config_leaf":
        w.config_path = home / "private-secret-sentinel:stream"
    else:
        w.config_path = home / ".env"
    calls = []
    monkeypatch.setattr(w, "merge_mordred_sections", lambda *a, **kw: calls.append("policy"))
    monkeypatch.setattr(env.DotEnvFileWriter, "upsert", lambda *a, **kw: calls.append("env"))
    monkeypatch.setattr(
        credentials.JSONCredentialsWriter, "write_network", lambda *a, **kw: calls.append("credentials")
    )
    inputs = network_cli.NetworkInitInputs(
        network_cli.NetworkAnswers("vpn", "tor", 9050, "MORDRED_MULLVAD_ACCOUNT", "auto", False),
        "private-secret-sentinel",
    )
    rc = network_cli._persist_network(
        inputs,
        policy_writer=w,
        env_writer=env.DotEnvFileWriter(),
        credentials_writer=credentials.JSONCredentialsWriter(),
        env_path=env_path,
        credentials_path=credentials_path,
    )
    assert (rc, calls, b.events) == (1, [], [])
    captured = capsys.readouterr()
    assert captured.out == "" and "invalid network configuration" in captured.err
    assert "private-secret-sentinel" not in captured.err


@pytest.mark.parametrize("choice", ["keep-existing", "overwrite", "abort", "reset"])
def test_windows_policy_only_migration_uses_checked_writer_and_conflicts(writer, windows_source, monkeypatch, choice):
    from mordred_hermes import _yaml_io

    monkeypatch.setattr(_yaml_io, "_platform", "nt")
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade

    b, w = writer
    base, events, _ = windows_source
    base.mkdir(parents=True)
    source = {
        "plugins": {
            "entries": {
                "mordred-privacy-check": {
                    "config": {
                        "policy": "strict",
                        "allow_cloud_llm": True,
                        "cloud_provider_allowlist": ["custom", ""],
                        "ignored": "retained source only",
                    }
                }
            }
        }
    }
    (base.parent / "openclaw.json").write_text(json.dumps(source))
    w.write(pw.PolicySnapshot("lenient"))
    overrides = ["opaque-invalid-retained"]
    body = json.loads(b.policy.files["policy.json"][0])
    body["provider_overrides"] = overrides
    put(b.policy, "policy.json", json.dumps(body).encode())
    before = b.home.files.copy(), b.policy.files.copy()
    writes = []
    original_write = w.write

    def counted_write(snapshot):
        writes.append(snapshot)
        return original_write(snapshot)

    monkeypatch.setattr(w, "write", counted_write)
    options = upgrade.UpgradeOptions(reset=choice == "reset", policy_conflict=None if choice == "reset" else choice)
    if choice == "abort":
        with pytest.raises(SystemExit, match="abort"):
            migration.migrate(openclaw_base=base, policy_writer=w, options=options)
        assert (b.home.files, b.policy.files) == before
        assert writes == []
        return
    result = migration.migrate(openclaw_base=base, policy_writer=w, options=options)
    assert result == ("noop" if choice == "keep-existing" else "migrated")
    assert len(writes) == (0 if choice == "keep-existing" else 1)
    body = json.loads(b.policy.files["policy.json"][0])
    assert body["policy"] == ("lenient" if choice == "keep-existing" else "strict")
    assert body["provider_overrides"] == overrides
    after = b.home.files.copy(), b.policy.files.copy()
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=options) == (
        "noop" if choice == "keep-existing" else "migrated"
    )
    assert (b.home.files, b.policy.files) == after
    assert len(writes) == (0 if choice == "keep-existing" else 2)
    assert events


def test_windows_empty_recognized_policy_uses_legacy_defaults(writer, windows_source):
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade

    b, w = writer
    base, _, _ = windows_source
    base.mkdir(parents=True)
    (base.parent / "openclaw.json").write_text(
        json.dumps({"plugins": {"entries": {"mordred-privacy-check": {"config": {}}}}})
    )
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions()) == "migrated"
    body = json.loads(b.policy.files["policy.json"][0])
    assert (body["policy"], body["allow_cloud_llm"], body["cloud_provider_allowlist"]) == ("lenient", False, [])


@pytest.mark.parametrize("missing", ["mirror", "stale-mirror", "llm-plugin"])
def test_matching_privacy_section_still_reconciles_checked_pair(writer, windows_source, monkeypatch, missing):
    from mordred_hermes import _yaml_io
    from mordred_hermes.wizard import openclaw_migration as migration
    from mordred_hermes.wizard import upgrade

    monkeypatch.setattr(_yaml_io, "_platform", "nt")
    b, w = writer
    base, _, _ = windows_source
    base.mkdir(parents=True)
    (base.parent / "openclaw.json").write_text(
        json.dumps({"plugins": {"entries": {"mordred-privacy-check": {"config": {"policy": "strict"}}}}})
    )
    w.write(pw.PolicySnapshot("strict"))
    if missing == "mirror":
        del b.policy.files["policy.json"]
    elif missing == "stale-mirror":
        body = json.loads(b.policy.files["policy.json"][0])
        body["policy"] = "off"
        put(b.policy, "policy.json", json.dumps(body).encode())
    else:
        config = b.home.files["config.yaml"][0].decode().replace("    - mordred\n", "    - mordred_network\n")
        config = config.replace("harness_primary: none", "harness_primary: stale")
        put(b.home, "config.yaml", config.encode())
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions()) == "migrated"
    assert json.loads(b.policy.files["policy.json"][0])["policy"] == "strict"
    config = b.home.files["config.yaml"][0]
    assert b"harness_primary: none" in config and b"mordred_network\n" not in config
    after = b.home.files.copy(), b.policy.files.copy()
    b.events.clear()
    assert migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions()) == "migrated"
    assert (b.home.files, b.policy.files) == after
    assert not any(":replace:" in event or ":create:" in event or ":delete:" in event for event in b.events)
