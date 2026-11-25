"""``keyvault init --backup-file``: no seed on screen, and a file plus the passphrase restore the keyvault."""

from __future__ import annotations

import argparse
import stat
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _bip39, _storage, api
from mordred_hermes.keyvault import pow as kvpow
from mordred_hermes.keyvault._backup_seed import NoSeedInBackup, seed_from_backup
from mordred_hermes.wizard import keyvault_cli, setup_cli
from tests._keyvault_fakes import FakeBackend

pytestmark = pytest.mark.usefixtures("fake_native_creation_receipts")

SEED = _bip39.entropy_to_mnemonic(bytes(range(1, 33)))
PASSPHRASE = "a long passphrase for the backup"


@pytest.fixture(autouse=True)
def _patches(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests._keyvault_owned_deletion import install_fake_owned_deletion

    install_fake_owned_deletion(monkeypatch)
    monkeypatch.setattr(kvpow, "POW_DIFFICULTY_BITS", 4)
    monkeypatch.setattr(_bip39, "generate_mnemonic", lambda: SEED)

    def no_blackout() -> Any:
        raise AssertionError("the backup-file flow must not ask for an air gap")

    monkeypatch.setattr("mordred_hermes.keyvault.network_fallback.resolve_blackout_assert", no_blackout)


class Prompts:
    """Answers password prompts from a queue and records every label asked."""

    def __init__(self, *passwords: str) -> None:
        self._passwords = list(passwords)
        self.asked: list[str] = []

    def ask_password(self, label: str, default: str = "") -> str:
        self.asked.append(label)
        return self._passwords.pop(0)

    def ask_text(self, label: str, default: str = "") -> str:
        raise AssertionError(f"no visible prompt is expected, got {label!r}")

    def ask_bool(self, label: str, default: bool) -> bool:
        return default

    def ask_choice(self, label: str, choices: Any, default: str) -> str:
        return default


def _sink(entry: dict[str, Any]) -> None:
    return None


def _init(home: Path, backup: Path, backend: FakeBackend, prompts: Prompts) -> int:
    return keyvault_cli.init_keyvault(
        home=home, backend=backend, prompt_io=prompts, audit_sink=_sink, backup_file=backup
    )


def test_init_saves_a_backup_file_without_showing_the_seed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home, backup = tmp_path / "a", tmp_path / "out" / "keyvault-backup.mrkv"
    home.mkdir()
    backup.parent.mkdir()
    prompts = Prompts(PASSPHRASE, PASSPHRASE)

    assert _init(home, backup, FakeBackend(), prompts) == 0

    assert prompts.asked == ["Choose a Passphrase", "Re-enter the Passphrase"]  # no digest, no seed
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    out = capsys.readouterr()
    words = SEED.split()
    for i in range(len(words) - 2):  # not even three of its words in a row
        assert " ".join(words[i : i + 3]) not in out.out + out.err
    assert seed_from_backup(backup.read_bytes(), PASSPHRASE)[0] == SEED
    keys = _storage.load_meta(_storage.resolve_keyvault_dir(home)).get("keys") or {}
    assert len(keys) == 1


def test_the_file_and_the_passphrase_restore_on_another_device(tmp_path: Path) -> None:
    device_a, device_b, backup = tmp_path / "a", tmp_path / "b", tmp_path / "keyvault-backup.mrkv"
    device_a.mkdir()
    device_b.mkdir()
    backend_a = FakeBackend()
    assert _init(device_a, backup, backend_a, Prompts(PASSPHRASE, PASSPHRASE)) == 0
    key_id = next(iter(_storage.load_meta(_storage.resolve_keyvault_dir(device_a))["keys"]))

    # Enter at the seed prompt: the seed comes from the file.
    rc = keyvault_cli.recover(
        blob_path=backup, home=device_b, backend=FakeBackend(), prompt_io=Prompts("", PASSPHRASE), audit_sink=_sink
    )
    assert rc == 0
    assert key_id in _storage.load_meta(_storage.resolve_keyvault_dir(device_b))["keys"]


def test_a_wrong_passphrase_restores_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    device_a, device_b, backup = tmp_path / "a", tmp_path / "b", tmp_path / "keyvault-backup.mrkv"
    device_a.mkdir()
    device_b.mkdir()
    assert _init(device_a, backup, FakeBackend(), Prompts(PASSPHRASE, PASSPHRASE)) == 0
    capsys.readouterr()

    rc = keyvault_cli.recover(
        blob_path=backup, home=device_b, backend=FakeBackend(), prompt_io=Prompts("", "not it"), audit_sink=_sink
    )
    assert rc == 1
    assert "Wrong passphrase" in capsys.readouterr().err
    assert not (_storage.load_meta(_storage.resolve_keyvault_dir(device_b)).get("keys") or {})


def test_a_paper_only_backup_still_needs_the_typed_seed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "a"
    home.mkdir()
    backend = FakeBackend()
    pow_bytes = kvpow.compute_pow(api._normalize_seed_phrase(SEED), difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    _handle, digest = api.prepare_generate(SEED, PASSPHRASE, pow_bytes)
    result = api.generate(SEED, PASSPHRASE, pow_bytes, digest, backend=backend, audit_sink=_sink, home=home)
    blob = api.export_backup(
        result.key_id, PASSPHRASE, backend=backend, audit_sink=_sink, home=home, seed_phrase=SEED, pow_bytes=pow_bytes
    )
    with pytest.raises(NoSeedInBackup):
        seed_from_backup(blob, PASSPHRASE)

    backup = tmp_path / "paper.mrkv"
    backup.write_bytes(blob)
    device_b = tmp_path / "b"
    device_b.mkdir()
    rc = keyvault_cli.recover(
        blob_path=backup, home=device_b, backend=FakeBackend(), prompt_io=Prompts("", PASSPHRASE), audit_sink=_sink
    )
    assert rc == 1
    assert "type the 24 words" in capsys.readouterr().err


def test_an_existing_output_file_is_refused_before_any_prompt(tmp_path: Path) -> None:
    home, backup = tmp_path / "a", tmp_path / "keyvault-backup.mrkv"
    home.mkdir()
    backup.write_bytes(b"something already here")
    prompts = Prompts()

    assert _init(home, backup, FakeBackend(), prompts) == 1
    assert prompts.asked == []
    assert backup.read_bytes() == b"something already here"
    assert not (_storage.load_meta(_storage.resolve_keyvault_dir(home)).get("keys") or {})


def test_setup_and_init_take_the_backup_file_flag() -> None:
    from mordred_hermes.wizard.cli import _setup_subparser

    parser = argparse.ArgumentParser(prog="hermes-mordred")
    _setup_subparser(parser)
    assert parser.parse_args(["keyvault", "init", "--backup-file", "/x/b.mrkv"]).backup_file == "/x/b.mrkv"
    args = parser.parse_args(["setup", "--backup-file", "/x/b.mrkv"])
    assert args.backup_file == "/x/b.mrkv"


def test_setup_preflight_with_a_backup_file_skips_the_air_gap(tmp_path: Path) -> None:
    # The autouse patch makes any air-gap probe fail the test.
    assert setup_cli._keyvault_preflight(home=tmp_path, backup_file=tmp_path / "b.mrkv") is None


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes-mordred", "setup", "--skip-hermes-setup", "--backup-file", "/x/b.mrkv"],
        ["hermes-mordred", "keyvault", "init", "--backup-file", "/x/b.mrkv"],
    ],
)
def test_the_backup_file_commands_stay_offline_maintenance(argv: list[str]) -> None:
    # A maintenance process takes no runtime database lease; setup's vault step needs the exclusive one.
    from mordred_hermes.dbcrypt._cli import maintenance_process

    assert maintenance_process(argv) is True


@pytest.mark.parametrize("command", [("setup",), ("keyvault", "init")])
def test_every_option_of_the_real_parser_is_known_to_the_startup_grammar(command: tuple[str, ...]) -> None:
    from mordred_hermes.dbcrypt._cli import maintenance_process
    from mordred_hermes.wizard.cli import _setup_subparser

    parser = argparse.ArgumentParser(prog="hermes-mordred")
    _setup_subparser(parser)
    action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    sub = action.choices[command[0]]
    for name in command[1:]:
        sub = next(a for a in sub._actions if isinstance(a, argparse._SubParsersAction)).choices[name]
    for option in sub._actions:
        if not option.option_strings or "--help" in option.option_strings:
            continue
        value = ["x"] if option.nargs is None and not isinstance(option, argparse._StoreConstAction) else []
        if isinstance(option, argparse._StoreTrueAction | argparse._StoreFalseAction):
            value = []
        argv = ["hermes-mordred", *command, option.option_strings[-1], *value]
        assert maintenance_process(argv) is True, argv


# --------------------------------------------------------------------------- #
# setup --no-prompts: a generated passphrase, saved inside the file
# --------------------------------------------------------------------------- #


class NoPrompts(Prompts):
    """Fails the test on any terminal question."""

    def ask_password(self, label: str, default: str = "") -> str:
        raise AssertionError(f"--no-prompts must not ask, got {label!r}")

    def ask_bool(self, label: str, default: bool) -> bool:
        raise AssertionError(f"--no-prompts must not ask, got {label!r}")


def _self_contained_init(home: Path, backup: Path, backend: FakeBackend) -> int:
    from mordred_hermes.keyvault import _backup_file
    from mordred_hermes.wizard._flow_session import FlowSession

    with FlowSession(unattended=False) as session:
        session.remember_passphrase(_backup_file.generate_passphrase())
        return keyvault_cli.init_keyvault(
            home=home,
            backend=backend,
            prompt_io=NoPrompts(),
            audit_sink=_sink,
            backup_file=backup,
            flow_session=session,
            embed_passphrase=True,
        )


def test_the_backup_file_format_round_trips_and_leaves_plain_blobs_alone() -> None:
    from mordred_hermes.keyvault import _backup_file

    packed = _backup_file.pack("päss", b"MRKV-blob")
    assert _backup_file.unpack(packed) == ("päss", b"MRKV-blob")
    assert _backup_file.unpack(b"MRKV-blob") == (None, b"MRKV-blob")
    with pytest.raises(_backup_file.BackupFileCorrupt):
        _backup_file.unpack(_backup_file.MAGIC + b"\x00\x05ab")
    assert len(_backup_file.generate_passphrase()) >= 40


def test_a_self_contained_file_alone_restores_on_another_device(tmp_path: Path) -> None:
    from mordred_hermes.keyvault import _backup_file

    device_a, device_b, backup = tmp_path / "a", tmp_path / "b", tmp_path / "keyvault-backup.mrkv"
    device_a.mkdir()
    device_b.mkdir()
    assert _self_contained_init(device_a, backup, FakeBackend()) == 0
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    passphrase, blob = _backup_file.unpack(backup.read_bytes())
    assert passphrase is not None
    assert seed_from_backup(blob, passphrase)[0] == SEED
    key_id = next(iter(_storage.load_meta(_storage.resolve_keyvault_dir(device_a))["keys"]))

    rc = keyvault_cli.recover(
        blob_path=backup, home=device_b, backend=FakeBackend(), prompt_io=NoPrompts(), audit_sink=_sink
    )
    assert rc == 0
    assert key_id in _storage.load_meta(_storage.resolve_keyvault_dir(device_b))["keys"]


def test_no_prompts_needs_a_backup_file_and_excludes_non_interactive(capsys: pytest.CaptureFixture[str]) -> None:
    from mordred_hermes.wizard.cli import _setup_subparser

    parser = argparse.ArgumentParser(prog="hermes-mordred")
    _setup_subparser(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["setup", "--no-prompts", "--non-interactive"])
    args = parser.parse_args(["setup", "--no-prompts"])
    assert setup_cli.cli_setup(args) == 2
    assert "--no-prompts needs --backup-file" in capsys.readouterr().err


def test_no_prompts_generates_for_a_new_keyvault_and_reads_the_file_later(tmp_path: Path) -> None:
    from mordred_hermes.keyvault import _backup_file
    from mordred_hermes.wizard._flow_session import FlowSession

    home, backup = tmp_path / "home", tmp_path / "b.mrkv"
    home.mkdir()
    options = setup_cli.SetupOptions(no_prompts=True, backup_file=backup)
    with FlowSession() as first:
        assert setup_cli._seed_no_prompt_passphrase(home=home, options=options, session=first) is None
        assert first.passphrase and len(first.passphrase) >= 40

    assert _self_contained_init(home, backup, FakeBackend()) == 0
    stored, _blob = _backup_file.unpack(backup.read_bytes())
    with FlowSession() as later:  # the keyvault exists now: the file's passphrase, not a new one
        assert setup_cli._seed_no_prompt_passphrase(home=home, options=options, session=later) is None
        assert later.passphrase == stored


def test_a_self_contained_backup_that_cannot_be_written_points_at_the_installer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mordred_hermes.wizard import keyvault_export_cli

    device, backup = tmp_path / "a", tmp_path / "keyvault-backup.mrkv"
    device.mkdir()
    monkeypatch.setattr(keyvault_export_cli, "_publish_backup", lambda path, data: False)
    assert _self_contained_init(device, backup, FakeBackend()) == 1
    err = capsys.readouterr().err
    assert "Open the Mordred installer again: it starts the keys over" in err
    assert "hermes-mordred" not in err  # nothing to type: the installer's next run recovers
    assert not backup.exists()
