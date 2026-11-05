"""Offline, profile-bound erasure of Mail and Telegram history only."""

from __future__ import annotations

from pathlib import Path

from .._core._database_contracts import DatabaseRefused
from .._core._database_lifecycle import ExclusiveLease
from ..dbcrypt._maintenance import maintenance_scope
from ..keyvault._reset_authority import ResetAuthorization, check_reset_access
from ._protected_destination import checked_store_destination


def erase_reset_history(home: Path, *, lease: ExclusiveLease, _reset: ResetAuthorization) -> None:
    """One SQLCipher transaction under an existing EX lease, outside custody.

    A missing store is a no-op. Existing plaintext, unadopted, foreign-profile
    or unsupported stores refuse; this path never initializes or creates one.
    """
    check_reset_access(home, _reset, component="database")
    path = home / "plugin-data/mordred/mordred.db"
    try:
        path.lstat()
    except FileNotFoundError:
        return
    path = checked_store_destination(path, home=home)
    with maintenance_scope(home, lease=lease) as scope, scope.connection(path) as conn:
        tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "import_meta" not in tables:
            if any(name.startswith("import_") for name in tables):
                raise DatabaseRefused("incomplete import schema; reset history retained")
            return
        meta = {str(k): str(v) for k, v in conn.execute("SELECT key, value FROM import_meta")}
        if meta.get("profile_home") != str(home) or meta.get("schema_version", "") not in {"1", "2"}:
            raise DatabaseRefused("foreign or unsupported import store; reset history retained")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("INSERT INTO import_parts_fts(import_parts_fts, rank) VALUES ('secure-delete', 1)")
            for table in ("import_parts", "import_mail_refs"):
                if table not in tables and table == "import_mail_refs" and meta["schema_version"] == "1":
                    continue
                conn.execute(
                    f"DELETE FROM {table} WHERE source_uid IN "  # noqa: S608 - fixed table identifiers only
                    "(SELECT source_uid FROM import_messages WHERE conv_uid IN "
                    "(SELECT conv_uid FROM import_conversations WHERE source IN ('mail','telegram')) "
                    "OR run_id IN (SELECT run_id FROM import_runs WHERE source IN ('mail','telegram')))"
                )
            conn.execute(
                "DELETE FROM import_messages WHERE conv_uid IN "
                "(SELECT conv_uid FROM import_conversations WHERE source IN ('mail','telegram')) "
                "OR run_id IN (SELECT run_id FROM import_runs WHERE source IN ('mail','telegram'))"
            )
            for table in ("import_conversations", "import_accounts", "import_runs"):
                conn.execute(f"DELETE FROM {table} WHERE source IN ('mail','telegram')")  # noqa: S608
            conn.execute(
                "DELETE FROM import_meta WHERE substr(key,1,10)='mail_imap.' "
                "OR substr(key,1,5)='mail.' OR substr(key,1,9)='telegram.'"
            )
            # FTS triggers remove the tokens; integrity-check verifies that the
            # surviving external-content index agrees with the remaining rows.
            conn.execute("INSERT INTO import_parts_fts(import_parts_fts, rank) VALUES ('integrity-check', 1)")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
