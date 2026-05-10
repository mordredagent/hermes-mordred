"""Tests for the SKILL.md frontmatter parser.

Uses pytest ``tmp_path`` to create synthetic SKILL.md fixtures rather
than checked-in files, so each test owns its inputs explicitly. The
``tests/fixtures/`` skills used by the install_wrapper integration
tests (Phase D) live separately.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.privacy_check.skill_frontmatter import (
    SkillMetadata,
    SkillMetadataError,
    parse,
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "SKILL.md"
    p.write_text(body, encoding="utf-8")
    return p


class TestParseHappyPath:
    def test_full_mordred_block(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: tor-skill
description: A skill that requires Tor.
metadata:
  mordred:
    network_requirements: tor
    requires_keyvault: true
    outbound_endpoints:
      - https://api.example.com
      - https://api.example.org
---
Body content here.
""",
        )
        result = parse(path)
        assert result == SkillMetadata(
            name="tor-skill",
            network_requirements="tor",
            requires_keyvault=True,
            outbound_endpoints=("https://api.example.com", "https://api.example.org"),
        )

    @pytest.mark.parametrize("nr", ["tor", "vpn", "clearnet", "local-only"])
    def test_each_network_requirement_value(self, tmp_path: Path, nr: str) -> None:
        path = _write(
            tmp_path,
            f"""\
---
name: example
description: x
metadata:
  mordred:
    network_requirements: {nr}
---
""",
        )
        result = parse(path)
        assert result.network_requirements == nr

    def test_no_frontmatter_returns_empty_metadata(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "Just markdown body, no frontmatter.\n")
        assert parse(path) == SkillMetadata(None, None, False, ())

    def test_frontmatter_without_metadata_block(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: bare-skill
description: No metadata block at all.
---
""",
        )
        assert parse(path) == SkillMetadata("bare-skill", None, False, ())

    def test_metadata_without_mordred_block(self, tmp_path: Path) -> None:
        """Author/version metadata per agentskills.io spec but no mordred extension."""
        path = _write(
            tmp_path,
            """\
---
name: author-only
description: Has metadata but no mordred extension.
metadata:
  author: example-org
  version: "1.0"
---
""",
        )
        assert parse(path) == SkillMetadata("author-only", None, False, ())

    def test_partial_mordred_block(self, tmp_path: Path) -> None:
        """Only network_requirements set; other fields default."""
        path = _write(
            tmp_path,
            """\
---
name: partial
description: x
metadata:
  mordred:
    network_requirements: vpn
---
""",
        )
        assert parse(path) == SkillMetadata("partial", "vpn", False, ())


class TestParseInvalidInputs:
    def test_invalid_network_requirement_value_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: bad
description: x
metadata:
  mordred:
    network_requirements: bogus
---
""",
        )
        with pytest.raises(SkillMetadataError, match="network_requirements"):
            parse(path)

    def test_outbound_endpoints_must_be_list_of_strings(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: bad
description: x
metadata:
  mordred:
    outbound_endpoints:
      - https://ok.example.com
      - 42
---
""",
        )
        with pytest.raises(SkillMetadataError, match="outbound_endpoints"):
            parse(path)

    def test_outbound_endpoints_string_not_list_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: bad
description: x
metadata:
  mordred:
    outbound_endpoints: "https://oops.example.com"
---
""",
        )
        with pytest.raises(SkillMetadataError, match="outbound_endpoints"):
            parse(path)

    def test_metadata_block_wrong_type_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: bad
description: x
metadata: "this should be a mapping"
---
""",
        )
        with pytest.raises(SkillMetadataError, match="metadata must be a mapping"):
            parse(path)

    def test_mordred_block_wrong_type_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: bad
description: x
metadata:
  mordred: "should be a mapping"
---
""",
        )
        with pytest.raises(SkillMetadataError, match=r"metadata\.mordred must be a mapping"):
            parse(path)

    def test_unclosed_frontmatter_returns_empty(self, tmp_path: Path) -> None:
        """Missing closing ``---`` is treated as 'no frontmatter, no Mordred metadata'."""
        path = _write(
            tmp_path,
            """\
---
name: incomplete
description: no closing fence
""",
        )
        assert parse(path) == SkillMetadata(None, None, False, ())

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: x
description: x
metadata:
  mordred:
    network_requirements: tor
   bad_indent: true
---
""",
        )
        with pytest.raises(SkillMetadataError, match="malformed YAML"):
            parse(path)

    def test_frontmatter_yaml_must_be_mapping(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
- just
- a
- list
---
""",
        )
        with pytest.raises(SkillMetadataError, match="must be a YAML mapping"):
            parse(path)


class TestEdgeCases:
    def test_crlf_line_endings(self, tmp_path: Path) -> None:
        body = (
            "---\r\nname: crlf\r\ndescription: x\r\nmetadata:\r\n"
            "  mordred:\r\n    network_requirements: vpn\r\n---\r\nbody\r\n"
        )
        path = tmp_path / "SKILL.md"
        path.write_bytes(body.encode("utf-8"))
        assert parse(path).network_requirements == "vpn"

    def test_empty_frontmatter_body(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "---\n---\nbody\n")
        assert parse(path) == SkillMetadata(None, None, False, ())

    def test_requires_keyvault_explicit_false(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            """\
---
name: x
description: x
metadata:
  mordred:
    requires_keyvault: false
---
""",
        )
        assert parse(path).requires_keyvault is False
