"""Unit tests for scamhelper.okf module (Google Open Knowledge Format parser & validator)."""

import pytest
from pathlib import Path
from scamhelper.okf import (
    parse_note_content,
    OKFValidationError,
    OKFBundle,
)


def test_valid_note_passes():
    content = """---
type: scam_type
scam_type: sample_scam
title: Sample Scam
status: draft
---
# Sample Scam Body
This is a test body.
"""
    note = parse_note_content(content, "test.md")
    assert note.type == "scam_type"
    assert note.scam_type == "sample_scam"
    assert note.title == "Sample Scam"
    assert note.is_draft is True
    assert "test body" in note.body


def test_missing_type_fails():
    content = """---
title: Note without type
status: draft
---
Body text.
"""
    with pytest.raises(OKFValidationError) as exc_info:
        parse_note_content(content, "missing_type.md")
    assert "missing required non-empty 'type'" in str(exc_info.value)


def test_malformed_frontmatter_fails():
    content = """This file has no frontmatter delimiter."""
    with pytest.raises(OKFValidationError) as exc_info:
        parse_note_content(content, "bad.md")
    assert "does not begin with YAML frontmatter" in str(exc_info.value)


def test_draft_note_is_not_quoted_as_verified():
    content = """---
type: scam_type
scam_type: draft_scam
title: Draft Scam
status: draft
---
Extremely specific advisory details.
"""
    note = parse_note_content(content, "draft.md")
    assert note.is_draft is True
    safe_summary = note.get_safe_summary()
    assert "This matches a known pattern (draft note, not yet verified)" in safe_summary


def test_bundle_validation_on_project_notes():
    """Verify that the actual notes bundle in the project passes all OKF conformance rules."""
    repo_root = Path(__file__).resolve().parent.parent
    notes_dir = repo_root / "notes"

    bundle = OKFBundle(notes_dir)
    bundle.load()

    # Must find index.md and log.md
    assert bundle.index_note is not None
    assert bundle.log_note is not None
    assert len(bundle.notes) >= 8  # 12 scam types + index.md + log.md

    is_valid, errors = bundle.validate()
    assert is_valid is True, f"OKF Bundle validation failed with errors: {errors}"
    assert len(errors) == 0


def test_bundle_search():
    repo_root = Path(__file__).resolve().parent.parent
    notes_dir = repo_root / "notes"

    bundle = OKFBundle(notes_dir)
    results = bundle.search_notes("electricity bill power cut", top_k=2)
    assert len(results) > 0
    assert results[0].scam_type == "utility_disconnection"
