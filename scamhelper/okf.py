"""Google Open Knowledge Format (OKF) loader, parser, and bundle validator.

Implements the OKF specification for knowledge bundles:
- Parses YAML frontmatter and markdown body.
- Enforces conformance: required 'type' field, reserved files (index.md, log.md),
  and bundle-relative markdown link integrity.
- Manages draft vs. verified note statuses, preventing unverified claims.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import yaml

from scamhelper.schemas import NoteSummary


class OKFValidationError(Exception):
    """Exception raised when an OKF note or bundle fails conformance."""
    pass


class OKFNote:
    """Represents a single parsed OKF note."""

    def __init__(self, file_path: str, frontmatter: Dict[str, Any], body: str):
        self.file_path = file_path
        self.frontmatter = frontmatter
        self.body = body.strip()

        # Common attributes
        self.type: str = str(frontmatter.get("type", ""))
        self.scam_type: Optional[str] = frontmatter.get("scam_type")
        self.title: str = frontmatter.get("title", Path(file_path).stem.replace("-", " ").title())
        self.aliases: List[str] = frontmatter.get("aliases", [])
        self.status: str = frontmatter.get("status", "draft")
        self.sources: List[Dict[str, Any]] = frontmatter.get("sources", [])
        self.last_verified: Optional[str] = frontmatter.get("last_verified")
        self.red_flags: List[str] = frontmatter.get("red_flags", [])
        self.urgent_triggers: List[str] = frontmatter.get("urgent_triggers", [])
        self.okf_version: Optional[str] = frontmatter.get("okf_version")

    @property
    def is_draft(self) -> bool:
        return self.status.lower() == "draft"

    def get_safe_summary(self) -> str:
        """Return safe explanation respecting the draft note constraint."""
        if self.is_draft:
            prefix = "This matches a known pattern (draft note, not yet verified).\n"
        else:
            prefix = ""
        return prefix + self.body


def parse_note_content(content: str, file_path: str = "<memory>") -> OKFNote:
    """
    Parse markdown content with YAML frontmatter.
    Validates OKF conformance:
    1. Bounded by --- at start.
    2. Valid YAML dict frontmatter.
    3. Required 'type' key with non-empty string.
    Tolerates unknown keys.
    """
    content = content.lstrip("\ufeff")  # remove BOM if present
    if not content.startswith("---"):
        raise OKFValidationError(f"File '{file_path}' does not begin with YAML frontmatter delimiter '---'.")

    # Match frontmatter
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n(.*)$", content, re.DOTALL)
    if not match:
        raise OKFValidationError(f"File '{file_path}' has unclosed or malformed YAML frontmatter.")

    fm_raw, body = match.group(1), match.group(2)
    try:
        fm = yaml.safe_load(fm_raw)
    except Exception as exc:
        raise OKFValidationError(f"File '{file_path}' contains invalid YAML frontmatter: {exc}")

    if not isinstance(fm, dict):
        raise OKFValidationError(f"File '{file_path}' frontmatter must be a YAML mapping/dictionary.")

    note_type = fm.get("type")
    if not note_type or not isinstance(note_type, str) or not note_type.strip():
        raise OKFValidationError(f"File '{file_path}' is missing required non-empty 'type' frontmatter key.")

    return OKFNote(file_path=file_path, frontmatter=fm, body=body)


def parse_note_file(file_path: Path | str) -> OKFNote:
    """Read and parse a note from disk."""
    path = Path(file_path)
    if not path.is_file():
        raise OKFValidationError(f"File not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    return parse_note_content(content, file_path=str(path))


class OKFBundle:
    """
    Manages an OKF knowledge bundle directory:
    - Root index.md (reserved)
    - log.md (reserved)
    - Subdirectories of notes (e.g., scam-types/)
    - Validates bundle conformance and markdown link references.
    """

    def __init__(self, root_dir: Path | str):
        self.root_dir = Path(root_dir).resolve()
        self.notes: Dict[str, OKFNote] = {}  # keyed by bundle-relative path (e.g. /scam-types/fake-kyc.md)
        self.scam_type_map: Dict[str, OKFNote] = {}  # keyed by scam_type field
        self.index_note: Optional[OKFNote] = None
        self.log_note: Optional[OKFNote] = None

    def load(self) -> None:
        """Scan directory and load all markdown notes."""
        self.notes.clear()
        self.scam_type_map.clear()
        self.index_note = None
        self.log_note = None

        if not self.root_dir.exists():
            return

        for root, _, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith(".md"):
                    full_path = Path(root) / file
                    rel_path = "/" + str(full_path.relative_to(self.root_dir)).replace("\\", "/")
                    try:
                        note = parse_note_file(full_path)
                        self.notes[rel_path] = note

                        if rel_path == "/index.md":
                            self.index_note = note
                        elif rel_path == "/log.md":
                            self.log_note = note

                        if note.scam_type:
                            self.scam_type_map[note.scam_type] = note
                    except OKFValidationError:
                        # Will be reported during validate()
                        pass

    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate the entire OKF bundle conformance.
        Checks:
        1. index.md exists and has non-empty type.
        2. log.md exists and has non-empty type.
        3. All markdown files parse with valid YAML frontmatter and required non-empty 'type'.
        4. All bundle-relative markdown links (e.g. [title](/scam-types/x.md)) resolve to valid notes.
        Returns (is_valid, list_of_errors).
        """
        errors: List[str] = []

        if not self.root_dir.exists():
            return False, [f"Bundle root directory does not exist: {self.root_dir}"]

        # Check reserved files
        index_path = self.root_dir / "index.md"
        if not index_path.exists():
            errors.append(f"Missing reserved file: {index_path}")
        else:
            try:
                parse_note_file(index_path)
            except OKFValidationError as err:
                errors.append(str(err))

        log_path = self.root_dir / "log.md"
        if not log_path.exists():
            errors.append(f"Missing reserved file: {log_path}")
        else:
            try:
                parse_note_file(log_path)
            except OKFValidationError as err:
                errors.append(str(err))

        # Check all markdown files
        for root, _, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith(".md"):
                    full_path = Path(root) / file
                    rel_path = "/" + str(full_path.relative_to(self.root_dir)).replace("\\", "/")
                    try:
                        note = parse_note_file(full_path)
                        # Check bundle-relative links in body
                        link_pattern = re.compile(r"\[.*?\]\((/[^\s)]+\.md)\)")
                        for match in link_pattern.finditer(note.body):
                            target_rel = match.group(1)
                            target_disk = self.root_dir / target_rel.lstrip("/")
                            if not target_disk.exists():
                                errors.append(
                                    f"Broken link in '{rel_path}': target '{target_rel}' not found in bundle."
                                )
                    except OKFValidationError as err:
                        errors.append(str(err))

        return len(errors) == 0, errors

    def get_note(self, scam_type_or_path: str) -> Optional[OKFNote]:
        """Look up note by scam_type or bundle-relative path."""
        if scam_type_or_path in self.scam_type_map:
            return self.scam_type_map[scam_type_or_path]

        norm_path = scam_type_or_path if scam_type_or_path.startswith("/") else "/" + scam_type_or_path
        if norm_path in self.notes:
            return self.notes[norm_path]

        return None

    def search_notes(self, query: str, top_k: int = 3) -> List[NoteSummary]:
        """
        Search notes by keyword overlap or BM25 over title, aliases, and content.
        Returns top matching NoteSummary objects.
        """
        if not self.notes:
            self.load()

        results: List[Tuple[float, OKFNote]] = []
        tokens = [t.lower() for t in re.findall(r"\w+", query) if len(t) > 2]

        for note in self.notes.values():
            if note.type != "scam_type":
                continue

            score = 0.0
            searchable = (
                f"{note.title} {' '.join(note.aliases)} {' '.join(note.red_flags)} {note.body}"
            ).lower()

            for tok in tokens:
                if tok in note.title.lower():
                    score += 5.0
                if any(tok in alias.lower() for alias in note.aliases):
                    score += 4.0
                if any(tok in rf.lower() for rf in note.red_flags):
                    score += 3.0
                if tok in searchable:
                    score += 1.0

            if score > 0:
                results.append((score, note))

        results.sort(key=lambda x: x[0], reverse=True)
        summaries: List[NoteSummary] = []
        for score, note in results[:top_k]:
            summaries.append(
                NoteSummary(
                    scam_type=note.scam_type or "",
                    title=note.title,
                    status=note.status,
                    red_flags=note.red_flags[:3] if note.red_flags else [],
                    score=score,
                )
            )
        return summaries
