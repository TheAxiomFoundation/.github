"""Verbatim path helpers from axiom-encode; test data, never RuleSpec modules.

Source: src/axiom_encode/harness/validator_pipeline.py
Ref: 5ddb5ea4a3d98d386330ca4a076ecb1beb54e16a
Only validation of a supplied existing Path is injected by the tests.
"""
from __future__ import annotations
import contextlib
import re
from pathlib import Path
from typing import Iterable
RULESPEC_ATOMIC_MODULE_ROOTS = {"statutes", "regulations", "policies", "legislation"}

def _same_section_path_parts_for_file(
    rules_file: Path,
    policy_repo_path: Path,
) -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
    """Return source root, section path, and child fragments for same-section imports."""
    resolved_file = rules_file.resolve()
    resolved_root = policy_repo_path.resolve()
    relative_parts: tuple[str, ...] | None = None
    with contextlib.suppress(ValueError):
        relative_parts = resolved_file.relative_to(resolved_root).parts
    if relative_parts is None:
        parts = resolved_file.parts
        for source_root in ("statutes", "regulations"):
            with contextlib.suppress(ValueError):
                source_index = parts.index(source_root)
                relative_parts = tuple(parts[source_index:])
                break
    if relative_parts is None or len(relative_parts) < 2:
        return None

    normalized_parts = tuple(Path(part).stem for part in relative_parts)
    if normalized_parts[0] == "statutes" and len(normalized_parts) >= 3:
        return (
            "statutes",
            normalized_parts[1:3],
            normalized_parts[3:],
        )
    if normalized_parts[0] == "regulations":
        if len(normalized_parts) >= 4 and normalized_parts[1].endswith("-cfr"):
            return (
                "regulations",
                normalized_parts[1:4],
                normalized_parts[4:],
            )
        if len(normalized_parts) >= 3:
            return (
                "regulations",
                normalized_parts[1:3],
                normalized_parts[3:],
            )
    return None

def _rulespec_path_or_child_exists_static(
    policy_repo_path: Path,
    import_base: str,
) -> bool:
    """Return whether a cited same-section RuleSpec source exists locally."""
    relative = Path(import_base)
    return (policy_repo_path / relative.with_suffix(".yaml")).exists() or (
        policy_repo_path / relative
    ).is_dir()

def _normalize_rulespec_import_path_static(import_path: str) -> str:
    normalized = import_path.split("#", 1)[0].strip().strip("\"'")
    if ":" in normalized:
        _, tail = normalized.split(":", 1)
        normalized = tail
    return normalized.strip("/")

def _resolve_rulespec_import_file_static(
    import_path: str,
    *,
    rules_file: Path,
    policy_repo_path: Path,
    rulespec_dependency_roots: Iterable[Path] | None = None,
) -> Path | None:
    """Resolve an import to a validated file in a recognized RuleSpec root."""

    def validated_existing(candidate: Path) -> Path | None:
        # ``Path.exists`` follows symlinks, so check ``is_symlink`` as well to
        # fail closed for broken links rather than silently treating them as a
        # missing import.  The shared validator also walks parent components
        # without resolving them first, rejecting directory indirection and
        # traversal outside the active or a recognized cross-repo root.
        if not candidate.exists() and not candidate.is_symlink():
            return None
        return validate_rulespec_context_file(candidate, policy_repo_path)

    normalized = _normalize_rulespec_import_path_static(import_path)
    if not normalized:
        return None
    normalized_path = Path(normalized)
    if normalized_path.is_absolute() or any(
        part in {"", ".", ".."} for part in normalized_path.parts
    ):
        raise UnsafeRulespecContextPath(
            f"RuleSpec import target is outside the active policy root: {import_path}"
        )
    if (
        not normalized_path.parts
        or normalized_path.parts[0] not in RULESPEC_ATOMIC_MODULE_ROOTS
    ):
        return None

    repo_prefix = _rulespec_import_prefix_static(import_path)
    if repo_prefix:
        target_ref = _parse_rulespec_target(import_path)
        if target_ref is None:
            return None
        # A declared jurisdiction prefix is authoritative. Route it only
        # through the canonical active checkout or explicit dependency roots;
        # a same-relative-path flat fixture must not shadow the target.
        resolved = _resolve_rulespec_target_file(
            target_ref,
            policy_repo_path,
            rulespec_dependency_roots=rulespec_dependency_roots,
        )
        if resolved is not None:
            return resolved
        return None

    candidate = policy_repo_path / f"{normalized}.yaml"
    if resolved := validated_existing(candidate):
        return resolved

    with contextlib.suppress(ValueError):
        relative_parent = rules_file.parent.resolve().relative_to(
            policy_repo_path.resolve()
        )
        candidate = policy_repo_path / relative_parent / f"{normalized}.yaml"
        if resolved := validated_existing(candidate):
            return resolved
    return None

def _rulespec_import_prefix_static(import_path: str) -> str | None:
    normalized = import_path.split("#", 1)[0].strip().strip("\"'")
    if ":" not in normalized:
        return None
    prefix, tail = normalized.split(":", 1)
    if re.fullmatch(r"[a-z][a-z0-9-]*", prefix) and tail:
        return prefix
    return None
