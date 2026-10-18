"""Verbatim executable-index helpers from axiom-encode; test data, never RuleSpec modules.

Source: src/axiom_encode/harness/validator_pipeline.py
Ref: 5ddb5ea4a3d98d386330ca4a076ecb1beb54e16a
Each definition below is copied unchanged (decorators excluded: the pinned
index is lru_cached, which a property test must not reuse across cases).
Tests inject only the jurisdiction prefix and context-directory admission.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import yaml
RULESPEC_ATOMIC_MODULE_ROOTS = frozenset({"statutes", "regulations", "policies", "legislation"})
RULESPEC_FILE_SUFFIX = ".yaml"


def _rulespec_repo_prefix(root: Path) -> str:
    return root.name


def validate_rulespec_context_directory(candidate: Path, _root: Path) -> Path | None:
    return candidate if candidate.is_dir() else None

_DIRECT_SCALAR_VALUE_PATTERN = re.compile(r"-?[\d,]+(?:\.\d+)?")

@dataclass(frozen=True)
class _IndexedExecutableRule:
    """Executable RuleSpec rule discovered in a local rule repository."""

    target: str
    symbol: str
    signature: str
    source_file: str

def _rulespec_executable_index_for_roots(
    root_paths: tuple[str, ...],
) -> tuple[_IndexedExecutableRule, ...]:
    records: list[_IndexedExecutableRule] = []
    for root_path in root_paths:
        root = Path(root_path)
        if not root.exists():
            continue
        prefix = _rulespec_repo_prefix(root)
        for source_root_name in sorted(RULESPEC_ATOMIC_MODULE_ROOTS):
            source_root = validate_rulespec_context_directory(
                root / source_root_name,
                root,
            )
            if source_root is None:
                continue
            for rules_file in sorted(source_root.rglob("*.yaml")):
                if rules_file.name.endswith(".test.yaml"):
                    continue
                try:
                    payload = yaml.safe_load(rules_file.read_text())
                except (OSError, yaml.YAMLError, ValueError):
                    continue
                if (
                    not isinstance(payload, dict)
                    or payload.get("format") != "rulespec/v1"
                ):
                    continue
                rules = payload.get("rules")
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    if not _is_executable_rulespec_rule(rule):
                        continue
                    signature = _rulespec_executable_signature(rule)
                    if signature is None:
                        continue
                    symbol = _rulespec_rule_name(rule)
                    records.append(
                        _IndexedExecutableRule(
                            target=_canonical_rulespec_target(
                                prefix=prefix,
                                repo_root=root,
                                rules_file=rules_file,
                                symbol=symbol,
                            ),
                            symbol=symbol,
                            signature=signature,
                            source_file=str(rules_file.resolve()),
                        )
                    )
    return tuple(records)

def _is_executable_rulespec_rule(rule: Any) -> bool:
    if not isinstance(rule, dict):
        return False
    return str(rule.get("kind") or "").strip().lower() in {
        "parameter",
        "derived",
        "derived_relation",
    }

def _rulespec_rule_name(rule: dict[str, Any]) -> str:
    return str(rule.get("name") or "<unknown>").strip() or "<unknown>"

def _canonical_rulespec_target(
    *,
    prefix: str,
    repo_root: Path,
    rules_file: Path,
    symbol: str,
) -> str:
    relative = rules_file.resolve().relative_to(repo_root.resolve())
    if relative.suffix == RULESPEC_FILE_SUFFIX:
        relative = relative.with_suffix("")
    if not relative.parts or relative.parts[0] not in RULESPEC_ATOMIC_MODULE_ROOTS:
        raise ValueError(
            "RuleSpec target must be beneath a canonical content root "
            f"in the canonical jurisdiction root: {rules_file}"
        )
    return f"{prefix}:{relative.as_posix()}#{symbol}"

def _rulespec_executable_signature(rule: dict[str, Any]) -> str | None:
    versions = rule.get("versions")
    if not isinstance(versions, list):
        return None

    normalized_versions: list[dict[str, Any]] = []
    substantive = False
    for version in versions:
        if not isinstance(version, dict):
            continue
        normalized_version: dict[str, Any] = {}
        for key in ("effective_from", "from", "effective_to", "to"):
            if key in version:
                normalized_version[key] = _canonical_yaml_value(version.get(key))
        values = version.get("values")
        if isinstance(values, dict) and values:
            normalized_version["values"] = _canonical_yaml_value(values)
            substantive = True
        else:
            formula = version.get("formula")
            if isinstance(formula, str) and formula.strip():
                normalized_formula = _normalize_formula_signature(formula)
                normalized_version["formula"] = normalized_formula
                if _formula_signature_is_substantive(normalized_formula):
                    substantive = True
        if "values" in normalized_version or "formula" in normalized_version:
            normalized_versions.append(normalized_version)

    if not normalized_versions or not substantive:
        return None

    payload = {
        "kind": str(rule.get("kind") or "").strip().lower(),
        "dtype": str(rule.get("dtype") or "").strip(),
        "period": str(rule.get("period") or "").strip(),
        "unit": str(rule.get("unit") or "").strip(),
        "indexed_by": str(rule.get("indexed_by") or "").strip(),
        "versions": normalized_versions,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))

def _normalize_formula_signature(formula: str) -> str:
    return re.sub(r"\s+", " ", formula.strip())

def _formula_signature_is_substantive(formula: str) -> bool:
    numeric = _numeric_rule_value(formula)
    if numeric is not None:
        value = numeric[1]
        return not (float(value).is_integer() and int(value) in {-1, 0, 1, 2, 3})
    if re.fullmatch(r"[A-Za-z_][\w.]*", formula):
        return False
    return True

def _numeric_rule_value(value: Any) -> tuple[str, float] | None:
    """Return a display string and numeric value for a YAML scalar."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return str(value), float(value)
    if isinstance(value, str) and _DIRECT_SCALAR_VALUE_PATTERN.fullmatch(value.strip()):
        raw = value.strip()
        return raw, float(raw.replace(",", ""))
    return None

def _canonical_yaml_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _canonical_yaml_value(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }
    if isinstance(value, list):
        return [_canonical_yaml_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
