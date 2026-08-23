"""Tool-backed TypeScript adapters that wrap repo-native frontend tooling."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..engine import AdapterContext, AdapterUnavailableError, RulesAdapter
from ..models import FindingLocation, FindingSeverity, NormalizedFinding, RepoLanguage
from ..registry import create_default_registry

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..registry import RuleDefinition

_TYPECHECK_RULE_ID = "typescript.foundation.typecheck-clean"
_ESLINT_RULE_ID = "typescript.foundation.eslint-clean"
_TYPECHECK_CONFIG_CANDIDATES = ("tsconfig.json", "tsconfig.base.json")
_ESLINT_CONFIG_CANDIDATES = (
    "eslint.config.js",
    "eslint.config.cjs",
    "eslint.config.mjs",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintrc.yaml",
)
_TSC_DIAGNOSTIC_PATTERN = re.compile(
    r"^(?P<path>.+?)\((?P<line>\d+),(?P<column>\d+)\):\s*"
    r"error\s+(?P<code>TS\d+):\s*(?P<message>.+)$"
)
_TOOL_UNAVAILABLE_SNIPPETS = (
    "command not found",
    "couldn't find an eslint configuration file",
    "eslint: not found",
    "missing script",
)


@dataclass(frozen=True)
class _PackageInfo:
    scripts: dict[str, str]
    package_manager: str | None
    package_json: dict[str, object]


class TypeScriptTypecheckAdapter(RulesAdapter):
    adapter_key = "typescript-typecheck"

    def __init__(self) -> None:
        self._rule = create_default_registry().get(_TYPECHECK_RULE_ID)
        if self._rule is None:
            raise ValueError(f"Missing rule definition for {_TYPECHECK_RULE_ID}")

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> Sequence[NormalizedFinding]:
        if _TYPECHECK_RULE_ID not in rule_ids:
            return ()

        package_info = _load_package_info(context.repo_root, context.repo_profile.tooling)
        command = _resolve_typecheck_command(context.repo_root, package_info)
        completed = _run_tool_command(context.repo_root, command)
        findings = _parse_tsc_findings(
            rule=self._rule,
            repo_root=context.repo_root,
            target_files=context.target_files,
            mode=context.mode,
            output=_combine_tool_output(completed),
        )
        if completed.returncode != 0 and not findings:
            _raise_tool_command_error("TypeScript typecheck", completed)
        return findings


class TypeScriptEslintAdapter(RulesAdapter):
    adapter_key = "typescript-eslint"

    def __init__(self) -> None:
        self._rule = create_default_registry().get(_ESLINT_RULE_ID)
        if self._rule is None:
            raise ValueError(f"Missing rule definition for {_ESLINT_RULE_ID}")

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> Sequence[NormalizedFinding]:
        if _ESLINT_RULE_ID not in rule_ids:
            return ()

        package_info = _load_package_info(context.repo_root, context.repo_profile.tooling)
        command = _resolve_eslint_command(context.repo_root, package_info)
        completed = _run_tool_command(context.repo_root, command)
        findings = _parse_eslint_findings(
            rule=self._rule,
            repo_root=context.repo_root,
            target_files=context.target_files,
            mode=context.mode,
            output=_combine_tool_output(completed),
        )
        if completed.returncode != 0 and not findings:
            _raise_tool_command_error("ESLint", completed)
        return findings


def _load_package_info(repo_root: Path, tooling: Sequence[str]) -> _PackageInfo:
    package_json_path = repo_root / "package.json"
    if not package_json_path.is_file():
        raise AdapterUnavailableError("No package.json found for TypeScript tooling rules.")

    package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
    raw_scripts = package_json.get("scripts", {})
    if not isinstance(raw_scripts, dict):
        raw_scripts = {}
    scripts = {
        str(name): str(command)
        for name, command in raw_scripts.items()
        if isinstance(name, str) and isinstance(command, str)
    }

    package_manager = next(
        (manager for manager in ("pnpm", "yarn", "bun", "npm") if manager in tooling),
        None,
    )
    return _PackageInfo(scripts=scripts, package_manager=package_manager, package_json=package_json)


def _resolve_typecheck_command(repo_root: Path, package_info: _PackageInfo) -> list[str]:
    if "typecheck" in package_info.scripts:
        return _script_command(package_info.package_manager, "typecheck", "--pretty", "false")

    if any((repo_root / candidate).exists() for candidate in _TYPECHECK_CONFIG_CANDIDATES):
        local_tsc = _find_local_node_tool(repo_root, "tsc")
        if local_tsc is not None:
            return [str(local_tsc), "--noEmit", "--pretty", "false"]

    raise AdapterUnavailableError(
        "No repo-native TypeScript typecheck command or local tsc surface found."
    )


def _resolve_eslint_command(repo_root: Path, package_info: _PackageInfo) -> list[str]:
    lint_script = package_info.scripts.get("lint")
    if lint_script and "eslint" in lint_script:
        return _script_command(package_info.package_manager, "lint", "--format", "json")

    if _has_eslint_surface(repo_root, package_info.package_json):
        local_eslint = _find_local_node_tool(repo_root, "eslint")
        if local_eslint is not None:
            return [
                str(local_eslint),
                ".",
                "--ext",
                ".ts,.tsx",
                "--format",
                "json",
            ]

    raise AdapterUnavailableError("No repo-native ESLint config or lint script available.")


def _script_command(package_manager: str | None, script_name: str, *extra_args: str) -> list[str]:
    manager = package_manager or "npm"
    if manager == "npm":
        return ["npm", "run", "--silent", script_name, "--", *extra_args]
    if manager == "pnpm":
        return ["pnpm", "run", script_name, "--", *extra_args]
    if manager == "yarn":
        return ["yarn", script_name, *extra_args]
    if manager == "bun":
        return ["bun", "run", script_name, "--", *extra_args]
    raise AdapterUnavailableError(f"Unsupported package manager for tooling rules: {manager}")


def _find_local_node_tool(repo_root: Path, tool_name: str) -> Path | None:
    candidates = (
        repo_root / "node_modules" / ".bin" / tool_name,
        repo_root / "node_modules" / ".bin" / f"{tool_name}.cmd",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _has_eslint_surface(repo_root: Path, package_json: dict[str, object]) -> bool:
    if any((repo_root / candidate).exists() for candidate in _ESLINT_CONFIG_CANDIDATES):
        return True
    return isinstance(package_json.get("eslintConfig"), dict)


def _run_tool_command(repo_root: Path, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )


def _combine_tool_output(completed: subprocess.CompletedProcess[str]) -> str:
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if stdout and stderr:
        return f"{stdout}\n{stderr}"
    return stdout or stderr


def _parse_tsc_findings(
    *,
    rule: RuleDefinition,
    repo_root: Path,
    target_files: Sequence[str],
    mode: object,
    output: str,
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, int, int, str]] = set()

    for raw_line in output.splitlines():
        match = _TSC_DIAGNOSTIC_PATTERN.match(raw_line.strip())
        if match is None:
            continue
        normalized_path = _normalize_tool_path(repo_root, match.group("path"))
        if normalized_path is None or not _should_include_path(mode, target_files, normalized_path):
            continue
        line = int(match.group("line"))
        column = int(match.group("column"))
        code = match.group("code")
        message = match.group("message").strip()
        key = (normalized_path, line, column, code)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                adapter_id="typescript-typecheck",
                language=RepoLanguage.TYPESCRIPT,
                location=FindingLocation(path=normalized_path, line=line, column=column),
                message=f"{code}: {message}",
                metadata={"tool": "tsc", "code": code},
            )
        )

    return tuple(findings)


def _parse_eslint_findings(
    *,
    rule: RuleDefinition,
    repo_root: Path,
    target_files: Sequence[str],
    mode: object,
    output: str,
) -> tuple[NormalizedFinding, ...]:
    results = _extract_eslint_results(output)
    if results is None:
        return ()

    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        file_path = result.get("filePath")
        if not isinstance(file_path, str):
            continue
        normalized_path = _normalize_tool_path(repo_root, file_path)
        if normalized_path is None or not _should_include_path(mode, target_files, normalized_path):
            continue
        for message_entry in result.get("messages", ()):
            if not isinstance(message_entry, dict):
                continue
            raw_message = str(message_entry.get("message", "")).strip()
            if not raw_message:
                continue
            line = int(message_entry.get("line") or 1)
            column = int(message_entry.get("column") or 1)
            severity_level = int(message_entry.get("severity") or 1)
            eslint_rule_id = str(message_entry.get("ruleId") or "")
            key = (normalized_path, line, column, eslint_rule_id)
            if key in seen:
                continue
            seen.add(key)
            rendered_message = (
                f"[{eslint_rule_id}] {raw_message}" if eslint_rule_id else raw_message
            )
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="typescript-eslint",
                    language=RepoLanguage.TYPESCRIPT,
                    location=FindingLocation(path=normalized_path, line=line, column=column),
                    message=rendered_message,
                    severity=(
                        FindingSeverity.ERROR
                        if severity_level >= 2
                        else FindingSeverity.WARNING
                    ),
                    metadata={
                        "tool": "eslint",
                        "eslint_rule_id": eslint_rule_id or "<none>",
                        "source_severity": "error" if severity_level >= 2 else "warning",
                    },
                )
            )

    return tuple(findings)


def _extract_eslint_results(output: str) -> list[object] | None:
    decoder = json.JSONDecoder()
    for index, char in enumerate(output):
        if char != "[":
            continue
        try:
            payload, _ = decoder.raw_decode(output, index)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, list) and _looks_like_eslint_results(payload):
            return payload
    return None


def _looks_like_eslint_results(payload: list[object]) -> bool:
    if not payload:
        return True
    return any(isinstance(entry, dict) and "messages" in entry for entry in payload)


def _normalize_tool_path(repo_root: Path, raw_path: str) -> str | None:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate

    try:
        return candidate.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        normalized_root = repo_root.resolve().as_posix()
        normalized_raw = raw_path.replace("\\", "/")
        if normalized_raw.startswith(normalized_root.rstrip("/") + "/"):
            return normalized_raw[len(normalized_root.rstrip("/")) + 1 :]
    return None


def _should_include_path(mode: object, target_files: Sequence[str], path: str) -> bool:
    if getattr(mode, "value", mode) == "inventory":
        return True
    return path.replace("\\", "/") in {target.replace("\\", "/") for target in target_files}


def _raise_tool_command_error(
    tool_name: str, completed: subprocess.CompletedProcess[str]
) -> None:
    rendered_output = _combine_tool_output(completed).strip()
    message = rendered_output.splitlines()[0] if rendered_output else f"{tool_name} command failed."
    lowered = rendered_output.lower()
    if any(snippet in lowered for snippet in _TOOL_UNAVAILABLE_SNIPPETS):
        raise AdapterUnavailableError(f"{tool_name} unavailable: {message}")
    raise RuntimeError(f"{tool_name} command failed: {message}")


DEFAULT_ADAPTERS = (TypeScriptTypecheckAdapter(), TypeScriptEslintAdapter())
