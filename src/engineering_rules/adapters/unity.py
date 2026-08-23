"""Unity/C# adapters for game-engine engineering rules."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..engine import AdapterContext, ExecutionMode, RulesAdapter
from ..models import FindingLocation, NormalizedFinding, RepoLanguage
from ..registry import RulesRegistry, create_default_registry

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_RUNTIME_UNITY_EDITOR_RULE_ID = "unity.reliability.no-runtime-unityeditor-usage"
_IMGUI_DPI_SCALING_RULE_ID = "unity.ui.no-direct-imgui-dpi-scaling"
_NO_RENDERER_BATCHMODE_RULE_ID = "unity.reliability.no-renderer-creation-in-batchmode"
_NO_DESTROYIMMEDIATE_RESOURCES_RULE_ID = "unity.reliability.no-destroyimmediate-on-resources-assets"
_NO_PER_FRAME_ALLOC_RULE_ID = "unity.performance.no-per-frame-allocation-in-hot-path"
_NO_GRAVITY_STACKING_RULE_ID = "unity.physics.no-gravity-stacking"
_NO_ALLOC_PHYSICS_OVERLAP_RULE_ID = "unity.performance.no-alloc-physics-overlap"
_NO_SINGLETON_BEFORE_INSTANTIATION_RULE_ID = (
    "unity.reliability.no-singleton-access-before-instantiation"
)
_NO_INPUT_ZEROED_BEFORE_LATEUPDATE_RULE_ID = "unity.correctness.no-input-zeroed-before-lateupdate"
_NO_MOVEROTATION_CANCELED_RULE_ID = "unity.physics.no-moverotation-canceled-by-fixedupdate"
_NO_IGNORECOLLISION_WITHOUT_QUERY_RULE_ID = "unity.physics.no-ignorecollision-without-query-guard"
_NO_NETWORK_SINGLETON_AFTER_UI_BOOTSTRAP_RULE_ID = (
    "unity.reliability.no-network-singleton-after-ui-bootstrap"
)
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".vs",
    "Library",
    "Logs",
    "Obj",
    "PackagesCache",
    "Temp",
    "UserSettings",
}
_USING_UNITY_EDITOR_PATTERN = re.compile(
    r"^\s*using\s+(?:static\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?"
    r"UnityEditor(?:\.[A-Za-z_][A-Za-z0-9_.]*)?\s*;"
)
_UNITY_EDITOR_REFERENCE_PATTERN = re.compile(r"\bUnityEditor\.[A-Za-z_][A-Za-z0-9_]*")
_PREPROCESSOR_IF_PATTERN = re.compile(r"^\s*#\s*if\s+(?P<expr>.+?)\s*$")
_PREPROCESSOR_ELIF_PATTERN = re.compile(r"^\s*#\s*elif\s+(?P<expr>.+?)\s*$")
_PREPROCESSOR_ELSE_PATTERN = re.compile(r"^\s*#\s*else\b")
_PREPROCESSOR_ENDIF_PATTERN = re.compile(r"^\s*#\s*endif\b")
_UNITY_EDITOR_SYMBOL_PATTERN = re.compile(r"\bUNITY_EDITOR(?:_[A-Z0-9_]+)?\b")
_NOT_UNITY_EDITOR_SYMBOL_PATTERN = re.compile(
    r"!\s*(?:\(\s*)?UNITY_EDITOR(?:_[A-Z0-9_]+)?\b(?:\s*\))?"
)
_ON_GUI_PATTERN = re.compile(r"\bvoid\s+OnGUI\s*\(")
_DIRECT_DPI_SCALING_PATTERN = re.compile(r"\bScreen\.dpi\s*/\s*160(?:f|F)?\b")
_RENDERER_CREATION_PATTERN = re.compile(
    r"\bnew\s+(TrailRenderer|LineRenderer|ParticleSystem)\b|\bAddComponent\s*<\s*(TrailRenderer|LineRenderer|ParticleSystem)\s*>"
)
_BATCHMODE_GUARD_PATTERN = re.compile(r"\bApplication\.isBatchMode\b")
_DESTROYIMMEDIATE_PATTERN = re.compile(r"\bDestroyImmediate\s*\(")
_RESOURCES_LOAD_PATTERN = re.compile(r"\bResources\.Load\b")
_PER_FRAME_ALLOC_PATTERN = re.compile(r"\bnew\s+(Vector3\[[^\]]*\]|List<[^>]+>|Dictionary<[^>]+>)")
_UPDATE_FIXEDUPDATE_PATTERN = re.compile(r"\bvoid\s+(Update|FixedUpdate)\s*\(")
_UPDATE_PATTERN = re.compile(r"\bvoid\s+Update\s*\(")
_LATEUPDATE_PATTERN = re.compile(r"\bvoid\s+LateUpdate\s*\(")
_AWAKE_START_PATTERN = re.compile(r"\bvoid\s+(Awake|Start)\s*\(")
_USE_GRAVITY_PATTERN = re.compile(r"\buseGravity\s*=\s*true\b")
_MOVE_POSITION_PATTERN = re.compile(r"\bMovePosition\b")
_VELOCITY_PATTERN = re.compile(r"\bvelocity\b")
_PHYSICS_OVERLAP_PATTERN = re.compile(r"\bPhysics\.Overlap(Sphere|Capsule)\s*\(")
_SINGLETON_INSTANCE_PATTERN = re.compile(r"\b\w+\.Instance\b")
_INPUT_ZERO_PATTERN = re.compile(r"=\s*Vector2\.zero\b")
_MOVE_ROTATION_PATTERN = re.compile(r"\bMoveRotation\s*\(")
_ANGULAR_VELOCITY_ZERO_PATTERN = re.compile(r"\bangularVelocity\s*=\s*Vector3\.zero\b")
_IGNORE_COLLISION_PATTERN = re.compile(r"\bPhysics\.IgnoreCollision\s*\(")
_QUERY_PATTERN = re.compile(r"\b(CapsuleCast|OverlapSphere)\b")
_UI_SCREEN_ADD_COMPONENT_PATTERN = re.compile(r"AddComponent\s*<\s*\w*Screen\s*>")
_NETWORK_SINGLETON_ADD_COMPONENT_PATTERN = re.compile(
    r"AddComponent\s*<\s*(?:NetworkClient|AuthManager|\w*Manager)\s*>"
)
_VERBATIM_INTERPOLATED_STRING_PREFIXES = ('$@"', '@$"')


class UnityAdapter(RulesAdapter):
    adapter_key = "unity"

    def __init__(self, registry: RulesRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> tuple[NormalizedFinding, ...]:
        findings: list[NormalizedFinding] = []
        if _RUNTIME_UNITY_EDITOR_RULE_ID in rule_ids:
            findings.extend(self._run_runtime_unityeditor_rule(context))
        if _IMGUI_DPI_SCALING_RULE_ID in rule_ids:
            findings.extend(self._run_imgui_dpi_scaling_rule(context))
        if _NO_RENDERER_BATCHMODE_RULE_ID in rule_ids:
            findings.extend(self._run_no_renderer_batchmode_rule(context))
        if _NO_DESTROYIMMEDIATE_RESOURCES_RULE_ID in rule_ids:
            findings.extend(self._run_no_destroyimmediate_resources_rule(context))
        if _NO_PER_FRAME_ALLOC_RULE_ID in rule_ids:
            findings.extend(self._run_no_per_frame_alloc_rule(context))
        if _NO_GRAVITY_STACKING_RULE_ID in rule_ids:
            findings.extend(self._run_no_gravity_stacking_rule(context))
        if _NO_ALLOC_PHYSICS_OVERLAP_RULE_ID in rule_ids:
            findings.extend(self._run_no_alloc_physics_overlap_rule(context))
        if _NO_SINGLETON_BEFORE_INSTANTIATION_RULE_ID in rule_ids:
            findings.extend(self._run_no_singleton_before_instantiation_rule(context))
        if _NO_INPUT_ZEROED_BEFORE_LATEUPDATE_RULE_ID in rule_ids:
            findings.extend(self._run_no_input_zeroed_before_lateupdate_rule(context))
        if _NO_MOVEROTATION_CANCELED_RULE_ID in rule_ids:
            findings.extend(self._run_no_moverotation_canceled_rule(context))
        if _NO_IGNORECOLLISION_WITHOUT_QUERY_RULE_ID in rule_ids:
            findings.extend(self._run_no_ignorecollision_without_query_rule(context))
        if _NO_NETWORK_SINGLETON_AFTER_UI_BOOTSTRAP_RULE_ID in rule_ids:
            findings.extend(self._run_no_network_singleton_after_ui_bootstrap_rule(context))
        return tuple(findings)

    def _run_runtime_unityeditor_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_RUNTIME_UNITY_EDITOR_RULE_ID)
        if rule is None:
            return ()

        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue

            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            findings.extend(
                _scan_runtime_unityeditor_usage(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_imgui_dpi_scaling_rule(self, context: AdapterContext) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_IMGUI_DPI_SCALING_RULE_ID)
        if rule is None:
            return ()

        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue

            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            findings.extend(
                _scan_direct_imgui_dpi_scaling(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_renderer_batchmode_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_RENDERER_BATCHMODE_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_renderer_creation_in_batchmode(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_destroyimmediate_resources_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_DESTROYIMMEDIATE_RESOURCES_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_destroyimmediate_on_resources(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_per_frame_alloc_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_PER_FRAME_ALLOC_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_per_frame_allocation(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_gravity_stacking_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_GRAVITY_STACKING_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_gravity_stacking(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_alloc_physics_overlap_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_ALLOC_PHYSICS_OVERLAP_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_alloc_physics_overlap(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_singleton_before_instantiation_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_SINGLETON_BEFORE_INSTANTIATION_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_singleton_access_before_instantiation(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_input_zeroed_before_lateupdate_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_INPUT_ZEROED_BEFORE_LATEUPDATE_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_input_zeroed_before_lateupdate(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_moverotation_canceled_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_MOVEROTATION_CANCELED_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_moverotation_canceled(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_ignorecollision_without_query_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_IGNORECOLLISION_WITHOUT_QUERY_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_ignorecollision_without_query_guard(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)

    def _run_no_network_singleton_after_ui_bootstrap_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_NO_NETWORK_SINGLETON_AFTER_UI_BOOTSTRAP_RULE_ID)
        if rule is None:
            return ()
        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            if not _is_runtime_csharp_source(relative_path, repo_root=context.repo_root):
                continue
            absolute_path = context.repo_root / relative_path
            try:
                text = absolute_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(
                _scan_network_singleton_after_ui_bootstrap(
                    relative_path=relative_path,
                    text=text,
                    rule=rule,
                )
            )
        return tuple(findings)


def _candidate_files(context: AdapterContext) -> Iterable[str]:
    if context.mode is ExecutionMode.DIFF:
        seen: set[str] = set()
        for path in context.target_files:
            normalized = Path(path).as_posix()
            if normalized in seen or _should_skip_path(normalized):
                continue
            absolute_path = context.repo_root / normalized
            if not absolute_path.is_file():
                continue
            seen.add(normalized)
            yield normalized
        return

    for path in sorted(context.repo_root.rglob("*.cs")):
        relative_path = path.relative_to(context.repo_root).as_posix()
        if _should_skip_path(relative_path):
            continue
        yield relative_path


def _should_skip_path(relative_path: str) -> bool:
    return any(part in _SKIP_DIRS for part in Path(relative_path).parts)


def _is_runtime_csharp_source(relative_path: str, *, repo_root: Path) -> bool:
    normalized = Path(relative_path)
    if normalized.suffix.lower() != ".cs":
        return False
    if not normalized.parts:
        return False
    if normalized.parts[0] not in {"Assets", "Packages"}:
        return False
    if any(part.lower() == "editor" for part in normalized.parts):
        return False
    return not _is_editor_only_assembly(relative_path, repo_root=repo_root)


def _is_editor_only_assembly(relative_path: str, *, repo_root: Path) -> bool:
    asmdef_path = _nearest_asmdef_path(relative_path, repo_root=repo_root)
    if asmdef_path is None:
        return False
    try:
        payload = json.loads(asmdef_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    include_platforms = payload.get("includePlatforms", [])
    if not isinstance(include_platforms, list) or not include_platforms:
        return False
    normalized_platforms = {
        str(platform).strip().lower() for platform in include_platforms if str(platform).strip()
    }
    return normalized_platforms == {"editor"}


def _nearest_asmdef_path(relative_path: str, *, repo_root: Path) -> Path | None:
    path = Path(relative_path)
    for directory in path.parents:
        search_root = repo_root if str(directory) == "." else repo_root / directory
        candidates = sorted(search_root.glob("*.asmdef"))
        if candidates:
            return candidates[0]
    return None


def _lines_inside_method(text: str, method_pattern: re.Pattern) -> set[int]:
    """Return 1-based line numbers that are inside a method matching ``method_pattern``."""
    result: set[int] = set()
    brace_depth = 0
    in_method = False
    method_depth = -1
    awaiting_open = False
    in_block_comment = False
    string_state: str | None = None

    for i, line in enumerate(text.splitlines(), start=1):
        sanitized, in_block_comment, string_state = _strip_noncode_segments(
            line,
            in_block_comment=in_block_comment,
            string_state=string_state,
        )
        open_b = sanitized.count("{")
        close_b = sanitized.count("}")

        if awaiting_open:
            if open_b > 0:
                in_method = True
                method_depth = brace_depth
                result.add(i)
                brace_depth += open_b - close_b
                if brace_depth <= method_depth:
                    in_method = False
                    method_depth = -1
                    awaiting_open = False
                continue
            elif sanitized.strip() and not sanitized.strip().startswith("["):
                awaiting_open = False

        if in_method:
            result.add(i)
            brace_depth += open_b - close_b
            if brace_depth <= method_depth:
                in_method = False
                method_depth = -1
                awaiting_open = False
        else:
            if method_pattern.search(sanitized):
                if open_b > 0:
                    in_method = True
                    method_depth = brace_depth
                    result.add(i)
                elif "=>" not in sanitized and ";" not in sanitized:
                    awaiting_open = True
            brace_depth += open_b - close_b

    return result


def _scan_runtime_unityeditor_usage(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    seen: set[tuple[int, str]] = set()
    editor_guard_stack: list[bool | None] = []
    in_block_comment = False
    string_state: str | None = None

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not in_block_comment and string_state is None:
            if match := _PREPROCESSOR_IF_PATTERN.match(line):
                editor_guard_stack.append(_branch_editor_only_state(match.group("expr")))
                continue
            if match := _PREPROCESSOR_ELIF_PATTERN.match(line):
                if editor_guard_stack:
                    editor_guard_stack[-1] = _branch_editor_only_state(match.group("expr"))
                continue
            if _PREPROCESSOR_ELSE_PATTERN.match(line):
                if editor_guard_stack:
                    current_state = editor_guard_stack[-1]
                    editor_guard_stack[-1] = None if current_state is None else not current_state
                continue
            if _PREPROCESSOR_ENDIF_PATTERN.match(line):
                if editor_guard_stack:
                    editor_guard_stack.pop()
                continue

        sanitized_line, in_block_comment, string_state = _strip_noncode_segments(
            line,
            in_block_comment=in_block_comment,
            string_state=string_state,
        )
        if any(state is True for state in editor_guard_stack):
            continue

        matched_pattern = _match_unityeditor_usage(sanitized_line)
        if matched_pattern is None or (line_number, matched_pattern) in seen:
            continue
        seen.add((line_number, matched_pattern))
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                adapter_id="unity",
                language=RepoLanguage.UNITY,
                location=FindingLocation(path=relative_path, line=line_number),
                message=(
                    "UnityEditor usage in runtime C# code should move into Assets/Editor or an "
                    "editor-only asmdef so player builds stay clean."
                ),
                metadata={"matched_pattern": matched_pattern},
            )
        )

    return tuple(findings)


def _scan_direct_imgui_dpi_scaling(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    editor_guard_stack: list[bool | None] = []
    in_block_comment = False
    string_state: str | None = None
    brace_depth = 0
    imgui_scope_depth: int | None = None
    awaiting_imgui_open = False

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not in_block_comment and string_state is None:
            if match := _PREPROCESSOR_IF_PATTERN.match(line):
                editor_guard_stack.append(_branch_editor_only_state(match.group("expr")))
                continue
            if match := _PREPROCESSOR_ELIF_PATTERN.match(line):
                if editor_guard_stack:
                    editor_guard_stack[-1] = _branch_editor_only_state(match.group("expr"))
                continue
            if _PREPROCESSOR_ELSE_PATTERN.match(line):
                if editor_guard_stack:
                    current_state = editor_guard_stack[-1]
                    editor_guard_stack[-1] = None if current_state is None else not current_state
                continue
            if _PREPROCESSOR_ENDIF_PATTERN.match(line):
                if editor_guard_stack:
                    editor_guard_stack.pop()
                continue

        sanitized_line, in_block_comment, string_state = _strip_noncode_segments(
            line,
            in_block_comment=in_block_comment,
            string_state=string_state,
        )

        open_braces = sanitized_line.count("{")
        close_braces = sanitized_line.count("}")
        editor_only_branch = any(state is True for state in editor_guard_stack)
        if imgui_scope_depth is None:
            if awaiting_imgui_open:
                stripped_line = sanitized_line.strip()
                if open_braces > 0:
                    if not editor_only_branch:
                        imgui_scope_depth = brace_depth + 1
                    awaiting_imgui_open = False
                elif "=>" in sanitized_line or (
                    stripped_line
                    and not _ON_GUI_PATTERN.search(sanitized_line)
                    and not stripped_line.startswith("[")
                ):
                    awaiting_imgui_open = False

            if editor_only_branch:
                brace_depth += open_braces - close_braces
                if imgui_scope_depth is not None and brace_depth < imgui_scope_depth:
                    imgui_scope_depth = None
                continue

            if _ON_GUI_PATTERN.search(sanitized_line):
                if open_braces > 0:
                    imgui_scope_depth = brace_depth + 1
                elif ";" not in sanitized_line and "=>" not in sanitized_line:
                    awaiting_imgui_open = True
        elif editor_only_branch:
            brace_depth += open_braces - close_braces
            if imgui_scope_depth is not None and brace_depth < imgui_scope_depth:
                imgui_scope_depth = None
            continue

        inside_imgui_scope = imgui_scope_depth is not None
        if not inside_imgui_scope or not _DIRECT_DPI_SCALING_PATTERN.search(sanitized_line):
            brace_depth += open_braces - close_braces
            if imgui_scope_depth is not None and brace_depth < imgui_scope_depth:
                imgui_scope_depth = None
            continue

        findings.append(
            NormalizedFinding.from_rule(
                rule,
                adapter_id="unity",
                language=RepoLanguage.UNITY,
                location=FindingLocation(path=relative_path, line=line_number),
                message=(
                    "Direct `Screen.dpi / 160f` scaling in IMGUI runtime code is risky on dense "
                    "phones. Use a capped UI-scale helper instead of raw DPI multiplication."
                ),
                metadata={"matched_pattern": "screen_dpi_over_160"},
            )
        )

        brace_depth += open_braces - close_braces
        if imgui_scope_depth is not None and brace_depth < imgui_scope_depth:
            imgui_scope_depth = None

    return tuple(findings)


def _scan_renderer_creation_in_batchmode(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if not _RENDERER_CREATION_PATTERN.search(sanitized):
            continue
        if _BATCHMODE_GUARD_PATTERN.search(sanitized):
            continue
        if line_number in seen:
            continue
        seen.add(line_number)
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                adapter_id="unity",
                language=RepoLanguage.UNITY,
                location=FindingLocation(path=relative_path, line=line_number),
                message=(
                    "Creating TrailRenderer, LineRenderer, or ParticleSystem in batchmode can "
                    "crash headless builds. Guard with Application.isBatchMode."
                ),
                metadata={"matched_pattern": "renderer_creation_without_batchmode_guard"},
            )
        )
    return tuple(findings)


def _scan_destroyimmediate_on_resources(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    if not _RESOURCES_LOAD_PATTERN.search(text):
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _DESTROYIMMEDIATE_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "DestroyImmediate on Resources-loaded assets leaks the resource cache. "
                        "Clear cache references instead."
                    ),
                    metadata={"matched_pattern": "destroyimmediate_on_resources_asset"},
                )
            )
    return tuple(findings)


def _scan_per_frame_allocation(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    hot_lines = _lines_inside_method(text, _UPDATE_FIXEDUPDATE_PATTERN)
    if not hot_lines:
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line_number not in hot_lines:
            continue
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _PER_FRAME_ALLOC_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "Allocating arrays, List, or Dictionary in Update/FixedUpdate causes GC "
                        "pressure. Use pre-allocated buffers or object pooling."
                    ),
                    metadata={"matched_pattern": "per_frame_allocation_in_hot_path"},
                )
            )
    return tuple(findings)


def _scan_gravity_stacking(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    if not (_MOVE_POSITION_PATTERN.search(text) or _VELOCITY_PATTERN.search(text)):
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _USE_GRAVITY_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "Rigidbody.useGravity = true conflicts with custom gravity applied via "
                        "MovePosition or velocity. Disable built-in gravity when using custom."
                    ),
                    metadata={"matched_pattern": "useGravity_true_with_custom_gravity"},
                )
            )
    return tuple(findings)


def _scan_alloc_physics_overlap(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _PHYSICS_OVERLAP_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "Physics.OverlapSphere/OverlapCapsule allocates a new array every call. "
                        "Use OverlapSphereNonAlloc or OverlapCapsuleNonAlloc with a reusable buffer."
                    ),
                    metadata={"matched_pattern": "alloc_physics_overlap"},
                )
            )
    return tuple(findings)


def _scan_singleton_access_before_instantiation(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    hot_lines = _lines_inside_method(text, _AWAKE_START_PATTERN)
    if not hot_lines:
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line_number not in hot_lines:
            continue
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _SINGLETON_INSTANCE_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "Accessing a singleton Instance in Awake/Start before it is instantiated "
                        "can cause null references. Ensure the singleton initializes first."
                    ),
                    metadata={"matched_pattern": "singleton_access_before_instantiation"},
                )
            )
    return tuple(findings)


def _scan_input_zeroed_before_lateupdate(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    if not _LATEUPDATE_PATTERN.search(text):
        return ()
    hot_lines = _lines_inside_method(text, _UPDATE_PATTERN)
    if not hot_lines:
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line_number not in hot_lines:
            continue
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _INPUT_ZERO_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "Zeroing input in Update before LateUpdate can consume it prevents "
                        "LateUpdate readers from seeing the value. Cache input before clearing."
                    ),
                    metadata={"matched_pattern": "input_zeroed_before_lateupdate"},
                )
            )
    return tuple(findings)


def _scan_moverotation_canceled(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    if not _ANGULAR_VELOCITY_ZERO_PATTERN.search(text):
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _MOVE_ROTATION_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "MoveRotation in LateUpdate can be canceled by FixedUpdate zeroing "
                        "angularVelocity. Use direct rotation assignment or preserve angularVelocity."
                    ),
                    metadata={"matched_pattern": "moverotation_canceled_by_fixedupdate"},
                )
            )
    return tuple(findings)


def _scan_ignorecollision_without_query_guard(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    if not _QUERY_PATTERN.search(text):
        return ()
    findings: list[NormalizedFinding] = []
    seen: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if _IGNORE_COLLISION_PATTERN.search(sanitized) and line_number not in seen:
            seen.add(line_number)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="unity",
                    language=RepoLanguage.UNITY,
                    location=FindingLocation(path=relative_path, line=line_number),
                    message=(
                        "Physics.IgnoreCollision without filtering ignored colliders from manual "
                        "CapsuleCast/OverlapSphere queries can cause missed collisions."
                    ),
                    metadata={"matched_pattern": "ignorecollision_without_query_guard"},
                )
            )
    return tuple(findings)


def _scan_network_singleton_after_ui_bootstrap(
    *,
    relative_path: str,
    text: str,
    rule: object,
) -> tuple[NormalizedFinding, ...]:
    bootstrap_lines = _lines_inside_method(text, _AWAKE_START_PATTERN)
    if not bootstrap_lines:
        return ()
    ui_screen_line: int | None = None
    network_singleton_line: int | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line_number not in bootstrap_lines:
            continue
        sanitized, _, _ = _strip_noncode_segments(line, in_block_comment=False, string_state=None)
        if ui_screen_line is None and _UI_SCREEN_ADD_COMPONENT_PATTERN.search(sanitized):
            ui_screen_line = line_number
        if network_singleton_line is None and _NETWORK_SINGLETON_ADD_COMPONENT_PATTERN.search(
            sanitized
        ):
            network_singleton_line = line_number
    if ui_screen_line is None or network_singleton_line is None:
        return ()
    if ui_screen_line >= network_singleton_line:
        return ()
    return (
        NormalizedFinding.from_rule(
            rule,
            adapter_id="unity",
            language=RepoLanguage.UNITY,
            location=FindingLocation(path=relative_path, line=ui_screen_line),
            message=(
                "Bootstrap Awake/Start adds UI screen components before networking singletons; "
                "initialize NetworkClient/AuthManager first."
            ),
            metadata={"matched_pattern": "network-singleton-after-ui-bootstrap"},
        ),
    )


def _match_unityeditor_usage(line: str) -> str | None:
    if not line.strip():
        return None
    if _USING_UNITY_EDITOR_PATTERN.search(line):
        return "using_unityeditor"
    if _UNITY_EDITOR_REFERENCE_PATTERN.search(line):
        return "unityeditor_namespace_reference"
    return None


def _strip_noncode_segments(
    line: str,
    *,
    in_block_comment: bool,
    string_state: str | None,
) -> tuple[str, bool, str | None]:
    sanitized: list[str] = []
    index = 0
    while index < len(line):
        if in_block_comment:
            end = line.find("*/", index)
            if end == -1:
                return "".join(sanitized), True, string_state
            index = end + 2
            in_block_comment = False
            continue

        if string_state == "double":
            if line[index] == "\\" and index + 1 < len(line):
                index += 2
                continue
            if line[index] == '"':
                string_state = None
            index += 1
            continue

        if string_state == "single":
            if line[index] == "\\" and index + 1 < len(line):
                index += 2
                continue
            if line[index] == "'":
                string_state = None
            index += 1
            continue

        if string_state == "verbatim_double":
            if line.startswith('""', index):
                index += 2
                continue
            if line[index] == '"':
                string_state = None
                index += 1
                continue
            index += 1
            continue

        if line.startswith("//", index):
            break
        if line.startswith("/*", index):
            in_block_comment = True
            index += 2
            continue
        if any(line.startswith(prefix, index) for prefix in _VERBATIM_INTERPOLATED_STRING_PREFIXES):
            string_state = "verbatim_double"
            index += 3
            continue
        if line.startswith('@"', index):
            string_state = "verbatim_double"
            index += 2
            continue
        if line.startswith('$"', index):
            string_state = "double"
            index += 2
            continue
        if line[index] == '"':
            string_state = "double"
            index += 1
            continue
        if line[index] == "'":
            string_state = "single"
            index += 1
            continue

        sanitized.append(line[index])
        index += 1

    return "".join(sanitized), in_block_comment, string_state


def _branch_editor_only_state(expression: str) -> bool | None:
    branches = [branch.strip() for branch in expression.upper().split("||")]
    if not branches:
        return None
    if all(
        _UNITY_EDITOR_SYMBOL_PATTERN.search(branch)
        and not _NOT_UNITY_EDITOR_SYMBOL_PATTERN.search(branch)
        for branch in branches
    ):
        return True
    if all(
        _NOT_UNITY_EDITOR_SYMBOL_PATTERN.search(branch)
        and not _UNITY_EDITOR_SYMBOL_PATTERN.search(
            _NOT_UNITY_EDITOR_SYMBOL_PATTERN.sub("", branch)
        )
        for branch in branches
    ):
        return False
    return None


DEFAULT_ADAPTERS = (UnityAdapter(),)
