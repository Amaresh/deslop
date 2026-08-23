"""Go adapter for backend config, secret, and SQL safety rules."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..engine import AdapterContext, ExecutionMode, RulesAdapter
from ..models import FindingLocation, NormalizedFinding, RepoLanguage
from ..registry import RulesRegistry, create_default_registry
from .shared import (
    _is_masked_sensitive_logging_name as _shared_is_masked_sensitive_logging_name,
)
from .shared import (
    _is_strong_secret_name as _shared_is_strong_secret_name,
)
from .shared import (
    _looks_like_dependency_boundary_name as _shared_looks_like_dependency_boundary_name,
)
from .shared import (
    _looks_like_placeholder as _shared_looks_like_placeholder,
)
from .shared import (
    _sensitive_logging_name_kind as _shared_sensitive_logging_name_kind,
)
from .shared import (
    _split_identifier_tokens as _shared_split_identifier_tokens,
)

_HANDLER_ENV_RULE_ID = "go.config.no-handler-env-read"
_HANDLER_OUTBOUND_HTTP_RULE_ID = "go.architecture.no-handler-direct-outbound-http"
_HANDLER_CONCRETE_DEPENDENCY_RULE_ID = "go.architecture.no-handler-concrete-dependency"
_HANDLER_PERSISTENCE_BOUNDARY_RULE_ID = "go.architecture.no-handler-direct-sql-execution"
_HANDLER_SERVICE_LOCATOR_RULE_ID = "go.architecture.no-handler-service-locator-access"
_HANDLER_ASYNC_RULE_ID = "go.architecture.no-handler-detached-goroutine"
_HANDLER_CONTEXT_RULE_ID = "go.architecture.no-handler-rooted-background-context"
_HANDLER_OBSERVABILITY_RULE_ID = "go.architecture.no-handler-log-only-background-outcome"
_HANDLER_RESPONSE_LIFECYCLE_RULE_ID = "go.architecture.no-handler-terminal-response-fallthrough"
_SERVICE_LAYER_ASYNC_RULE_ID = "go.architecture.no-service-layer-detached-goroutine"
_SERVICE_LAYER_CONTEXT_RULE_ID = "go.architecture.no-service-layer-rooted-background-context"
_SERVICE_LAYER_OBSERVABILITY_RULE_ID = (
    "go.architecture.no-service-layer-log-only-background-outcome"
)
_SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID = (
    "go.architecture.no-service-layer-outbound-client-construction"
)
_SERVICE_LAYER_SERVICE_LOCATOR_RULE_ID = "go.architecture.no-service-layer-service-locator-access"
_SECRET_FALLBACK_RULE_ID = "go.security.no-secret-fallback-literal"
_DYNAMIC_SQL_RULE_ID = "go.security.no-dynamic-sql-execution"
_EXTERNAL_LITERAL_RULE_ID = "go.reliability.no-hardcoded-external-literals"
_ERROR_RESPONSE_RULE_ID = "go.security.no-handler-error-detail-response"
_STRICT_JSON_BODY_RULE_ID = "go.reliability.no-handler-request-json-decode-without-strict-decoder"
_CREDENTIAL_LOGGING_RULE_ID = "go.security.no-raw-credential-logging"
_PII_LOGGING_RULE_ID = "go.security.no-raw-pii-logging"
_VECTOR_MAGNITUDE_RULE_ID = "go.correctness.no-squared-vector-magnitude-without-sqrt"
_HARD_CODED_SQL_SCHEMA_RULE_ID = (
    "go.reliability.no-hardcoded-sql-schema-reference-without-migration-check"
)
_JSON_NUMERIC_FIELD_RULE_ID = "go.reliability.no-json-numeric-field-without-flexible-decoder"
_PLAINTEXT_HTTP_ERROR_RULE_ID = "go.security.no-plaintext-http-error-for-unconfigured-service"
_AUTHORITATIVE_VALIDATION_RULE_ID = "go.security.authoritative-server-must-validate-client-input"
_OAUTH_CALLBACK_STATE_RULE_ID = "go.security.no-oauth-callback-without-csrf-state"
_IN_MEMORY_STORE_RULE_ID = "go.reliability.no-in-memory-store-without-expiry-pruning"
_UNVALIDATED_ENUMERATED_INPUT_RULE_ID = "go.security.no-unvalidated-enumerated-input"
_IMPLICIT_CROSS_MODULE_SESSION_RULE_ID = "go.architecture.no-implicit-cross-module-session-fields"
_SKIP_DIRECTORIES = frozenset({".git", "bin", "build", "dist", "node_modules", "tmp", "vendor"})
_ASYNC_HANDLER_PATH_MARKERS = frozenset({"handler", "handlers", "websocket"})
_HANDLER_PATH_MARKERS = frozenset({"handler", "handlers"})
_SERVICE_LAYER_PATH_MARKERS = frozenset(
    {
        "consumer",
        "consumers",
        "notification",
        "notifications",
        "orchestrator",
        "proxy",
        "scheduler",
        "schedulers",
        "service",
        "services",
        "worker",
        "workers",
        "workflow",
        "workflows",
    }
)
_SERVICE_LAYER_EXCLUDED_MARKERS = frozenset(
    {"client", "clients", "cmd", "config", "configs", "factory", "factories", "handler", "main"}
)
_GO_SERVICE_LOCATOR_HOLDER_MARKERS = frozenset(
    {"client", "manager", "pool", "provider", "registry", "singleton", "store"}
)
_GO_GOROUTINE_LIFECYCLE_MARKERS = frozenset({"loop", "pump"})
_ENV_READ_PATTERN = re.compile(r"\bos\.(?P<func>Getenv|LookupEnv)\s*\(")
_GO_GOROUTINE_PATTERN = re.compile(
    r"\bgo\s+(?P<access>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_GO_ANONYMOUS_GOROUTINE_PATTERN = re.compile(r"\bgo\s+func\s*\(")
_GO_TERMINAL_RESPONSE_CALL_PATTERN = re.compile(
    r"\b(?P<access>http\.Error|jsonError|writeError)\s*\("
)
_GO_HTTP_ERROR_RESPONSE_PATTERN = re.compile(r"\b(?P<access>http\.Error)\s*\(")
_GO_BARE_REQUEST_JSON_DECODE_PATTERN = re.compile(
    r"\bjson\.NewDecoder\s*\(\s*(?P<request>[A-Za-z_][A-Za-z0-9_]*)\.Body\s*\)\.\s*Decode\s*\("
)
_GO_JSON_DECODER_ASSIGNMENT_PATTERN = re.compile(
    r"(?:"
    r"\bvar\s+(?P<var_name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"|(?P<assign_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*"
    r")json\.NewDecoder\s*\(\s*(?P<request>[A-Za-z_][A-Za-z0-9_]*)\.Body\s*\)"
)
_GO_JSON_DECODER_STRICT_CALL_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\.\s*DisallowUnknownFields\s*\("
)
_GO_JSON_DECODER_DECODE_CALL_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\.\s*Decode\s*\("
)
_GO_ROOTED_CONTEXT_PATTERN = re.compile(
    r"(?P<access>"
    r"context\.(?:Background|TODO)\s*\(\)"
    r"|context\.(?:WithCancel|WithDeadline|WithTimeout|WithValue)\s*\(\s*context\.(?:Background|TODO)\s*\(\)"
    r")"
)
_GO_BACKGROUND_SURFACE_PATTERN = re.compile(
    r"\b(?:"
    r"metrics?|counter|gauge|histogram|audit|incident|capture"
    r"|record(?:Failure|Error|Outcome|Result|Status)"
    r"|save(?:Failure|Error|Outcome|Result|Status)"
    r"|persist(?:Failure|Error|Outcome|Result|Status)"
    r"|update(?:Failure|Error|Outcome|Result|Status)"
    r"|emit(?:Metric|Event)|publish(?:Metric|Event)"
    r")\b",
    re.IGNORECASE,
)
_HANDLER_OUTBOUND_HTTP_PATTERN = re.compile(
    r"\bhttp\.(?P<access>NewRequestWithContext|NewRequest|Get|Post|Head|PostForm|DefaultClient)\b"
)
_HANDLER_HTTP_CLIENT_PATTERN = re.compile(r"(?:&\s*http\.Client|(?<![\w*])http\.Client)\s*\{")
_HANDLER_CONCRETE_DEPENDENCY_PATTERN = re.compile(
    r"(?P<access>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?New(?:[A-Z][A-Za-z0-9_]*)?(?:Client|Service|Repository|"
    r"Gateway|Sender|Notifier|Publisher|Store)"
    r")\s*\("
)
_GO_HANDLER_PERSISTENCE_CALL_PATTERN = re.compile(
    r"\b(?P<access>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:db|tx)\."
    r"(?:QueryContext|QueryRowContext|QueryRow|Query|ExecContext|Exec|BeginTx)"
    r")\s*\("
)
_SERVICE_LAYER_OUTBOUND_CLIENT_PATTERN = re.compile(
    r"(?P<access>"
    r"http\.DefaultClient\b"
    r"|(?:&\s*http\.Client|(?<![\w*])http\.Client)(?=\s*\{)"
    r"|(?:[A-Za-z_][A-Za-z0-9_]*\.)?New(?:[A-Z][A-Za-z0-9_]*)?(?:Client|Gateway|Sender|Notifier|Publisher)(?=\s*\()"
    r")"
)
_GO_SERVICE_LOCATOR_CALL_PATTERN = re.compile(
    r"\b(?P<access>"
    r"(?:Get|Default)[A-Z][A-Za-z0-9_]*(?:Registry|Store|Client|Provider|Manager|Pool|Singleton|Instance)"
    r"|[A-Za-z_][A-Za-z0-9_]*GetInstance"
    r")\s*\("
)
_GO_FUNCTION_DECL_PATTERN = re.compile(
    r"\bfunc\s*(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_GO_HANDLER_FUNC_LITERAL_PATTERN = re.compile(r"\bfunc\s*\(")
_ENV_DEFAULT_PATTERN = re.compile(
    r'\b(?P<func>[A-Za-z_][A-Za-z0-9_]*)\(\s*"(?P<key>[^"]+)"\s*,\s*"(?P<default>[^"\n]*)"\s*,?\s*\)'
)
_SQL_KEYWORD_PATTERN = re.compile(
    r"\b("
    r"select|insert|update|delete|with|create|drop|alter|where|from|into|join|values|set|"
    r"and|or|order|limit|offset|group|having|union"
    r")\b",
    re.IGNORECASE,
)
_SQL_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>:=|\+=|=(?!=))\s*"
)
_SQL_EXECUTION_PATTERN = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\."
    r"(?P<method>QueryContext|QueryRowContext|QueryRow|Query|ExecContext|Exec|Raw)\s*\("
)
_RISKY_GO_PLACEHOLDER_PATTERN = re.compile(
    r"%(?:\[[0-9]+\])?[+#0\- ]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[svqTxXp]"
)
_EXTERNAL_URL_PATTERN = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s]*)?$")
_EXTERNAL_DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+\.[a-z]{2,}$")
_EXTERNAL_IDENTIFIER_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")
_URL_CONTEXT_MARKERS = frozenset({"url", "uri", "host", "domain", "endpoint"})
_GO_LOG_CALL_PATTERN = re.compile(
    r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_.]*)\."
    r"(?P<method>Debugf|Errorf|Fatalf|Fatal|Infof|Panicf|Panic|Println|Printf|Print|Warnf)\s*\("
)
_RUNTIME_EXCLUDED_PATH_MARKERS = frozenset(
    {
        "benchmark",
        "benchmarks",
        "eval",
        "evals",
        "script",
        "scripts",
        "test",
        "tests",
        "tool",
        "tools",
    }
)
_GO_SQUARED_SUM_PATTERN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[A-Za-z_][A-Za-z0-9_]*"
)
_GO_SQL_TABLE_REFERENCE_PATTERN = re.compile(
    r"\b(FROM|INTO|JOIN|UPDATE|TABLE)\s+([A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_GO_JSON_INT_FIELD_PATTERN = re.compile(
    r'\b[A-Za-z_][A-Za-z0-9_]*\s+(?:int(?:64|32|16|8)?|float(?:64|32)?)\s+`json:"([^"]*)"`'
)
_GO_STRUCT_DECL_PATTERN = re.compile(r"\btype\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+struct\s*\{")
_GO_OAUTH_CALLBACK_PATH_PATTERN = re.compile(r'"(?:/[^"]*)?(?:oauth|auth)/callback(?:/[^"]*)?"')
_GO_OAUTH_CALLBACK_FUNC_PATTERN = re.compile(
    r"\b(?:OAuthCallback|AuthCallback|HandleOAuthCallback|HandleAuthCallback)\b"
)
_GO_STATE_VERIFICATION_PATTERN = re.compile(r"\bstate\b")
_GO_REQUEST_STRING_READ_PATTERN = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*r\.(?:FormValue|PostFormValue|URL\.Query\(\)\.Get|Header\.Get)\s*\("
)
_GO_MAP_INTERFACE_PATTERN = re.compile(
    r"\b(?:var\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+map\[string\]interface\{\}"
)
_GO_MAP_INTERFACE_MAKE_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*make\s*\(\s*map\[string\]interface\{\}\s*\)"
)
_GO_MAP_INTERFACE_PARAM_PATTERN = re.compile(
    r"\bfunc\s*[^(]*\([^)]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+map\[string\]interface\{\}"
)
_GO_MAP_STORE_PATTERN = re.compile(
    r"\b(?:var\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+map\[[^\]]+\](?:\*)?[A-Za-z_][A-Za-z0-9_]*"
)
_GO_MAP_STORE_MAKE_PATTERN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*make\s*\(\s*map\[[^\]]+\]\s*(?:\*)?\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"
)
_GO_MAP_STORE_PARAM_PATTERN = re.compile(
    r"\bfunc\s*[^(]*\([^)]*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+map\[[^\]]+\](?:\*)?[A-Za-z_][A-Za-z0-9_]*"
)
_GO_STORE_NAME_PATTERN = re.compile(
    r"(?:session|state|cache|store|pool|registry|holder|token|connection|client|user)s?$",
    re.IGNORECASE,
)
_GO_EXPIRY_PRUNING_PATTERN = re.compile(
    r"\b(?:time\.After|time\.Tick|time\.NewTicker|prune|expire|cleanup|evict|ttl|delete\(|Clear|Purge|gc)\b"
)
_GO_COORD_SPEED_PATTERN = re.compile(
    r"\.(?:X|Y|Z|Lat|Lng|Lon|Latitude|Longitude|Speed|Velocity|Acceleration|Position|Coord|Coords|Location|Point|Heading|Direction)\b"
)
_GO_VALIDATION_PATTERN = re.compile(
    r"\b(?:Clamp|Abs|Min|Max|Validate|Check|Bound|Limit|Range|Sanitize|Verify)\b"
)
_GO_REQUEST_DECODE_PATTERN = re.compile(
    r"\bjson\.(?:Unmarshal|NewDecoder)|\.Decode\s*\(|r\.(?:FormValue|PostFormValue|URL\.Query\(\)\.Get|Body)"
)
_GO_BOUNDS_CHECK_PATTERN = re.compile(
    r"\bif\s+.*(?:\.(?:X|Y|Z|Lat|Lng|Lon|Latitude|Longitude|Speed|Velocity|Acceleration|Position|Coord|Coords|Location|Point|Heading|Direction)[^;{}]*[<>]=?|"
    r"[<>]=?[^;{}]*\.(?:X|Y|Z|Lat|Lng|Lon|Latitude|Longitude|Speed|Velocity|Acceleration|Position|Coord|Coords|Location|Point|Heading|Direction))"
)
_GO_SESSION_LIKE_NAME_PATTERN = re.compile(
    r"(?:session|state|auth|user|profile|data|context|info|payload|metadata|attribute|property)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _GoDynamicSqlSource:
    line_range: range
    line_number: int
    construction_kind: str | None


@dataclass(frozen=True)
class _GoExecutionCall:
    method: str
    argument_text: str
    line_range: range
    line_number: int


@dataclass(frozen=True)
class _GoServiceLocatorMatch:
    line_range: range
    line_number: int
    access_pattern: str
    resolution_kind: str


@dataclass(frozen=True)
class _GoDetachedGoroutineMatch:
    line_range: range
    line_number: int
    access_pattern: str
    launch_kind: str


@dataclass(frozen=True)
class _GoRootedContextMatch:
    line_range: range
    line_number: int
    access_pattern: str
    propagation_kind: str


@dataclass(frozen=True)
class _GoBackgroundObservabilityMatch:
    line_range: range
    line_number: int
    access_pattern: str
    observability_kind: str


@dataclass(frozen=True)
class _GoResponseLifecycleMatch:
    line_range: range
    line_number: int
    access_pattern: str
    lifecycle_kind: str


@dataclass(frozen=True)
class _GoErrorResponseMatch:
    line_range: range
    line_number: int
    access_pattern: str
    detail_kind: str
    symbol: str


@dataclass(frozen=True)
class _GoPersistenceBoundaryMatch:
    line_range: range
    line_number: int
    access_pattern: str
    persistence_kind: str
    symbol: str


@dataclass(frozen=True)
class _GoStrictJsonBodyMatch:
    line_range: range
    line_number: int
    access_pattern: str
    strictness_kind: str
    symbol: str


@dataclass(frozen=True)
class _GoExternalLiteralMatch:
    line_range: range
    line_number: int
    context_name: str | None
    literal_kind: str
    literal_value: str


@dataclass(frozen=True)
class _GoLogCall:
    method: str
    arguments: tuple[str, ...]
    line_range: range
    line_number: int


@dataclass(frozen=True)
class _GoSensitiveLoggingMatch:
    log_method: str
    identifier_name: str
    sensitivity_kind: str
    line_range: range
    line_number: int


@dataclass(frozen=True)
class _GoFunctionContext:
    name: str
    body: str
    line_range: range
    body_start_line: int
    request_param_name: str | None = None


@dataclass(frozen=True)
class _GoControlLine:
    text: str
    line_number: int
    start_depth: int
    end_depth: int


class GoAdapter(RulesAdapter):
    adapter_key = "go"

    def __init__(self, registry: RulesRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> tuple[NormalizedFinding, ...]:
        requested_rule_ids = tuple(dict.fromkeys(rule_ids))
        if not requested_rule_ids:
            return ()

        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_go_files(context):
            absolute_path = context.repo_root / relative_path
            try:
                source = absolute_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            changed_lines = _changed_lines_for_path(
                repo_root=context.repo_root,
                relative_path=relative_path,
                mode=context.mode,
                total_lines=len(source.splitlines()),
            )
            if _HANDLER_ENV_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_ENV_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_env_read_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_OUTBOUND_HTTP_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_OUTBOUND_HTTP_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_outbound_http_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_CONCRETE_DEPENDENCY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_CONCRETE_DEPENDENCY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_concrete_dependency_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_PERSISTENCE_BOUNDARY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_PERSISTENCE_BOUNDARY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_persistence_boundary_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_SERVICE_LOCATOR_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_SERVICE_LOCATOR_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_service_locator_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_ASYNC_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_ASYNC_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_detached_goroutine_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_CONTEXT_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_CONTEXT_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_rooted_context_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_OBSERVABILITY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_OBSERVABILITY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_background_observability_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HANDLER_RESPONSE_LIFECYCLE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HANDLER_RESPONSE_LIFECYCLE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_response_lifecycle_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_outbound_client_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_ASYNC_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_ASYNC_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_detached_goroutine_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_CONTEXT_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_CONTEXT_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_rooted_context_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_OBSERVABILITY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_OBSERVABILITY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_background_observability_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_SERVICE_LOCATOR_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_SERVICE_LOCATOR_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_service_locator_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SECRET_FALLBACK_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SECRET_FALLBACK_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_secret_fallback_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _EXTERNAL_LITERAL_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_EXTERNAL_LITERAL_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_hardcoded_external_literal_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _DYNAMIC_SQL_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_DYNAMIC_SQL_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_dynamic_sql_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _ERROR_RESPONSE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_ERROR_RESPONSE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_error_response_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _STRICT_JSON_BODY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_STRICT_JSON_BODY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_handler_strict_json_body_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CREDENTIAL_LOGGING_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CREDENTIAL_LOGGING_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_sensitive_logging_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            sensitivity_kind="credential",
                        )
                    )
            if _PII_LOGGING_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_PII_LOGGING_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_sensitive_logging_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            sensitivity_kind="pii",
                        )
                    )
            if _VECTOR_MAGNITUDE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_VECTOR_MAGNITUDE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_squared_magnitude_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _HARD_CODED_SQL_SCHEMA_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_HARD_CODED_SQL_SCHEMA_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_hardcoded_sql_schema_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _JSON_NUMERIC_FIELD_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_JSON_NUMERIC_FIELD_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_json_numeric_field_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _PLAINTEXT_HTTP_ERROR_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_PLAINTEXT_HTTP_ERROR_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_plaintext_http_error_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _AUTHORITATIVE_VALIDATION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_AUTHORITATIVE_VALIDATION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_authoritative_validation_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _OAUTH_CALLBACK_STATE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_OAUTH_CALLBACK_STATE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_oauth_callback_state_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _IN_MEMORY_STORE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_IN_MEMORY_STORE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_in_memory_store_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _UNVALIDATED_ENUMERATED_INPUT_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_UNVALIDATED_ENUMERATED_INPUT_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_unvalidated_enumerated_input_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _IMPLICIT_CROSS_MODULE_SESSION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_IMPLICIT_CROSS_MODULE_SESSION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_implicit_cross_module_session_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
        return tuple(findings)


def _candidate_go_files(context: AdapterContext) -> tuple[str, ...]:
    if context.mode is ExecutionMode.DIFF:
        return tuple(
            path
            for path in context.target_files
            if path.endswith(".go") and not _should_skip_path(path)
        )

    candidates: list[str] = []
    for file_path in sorted(context.repo_root.rglob("*.go")):
        try:
            relative_path = file_path.relative_to(context.repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path):
            continue
        candidates.append(relative_path)
    return tuple(candidates)


def _should_skip_path(relative_path: str) -> bool:
    path = Path(relative_path)
    return any(part in _SKIP_DIRECTORIES for part in path.parts)


def _is_handler_path(relative_path: str) -> bool:
    path = Path(relative_path)
    if any(part.lower() in _HANDLER_PATH_MARKERS for part in path.parts):
        return True
    return path.stem.lower().endswith("handler")


def _is_go_async_handler_path(relative_path: str) -> bool:
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    if any(marker in _ASYNC_HANDLER_PATH_MARKERS for marker in markers):
        return True
    return path.stem.lower().endswith("handler")


def _is_go_async_service_or_workflow_path(relative_path: str) -> bool:
    if _is_go_async_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return False
    path = Path(relative_path)
    if path.name == "main.go" or "cmd" in {part.lower() for part in path.parts}:
        return False
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    if any(marker in _SERVICE_LAYER_EXCLUDED_MARKERS for marker in markers):
        return False
    return any(marker in _SERVICE_LAYER_PATH_MARKERS for marker in markers)


def _is_go_service_or_workflow_path(relative_path: str) -> bool:
    if _is_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return False
    path = Path(relative_path)
    if path.name == "main.go" or "cmd" in {part.lower() for part in path.parts}:
        return False
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    if any(marker in _SERVICE_LAYER_EXCLUDED_MARKERS for marker in markers):
        return False
    return any(marker in _SERVICE_LAYER_PATH_MARKERS for marker in markers)


def _find_handler_env_read_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for context in _iter_go_http_handler_like_contexts(source):
        scannable_body = _strip_go_string_literals(_strip_go_comments(context.body))
        for match in _ENV_READ_PATTERN.finditer(scannable_body):
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            shifted_range = _shift_go_line_range(line_range, line_delta=context.body_start_line - 1)
            if changed_lines is not None and not any(
                line in changed_lines for line in shifted_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message="Go handler surface reads environment variables directly.",
                    location=FindingLocation(path=relative_path, line=shifted_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.GO,
                    suggestion=(
                        "Resolve config during bootstrap and inject it into the handler instead "
                        "of calling os.Getenv/os.LookupEnv inside request handling code."
                    ),
                    metadata={"env_access": f"os.{match.group('func')}"},
                )
            )
    return findings


def _find_handler_outbound_http_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if changed_lines is not None and line_number not in changed_lines:
            continue
        access_pattern: str | None = None
        call_match = _HANDLER_OUTBOUND_HTTP_PATTERN.search(line)
        if call_match is not None:
            access_pattern = f"http.{call_match.group('access')}"
        elif _HANDLER_HTTP_CLIENT_PATTERN.search(line):
            access_pattern = "http.Client"
        if access_pattern is None:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message="Go handler surface constructs outbound HTTP directly.",
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Move the outbound HTTP construction into a dedicated client/helper and "
                    "call that from the handler instead of building requests inline."
                ),
                metadata={"access_pattern": access_pattern},
            )
        )
    return findings


def _find_handler_concrete_dependency_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    scannable_source = _strip_go_comments(source)
    for match in _HANDLER_CONCRETE_DEPENDENCY_PATTERN.finditer(scannable_source):
        if _is_go_function_declaration(scannable_source, match.start("access")):
            continue
        constructor_name = _normalize_go_construction_pattern(match.group("access"))
        if not _shared_looks_like_dependency_boundary_name(constructor_name, outbound_only=False):
            continue
        line_range = _match_line_range(scannable_source, match.start("access"), match.end("access"))
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler surface constructs concrete dependency "
                    f"'{constructor_name}' inline."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Construct the collaborator in bootstrap wiring and pass it into the handler "
                    "instead of calling the constructor inline."
                ),
                metadata={"access_pattern": constructor_name},
            )
        )
    return findings


def _find_handler_persistence_boundary_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_handler_persistence_boundary_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler surface reaches directly into persistence via "
                    f"'{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Move the SQL execution or transaction orchestration behind a repository or "
                    "service boundary and call that boundary from the handler instead."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "persistence_kind": match.persistence_kind,
                    "symbol": match.symbol,
                },
            )
        )
    return findings


def _find_service_layer_outbound_client_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_service_or_workflow_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    scannable_source = _strip_go_comments(source)
    for match in _SERVICE_LAYER_OUTBOUND_CLIENT_PATTERN.finditer(scannable_source):
        if _is_go_function_declaration(scannable_source, match.start("access")):
            continue
        constructor_name = _normalize_go_construction_pattern(match.group("access"))
        if not _shared_looks_like_dependency_boundary_name(constructor_name, outbound_only=True):
            continue
        line_range = _match_line_range(scannable_source, match.start("access"), match.end("access"))
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go service/workflow code constructs outbound client "
                    f"'{constructor_name}' inline."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Move the outbound client wiring into bootstrap or a dedicated factory and "
                    "inject it into the service/workflow code."
                ),
                metadata={"access_pattern": constructor_name},
            )
        )
    return findings


def _find_handler_service_locator_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_service_locator_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler surface resolves collaborator through runtime locator "
                    f"access '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Pass the collaborator into the handler from bootstrap wiring instead of "
                    "pulling it from a package-global holder or singleton getter at runtime."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "resolution_kind": match.resolution_kind,
                },
            )
        )
    return findings


def _find_handler_detached_goroutine_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_async_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_detached_goroutine_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler/connection-entry code launches detached goroutine via "
                    f"'{match.access_pattern}' without an explicit caller-owned cancellation "
                    "boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Pass request context or done signaling into the launched work or route it "
                    "through an explicit worker boundary instead of fire-and-forget goroutine "
                    "launch from handler code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "launch_kind": match.launch_kind,
                },
            )
        )
    return findings


def _find_handler_rooted_context_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_async_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_rooted_context_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler/connection-entry code roots async or request work in "
                    f"'{match.access_pattern}' instead of propagating caller context."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Thread the caller-owned context through the handler/goroutine path instead "
                    "of starting from context.Background() or context.TODO()."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "propagation_kind": match.propagation_kind,
                },
            )
        )
    return findings


def _find_handler_background_observability_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_async_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_background_observability_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler/connection-entry background work surfaces outcomes only through "
                    f"local logs via '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Emit a durable failure/status surface (for example a tracked status record, "
                    "incident/audit event, or metric) instead of relying only on logs inside the "
                    "background function."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "observability_kind": match.observability_kind,
                },
            )
        )
    return findings


def _find_handler_response_lifecycle_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_handler_path(relative_path) or relative_path.endswith("_test.go"):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_response_lifecycle_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go handler code writes terminal HTTP response via "
                    f"'{match.access_pattern}' but can still fall through to later request logic."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Return immediately after writing the terminal response or structure the "
                    "branch so no later handler logic can run on that path."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "lifecycle_kind": match.lifecycle_kind,
                },
            )
        )
    return findings


def _find_handler_error_response_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_error_response_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go HTTP handler response exposes raw error detail via {match.detail_kind}."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Return a stable client-facing error string and log the underlying error "
                    "separately instead of formatting the raw error into http.Error."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "detail_kind": match.detail_kind,
                    "symbol": match.symbol,
                },
            )
        )
    return findings


def _find_handler_strict_json_body_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_strict_json_body_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go HTTP handler decodes request JSON via "
                    f"{match.access_pattern} without strict decoder setup."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Create an explicit json.Decoder, call DisallowUnknownFields(), and then "
                    "Decode(...) so unexpected request fields fail closed."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "strictness_kind": match.strictness_kind,
                    "symbol": match.symbol,
                },
            )
        )
    return findings


def _find_service_layer_service_locator_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_service_or_workflow_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_service_locator_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go service/workflow code resolves collaborator through runtime locator "
                    f"access '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Inject the collaborator or pass it explicitly instead of resolving it from "
                    "a package-global holder or singleton getter inside service/workflow code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "resolution_kind": match.resolution_kind,
                },
            )
        )
    return findings


def _find_service_layer_detached_goroutine_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_async_service_or_workflow_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_detached_goroutine_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go service/workflow code launches detached goroutine via "
                    f"'{match.access_pattern}' without an explicit caller-owned cancellation "
                    "boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Pass request or worker context explicitly into the launched work or route "
                    "it through an explicit lifecycle boundary instead of fire-and-forget "
                    "goroutine launch from service/workflow code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "launch_kind": match.launch_kind,
                },
            )
        )
    return findings


def _find_service_layer_rooted_context_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_async_service_or_workflow_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_rooted_context_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go service/workflow code roots async or outbound work in "
                    f"'{match.access_pattern}' instead of propagating caller context."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Thread the caller-owned context through the service/goroutine path instead "
                    "of starting from context.Background() or context.TODO()."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "propagation_kind": match.propagation_kind,
                },
            )
        )
    return findings


def _find_service_layer_background_observability_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_go_async_service_or_workflow_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_background_observability_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go service/workflow background work surfaces outcomes only through local "
                    f"logs via '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Emit a durable failure/status surface (for example a tracked status record, "
                    "incident/audit event, or metric) instead of relying only on logs inside the "
                    "background function."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "observability_kind": match.observability_kind,
                },
            )
        )
    return findings


def _find_secret_fallback_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for match in _ENV_DEFAULT_PATTERN.finditer(source):
        func_name = match.group("func")
        if not _looks_like_env_default_helper(func_name):
            continue
        key = match.group("key").strip()
        default_value = match.group("default").strip()
        if not default_value or _shared_looks_like_placeholder(default_value):
            continue
        normalized_key = key.lower().replace(".", "_").replace("-", "_")
        if not _shared_is_strong_secret_name(normalized_key):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        line_number = source.count("\n", 0, match.start("default")) + 1
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go env helper for secret-like variable "
                    f"'{key}' embeds a literal fallback value."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Remove the literal secret fallback and source the value from runtime "
                    "configuration or a secret manager."
                ),
                metadata={"env_helper": func_name, "env_name": key},
            )
        )
    return findings


def _find_dynamic_sql_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    assignments = _collect_dynamic_sql_assignments(source)
    findings: list[NormalizedFinding] = []
    for execution_call in _iter_go_execution_calls(source):
        argument_name = _simple_identifier(execution_call.argument_text)
        source_line_range = execution_call.line_range
        source_line_number = execution_call.line_number
        construction_kind = _dynamic_go_sql_construction_kind(execution_call.argument_text)
        if argument_name is not None:
            assignment = _latest_go_assignment_before(
                assignments.get(argument_name, ()),
                execution_call.line_number,
            )
            if assignment is not None:
                source_line_range = _combine_line_ranges(
                    assignment.line_range,
                    execution_call.line_range,
                )
                source_line_number = assignment.line_number
                construction_kind = assignment.construction_kind
        if construction_kind is None:
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in source_line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go SQL execution surface "
                    f"'{execution_call.method}' receives dynamically constructed SQL "
                    f"via {construction_kind}."
                ),
                location=FindingLocation(path=relative_path, line=source_line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Bind query values as parameters. If identifiers truly must vary, "
                    "map them through a tight allowlist before composing the SQL."
                ),
                metadata={
                    "execution_surface": execution_call.method,
                    "sql_construction": construction_kind,
                },
            )
        )
    return findings


def _find_hardcoded_external_literal_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if relative_path.endswith("_test.go"):
        return []
    findings: list[NormalizedFinding] = []
    for match in _iter_go_external_literal_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        context_label = match.context_name or "literal"
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Go config/default surface hardcodes "
                    f"{match.literal_kind} literal via '{context_label}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Move the literal into typed runtime configuration, tenant metadata, "
                    "or a tight enum/allowlist instead of hardcoding it in code."
                ),
                metadata={
                    "context_name": context_label,
                    "literal_kind": match.literal_kind,
                    "literal_value": match.literal_value,
                },
            )
        )
    return findings


def _find_sensitive_logging_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    sensitivity_kind: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_go_sensitive_logging_matches(source):
        if match.sensitivity_kind != sensitivity_kind:
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        descriptor = "credential-bearing value" if sensitivity_kind == "credential" else "PII value"
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go runtime log statement emits raw {descriptor} via "
                    f"'{match.identifier_name}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion=(
                    "Log a masked/truncated form or remove the sensitive value from the "
                    "runtime log statement."
                ),
                metadata={
                    "identifier_name": match.identifier_name,
                    "log_method": match.log_method,
                    "sensitivity_kind": sensitivity_kind,
                },
            )
        )
    return findings


def _find_squared_magnitude_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    scannable = _strip_go_comments(source)
    for match in _GO_SQUARED_SUM_PATTERN.finditer(scannable):
        line_range = _match_line_range(scannable, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        func_body = _go_function_body_containing_line(source, line_range.start)
        if func_body is not None and "math.Sqrt" in func_body:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message="Go code computes squared vector magnitude without math.Sqrt.",
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Apply math.Sqrt to the Pythagorean sum when comparing or storing magnitudes.",
                metadata={"pattern": "squared-sum"},
            )
        )
    return findings


def _find_hardcoded_sql_schema_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    sql_keywords = frozenset(
        {
            "select",
            "insert",
            "update",
            "delete",
            "with",
            "create",
            "drop",
            "alter",
            "where",
            "from",
            "into",
            "join",
            "values",
            "set",
            "and",
            "or",
            "order",
            "limit",
            "offset",
            "group",
            "having",
            "union",
        }
    )
    excluded_names = frozenset(
        {
            "WHERE",
            "AND",
            "OR",
            "NOT",
            "NULL",
            "TRUE",
            "FALSE",
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "FROM",
            "JOIN",
            "LIMIT",
            "OFFSET",
            "ORDER",
            "GROUP",
            "HAVING",
            "WITH",
            "VALUES",
            "SET",
            "ON",
            "AS",
            "BY",
            "IN",
            "IS",
            "LIKE",
            "BETWEEN",
            "EXISTS",
            "CASE",
            "WHEN",
            "THEN",
            "ELSE",
            "END",
            "DISTINCT",
            "ALL",
            "UNION",
            "INTERSECT",
            "EXCEPT",
        }
    )
    for literal_start, literal_end, literal_value in _iter_go_string_literals(source):
        if not any(kw in literal_value.lower() for kw in sql_keywords):
            continue
        for match in _GO_SQL_TABLE_REFERENCE_PATTERN.finditer(literal_value):
            table_name = match.group(2)
            if table_name.upper() in excluded_names:
                continue
            line_range = _match_line_range(source, literal_start, literal_end)
            if changed_lines is not None and not any(line in changed_lines for line in line_range):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=f"Go SQL string hardcodes table/column reference '{table_name}'.",
                    location=FindingLocation(path=relative_path, line=line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.GO,
                    suggestion="Verify the reference against migration files or use a schema registry/typed query builder.",
                    metadata={"table_name": table_name, "sql_keyword": match.group(1).upper()},
                )
            )
    return findings


def _find_json_numeric_field_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for match in _GO_STRUCT_DECL_PATTERN.finditer(source):
        struct_name = match.group("name")
        brace_index = source.find("{", match.start())
        if brace_index == -1:
            continue
        body, end_offset = _scan_go_block(source, brace_index)
        if body is None:
            continue
        struct_start_line = source.count("\n", 0, match.start()) + 1
        has_custom_unmarshal = (
            re.search(
                rf"\bfunc\s*\([^)]*\s+\*?{re.escape(struct_name)}\)\s*UnmarshalJSON\b",
                source,
            )
            is not None
        )
        for field_match in _GO_JSON_INT_FIELD_PATTERN.finditer(body):
            tag = field_match.group(1)
            if "string" in tag:
                continue
            field_line_in_body = body[: field_match.start()].count("\n") + 1
            field_line = struct_start_line + field_line_in_body - 1
            if changed_lines is not None and field_line not in changed_lines:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Go struct '{struct_name}' decodes external numeric JSON field "
                        "without a flexible decoder (missing string tag or UnmarshalJSON)."
                    ),
                    location=FindingLocation(path=relative_path, line=field_line),
                    adapter_id=adapter_id,
                    language=RepoLanguage.GO,
                    suggestion='Add `json:",string"` or implement a custom UnmarshalJSON to handle empty-string/string-numeric variants.',
                    metadata={
                        "struct_name": struct_name,
                        "json_tag": tag,
                        "has_custom_unmarshal": str(has_custom_unmarshal).lower(),
                    },
                )
            )
    return findings


def _find_plaintext_http_error_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []
    findings: list[NormalizedFinding] = []
    for context in _iter_go_http_handler_like_contexts(source):
        scannable_body = _strip_go_comments(context.body)
        for match in _GO_HTTP_ERROR_RESPONSE_PATTERN.finditer(scannable_body):
            arguments, call_end = _extract_go_call_arguments(scannable_body, match.end())
            if len(arguments) < 3:
                continue
            status_arg = arguments[2].strip()
            if status_arg not in (
                "http.StatusInternalServerError",
                "http.StatusServiceUnavailable",
                "500",
                "503",
            ):
                continue
            line_range = _match_line_range(scannable_body, match.start("access"), call_end)
            shifted_range = range(
                line_range.start + context.body_start_line - 1,
                line_range.stop + context.body_start_line - 1,
            )
            if changed_lines is not None and not any(
                line in changed_lines for line in shifted_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Go HTTP handler returns plaintext error for unconfigured service "
                        f"failure with status {status_arg}."
                    ),
                    location=FindingLocation(path=relative_path, line=shifted_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.GO,
                    suggestion="Return a structured JSON error with a semantically correct status code instead of plain text.",
                    metadata={
                        "access_pattern": "http.Error",
                        "status_code": status_arg,
                        "symbol": context.name,
                    },
                )
            )
    return findings


def _find_authoritative_validation_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []
    findings: list[NormalizedFinding] = []
    for context in _iter_go_http_handler_like_contexts(source):
        scannable_body = _strip_go_comments(context.body)
        if _GO_REQUEST_DECODE_PATTERN.search(scannable_body) is None:
            continue
        if _GO_COORD_SPEED_PATTERN.search(scannable_body) is None:
            continue
        if _GO_VALIDATION_PATTERN.search(scannable_body) is not None:
            continue
        if _GO_BOUNDS_CHECK_PATTERN.search(scannable_body) is not None:
            continue
        line_range = context.line_range
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go authoritative handler '{context.name}' reads client coordinates or speed "
                    "without server-side validation."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Add bounds checks, clamping, or validation before applying client-provided coordinates or speed.",
                metadata={
                    "symbol": context.name,
                    "has_request_decode": "true",
                    "has_coord_speed": "true",
                    "has_validation": "false",
                },
            )
        )
    return findings


def _find_oauth_callback_state_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []
    findings: list[NormalizedFinding] = []
    for context in _iter_go_http_handler_like_contexts(source):
        if _GO_OAUTH_CALLBACK_FUNC_PATTERN.search(context.name) is None:
            continue
        scannable_body = _strip_go_comments(context.body)
        if _GO_STATE_VERIFICATION_PATTERN.search(scannable_body) is not None:
            continue
        line_range = context.line_range
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go OAuth callback handler '{context.name}' does not verify the CSRF "
                    "'state' parameter."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Generate, verify, and consume a per-request state token in the OAuth callback handler.",
                metadata={
                    "symbol": context.name,
                    "has_state_check": "false",
                },
            )
        )
    for match in _GO_OAUTH_CALLBACK_PATH_PATTERN.finditer(source):
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message="Go route registers an OAuth callback without visible state verification.",
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Ensure the OAuth callback handler generates, verifies, and consumes a per-request state token.",
                metadata={"route": match.group(0)},
            )
        )
    return findings


def _find_in_memory_store_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if relative_path.endswith("_test.go"):
        return []
    findings: list[NormalizedFinding] = []
    if _GO_EXPIRY_PRUNING_PATTERN.search(source) is not None:
        return []
    for match in _GO_MAP_STORE_PATTERN.finditer(source):
        name = match.group("name")
        if not _GO_STORE_NAME_PATTERN.search(name):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=f"Go in-memory store '{name}' (map) lacks visible expiry or pruning logic.",
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Add time-bounded expiry and periodic pruning to prevent unbounded memory growth.",
                metadata={
                    "store_name": name,
                    "store_kind": "map-variable",
                },
            )
        )
    for match in _GO_MAP_STORE_MAKE_PATTERN.finditer(source):
        name = match.group("name")
        if not _GO_STORE_NAME_PATTERN.search(name):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=f"Go in-memory store '{name}' (map) lacks visible expiry or pruning logic.",
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Add time-bounded expiry and periodic pruning to prevent unbounded memory growth.",
                metadata={
                    "store_name": name,
                    "store_kind": "map-make",
                },
            )
        )
    for match in _GO_MAP_STORE_PARAM_PATTERN.finditer(source):
        name = match.group("name")
        if not _GO_STORE_NAME_PATTERN.search(name):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=f"Go in-memory store '{name}' (map parameter) lacks visible expiry or pruning logic.",
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Add time-bounded expiry and periodic pruning to prevent unbounded memory growth.",
                metadata={
                    "store_name": name,
                    "store_kind": "map-parameter",
                },
            )
        )
    return findings


def _find_unvalidated_enumerated_input_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_runtime_go_path(relative_path):
        return []
    findings: list[NormalizedFinding] = []
    for context in _iter_go_http_handler_like_contexts(source):
        scannable_body = _strip_go_comments(context.body)
        for match in _GO_REQUEST_STRING_READ_PATTERN.finditer(scannable_body):
            var_name = match.group("var")
            validation_pattern = re.compile(
                rf"\bswitch\s+{re.escape(var_name)}\b|"
                rf'\bif\s+(?:.*?\b{re.escape(var_name)}\b\s*(?:==|!=)\s*["`]|\b{re.escape(var_name)}\b\s+(?:==|!=)\s*["`])|'
                rf'\bif\s+(?:["`][^"`]*["`]\s*(?:==|!=)\s*\b{re.escape(var_name)}\b)'
            )
            if validation_pattern.search(scannable_body) is not None:
                continue
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            shifted_range = _shift_go_line_range(line_range, line_delta=context.body_start_line - 1)
            if changed_lines is not None and not any(
                line in changed_lines for line in shifted_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Go handler reads enumerated string input '{var_name}' from the request "
                        "without allowlist validation."
                    ),
                    location=FindingLocation(path=relative_path, line=shifted_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.GO,
                    suggestion="Validate the input against an explicit allowlist before using it.",
                    metadata={
                        "symbol": context.name,
                        "variable": var_name,
                    },
                )
            )
    return findings


def _find_implicit_cross_module_session_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if relative_path.endswith("_test.go"):
        return []
    findings: list[NormalizedFinding] = []
    for match in _GO_MAP_INTERFACE_PATTERN.finditer(source):
        name = match.group("name")
        if not _GO_SESSION_LIKE_NAME_PATTERN.search(name):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go code passes session data via inferred map[string]interface{{}} "
                    f"('{name}') instead of an explicit shared SessionInfo DTO."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Define an explicit shared SessionInfo DTO and pass that between packages instead of a loose map.",
                metadata={
                    "variable": name,
                    "type": "map[string]interface{}",
                },
            )
        )
    for match in _GO_MAP_INTERFACE_MAKE_PATTERN.finditer(source):
        name = match.group("name")
        if not _GO_SESSION_LIKE_NAME_PATTERN.search(name):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go code passes session data via inferred map[string]interface{{}} "
                    f"('{name}') instead of an explicit shared SessionInfo DTO."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Define an explicit shared SessionInfo DTO and pass that between packages instead of a loose map.",
                metadata={
                    "variable": name,
                    "type": "map[string]interface{}",
                },
            )
        )
    for match in _GO_MAP_INTERFACE_PARAM_PATTERN.finditer(source):
        name = match.group("name")
        if not _GO_SESSION_LIKE_NAME_PATTERN.search(name):
            continue
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Go code passes session data via inferred map[string]interface{{}} "
                    f"('{name}') instead of an explicit shared SessionInfo DTO."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.GO,
                suggestion="Define an explicit shared SessionInfo DTO and pass that between packages instead of a loose map.",
                metadata={
                    "variable": name,
                    "type": "map[string]interface{}",
                },
            )
        )
    return findings


def _go_function_body_containing_line(source: str, line_number: int) -> str | None:
    for match in _GO_FUNCTION_DECL_PATTERN.finditer(source):
        brace_index = source.find("{", match.end())
        if brace_index == -1:
            continue
        body, end_offset = _scan_go_block(source, brace_index)
        if body is None:
            continue
        func_start_line = source.count("\n", 0, match.start()) + 1
        func_end_line = source.count("\n", 0, end_offset) + 1
        if func_start_line <= line_number <= func_end_line:
            return body
    return None


def _collect_dynamic_sql_assignments(source: str) -> dict[str, list[_GoDynamicSqlSource]]:
    scannable_source = _strip_go_comments(source)
    assignments: dict[str, list[_GoDynamicSqlSource]] = {}
    for match in _SQL_ASSIGNMENT_PATTERN.finditer(scannable_source):
        expression_text, expression_end = _scan_go_expression(
            scannable_source,
            match.end(),
            stop_chars=frozenset(),
            stop_at_newline=True,
        )
        if _SQL_KEYWORD_PATTERN.search(_strip_go_comments(expression_text)) is None:
            continue
        construction_kind = _dynamic_go_sql_construction_kind(expression_text)
        line_range = _line_range_for_offsets(scannable_source, match.start("name"), expression_end)
        assignments.setdefault(match.group("name"), []).append(
            _GoDynamicSqlSource(
                line_range=line_range,
                line_number=line_range.start,
                construction_kind=construction_kind,
            )
        )
    return assignments


def _iter_go_sensitive_logging_matches(source: str) -> tuple[_GoSensitiveLoggingMatch, ...]:
    matches: list[_GoSensitiveLoggingMatch] = []
    for call in _iter_go_log_calls(source):
        arguments = _go_sensitive_logging_arguments(call)
        for argument_text in arguments:
            identifier_name, sensitivity_kind = _go_sensitive_logging_identity(argument_text)
            if identifier_name is None or sensitivity_kind is None:
                continue
            matches.append(
                _GoSensitiveLoggingMatch(
                    log_method=call.method,
                    identifier_name=identifier_name,
                    sensitivity_kind=sensitivity_kind,
                    line_range=call.line_range,
                    line_number=call.line_number,
                )
            )
    return tuple(matches)


def _iter_go_log_calls(source: str) -> tuple[_GoLogCall, ...]:
    scannable_source = _strip_go_comments(source)
    calls: list[_GoLogCall] = []
    for match in _GO_LOG_CALL_PATTERN.finditer(scannable_source):
        if not _looks_like_go_log_receiver(match.group("receiver")):
            continue
        arguments, call_end = _extract_go_call_arguments(scannable_source, match.end())
        if not arguments:
            continue
        line_range = _match_line_range(scannable_source, match.start("method"), call_end)
        calls.append(
            _GoLogCall(
                method=match.group("method"),
                arguments=arguments,
                line_range=line_range,
                line_number=line_range.start,
            )
        )
    return tuple(calls)


def _go_sensitive_logging_arguments(call: _GoLogCall) -> tuple[str, ...]:
    if not call.arguments:
        return ()
    if call.method.endswith("f"):
        if len(call.arguments) == 1:
            return () if _is_plain_go_string_literal(call.arguments[0]) else call.arguments
        return call.arguments[1:]
    return tuple(
        argument for argument in call.arguments if not _is_plain_go_string_literal(argument)
    )


def _iter_go_execution_calls(source: str) -> tuple[_GoExecutionCall, ...]:
    scannable_source = _strip_go_comments(source)
    calls: list[_GoExecutionCall] = []
    for match in _SQL_EXECUTION_PATTERN.finditer(scannable_source):
        argument_text, argument_end = _extract_go_call_argument(
            scannable_source,
            match.end(),
            argument_index=_go_sql_argument_index(match.group("method")),
        )
        stripped_argument = argument_text.strip()
        if not stripped_argument:
            continue
        line_range = _line_range_for_offsets(scannable_source, match.start("method"), argument_end)
        calls.append(
            _GoExecutionCall(
                method=match.group("method"),
                argument_text=stripped_argument,
                line_range=line_range,
                line_number=line_range.start,
            )
        )
    return tuple(calls)


def _go_sql_argument_index(method_name: str) -> int:
    if method_name.endswith("Context"):
        return 1
    return 0


def _extract_go_call_argument(
    source: str, start_offset: int, *, argument_index: int
) -> tuple[str, int]:
    current_offset = start_offset
    for current_index in range(argument_index + 1):
        argument_text, argument_end = _scan_go_expression(
            source,
            current_offset,
            stop_chars=frozenset({",", ")"}),
        )
        separator = source[argument_end] if argument_end < len(source) else ""
        if current_index == argument_index:
            return argument_text, argument_end
        if separator != ",":
            return "", argument_end
        current_offset = _skip_go_argument_whitespace(source, argument_end + 1)
    return "", current_offset


def _extract_go_call_arguments(source: str, start_offset: int) -> tuple[tuple[str, ...], int]:
    current_offset = _skip_go_argument_whitespace(source, start_offset)
    if current_offset < len(source) and source[current_offset] == ")":
        return (), current_offset + 1

    arguments: list[str] = []
    while current_offset < len(source):
        argument_text, argument_end = _scan_go_expression(
            source,
            current_offset,
            stop_chars=frozenset({",", ")"}),
        )
        stripped_argument = argument_text.strip()
        if stripped_argument:
            arguments.append(stripped_argument)
        separator = source[argument_end] if argument_end < len(source) else ""
        if separator == ",":
            current_offset = _skip_go_argument_whitespace(source, argument_end + 1)
            continue
        if separator == ")":
            return tuple(arguments), argument_end + 1
        return tuple(arguments), argument_end
    return tuple(arguments), current_offset


def _skip_go_argument_whitespace(source: str, start_offset: int) -> int:
    index = start_offset
    while index < len(source) and source[index].isspace():
        index += 1
    return index


def _dynamic_go_sql_construction_kind(expression_text: str) -> str | None:
    normalized = _strip_go_comments(expression_text)
    if _SQL_KEYWORD_PATTERN.search(normalized) is None:
        return None
    format_kind = _risky_go_format_kind(normalized)
    if format_kind is not None:
        return format_kind
    if _is_unsafe_go_string_concatenation(normalized):
        return "string concatenation"
    return None


def _iter_go_external_literal_matches(source: str) -> tuple[_GoExternalLiteralMatch, ...]:
    matches: list[_GoExternalLiteralMatch] = []
    for literal_start, literal_end, literal_value in _iter_go_string_literals(source):
        context_name = _go_literal_context_name(source, literal_start - 1)
        literal_kind = _go_external_literal_kind(literal_value, context_name)
        if literal_kind is not None:
            line_range = _match_line_range(source, literal_start, literal_end)
            matches.append(
                _GoExternalLiteralMatch(
                    line_range=line_range,
                    line_number=line_range.start,
                    context_name=context_name,
                    literal_kind=literal_kind,
                    literal_value=literal_value,
                )
            )
    return tuple(matches)


def _go_literal_context_name(source: str, literal_offset: int) -> str | None:
    snippet = source[max(0, literal_offset - 160) : literal_offset]
    assignment_match = re.search(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=(?!=))\s*(?:[A-Za-z0-9_.]+\(\s*)?$",
        snippet,
        re.DOTALL,
    )
    if assignment_match is not None:
        return assignment_match.group("name")
    method_match = re.search(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\(\s*$", snippet, re.DOTALL)
    if method_match is not None:
        return method_match.group("name")
    return None


def _go_external_literal_kind(literal_value: str, context_name: str | None) -> str | None:
    if context_name is None:
        return None
    normalized_context = _normalize_external_context_name(context_name)
    if _EXTERNAL_URL_PATTERN.fullmatch(literal_value) and any(
        marker in normalized_context for marker in _URL_CONTEXT_MARKERS
    ):
        return "service-url"
    if _EXTERNAL_DOMAIN_PATTERN.fullmatch(literal_value) and (
        "domain" in normalized_context or "host" in normalized_context
    ):
        return "public-domain"
    if not _EXTERNAL_IDENTIFIER_PATTERN.fullmatch(literal_value):
        return None
    if "channel" in normalized_context:
        return "channel-identifier"
    if "provider" in normalized_context:
        return "provider-identifier"
    if "integration" in normalized_context:
        return "integration-identifier"
    if "owner" in normalized_context and "role" in normalized_context:
        return "owner-role-identifier"
    return None


def _iter_go_string_literals(source: str) -> Iterator[tuple[int, int, str]]:
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            newline_index = source.find("\n", index)
            index = len(source) if newline_index == -1 else newline_index + 1
            continue
        if source.startswith("/*", index):
            block_end = source.find("*/", index + 2)
            index = len(source) if block_end == -1 else block_end + 2
            continue
        char = source[index]
        if char == "`":
            literal_end = source.find("`", index + 1)
            literal_end = len(source) if literal_end == -1 else literal_end + 1
            yield index + 1, literal_end, source[index + 1 : literal_end - 1]
            index = literal_end
            continue
        if char == "'":
            index = _advance_go_quoted_literal(source, index + 1, quote="'")
            continue
        if char != '"':
            index += 1
            continue
        literal_start = index + 1
        literal_end = _advance_go_quoted_literal(source, literal_start, quote='"')
        yield literal_start, literal_end, source[literal_start : literal_end - 1]
        index = literal_end


def _normalize_external_context_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _risky_go_format_kind(expression_text: str) -> str | None:
    for function_name in ("fmt.Sprintf", "fmt.Appendf"):
        match = re.search(rf"\b{re.escape(function_name)}\s*\(", expression_text)
        if match is None:
            continue
        format_text = _go_format_argument_text(expression_text, match.end())
        if (
            format_text
            and _RISKY_GO_PLACEHOLDER_PATTERN.search(format_text) is not None
            and not _go_format_is_safe_placeholder_join(expression_text, match.end(), format_text)
        ):
            return function_name
    return None


def _go_format_is_safe_placeholder_join(
    expression_text: str, start_offset: int, format_text: str
) -> bool:
    risky_placeholders = list(_RISKY_GO_PLACEHOLDER_PATTERN.finditer(format_text))
    if len(risky_placeholders) != 1 or risky_placeholders[0].group(0)[-1].lower() != "s":
        return False
    second_argument, second_end = _extract_go_call_argument(
        expression_text,
        start_offset,
        argument_index=1,
    )
    if not re.fullmatch(
        r"\s*strings\.Join\(\s*(?:placeholders|valueStrings)\b.*\)\s*",
        second_argument,
        re.DOTALL,
    ):
        return False
    closing_offset = _skip_go_argument_whitespace(expression_text, second_end)
    if closing_offset < len(expression_text) and expression_text[closing_offset] == ",":
        closing_offset = _skip_go_argument_whitespace(expression_text, closing_offset + 1)
    return closing_offset < len(expression_text) and expression_text[closing_offset] == ")"


def _go_safe_condition_fragment_concat(expression_text: str) -> bool:
    return bool(
        re.fullmatch(
            r'\s*"[^"]*\b(?:WHERE|AND|OR)\b\s*"\s*\+\s*'
            r"(?:c|clause|condition(?:s)?(?:\s*\[[^\]]+\])?)\s*",
            expression_text,
        )
    )


def _go_format_argument_text(expression_text: str, start_offset: int) -> str | None:
    argument_start = _skip_go_argument_whitespace(expression_text, start_offset)
    if argument_start >= len(expression_text):
        return None
    quote = expression_text[argument_start]
    if quote == "`":
        end_offset = expression_text.find("`", argument_start + 1)
        if end_offset == -1:
            return None
        return expression_text[argument_start + 1 : end_offset]
    if quote == '"':
        end_offset = _advance_go_quoted_literal(expression_text, argument_start + 1, quote='"')
        return expression_text[argument_start + 1 : end_offset - 1]
    return None


def _has_dynamic_go_concatenation(expression_text: str) -> bool:
    return bool(
        re.search(r"[A-Za-z0-9_)\]]\s*\+", expression_text)
        or re.search(r"\+\s*[A-Za-z_(]", expression_text)
    )


def _is_unsafe_go_string_concatenation(expression_text: str) -> bool:
    stripped = _strip_go_string_literals(_strip_safe_go_concat_fragments(expression_text))
    if not _has_dynamic_go_concatenation(stripped):
        return False
    return not _go_safe_condition_fragment_concat(expression_text)


def _strip_safe_go_concat_fragments(expression_text: str) -> str:
    stripped = re.sub(
        r"\+\s*strings\.Join\(\s*(?:placeholders|valueStrings)\b[^)]*\)",
        "",
        expression_text,
    )
    return re.sub(
        r'\+\s*fmt\.Sprintf\(\s*"[^"]*%(?:\[\d+\])?(?:0?\d+)?d[^"]*"\s*,[^)]*\)',
        "",
        stripped,
    )


def _strip_go_comments(source: str) -> str:
    return re.sub(
        r"//.*?$|/\*.*?\*/",
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        source,
        flags=re.MULTILINE | re.DOTALL,
    )


def _strip_go_string_literals(source: str) -> str:
    chunks: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char == "`":
            end_offset = source.find("`", index + 1)
            literal_end = len(source) if end_offset == -1 else end_offset + 1
            chunks.append(re.sub(r"[^\n]", " ", source[index:literal_end]))
            index = literal_end
            continue
        if char == '"':
            literal_end = _advance_go_quoted_literal(source, index + 1, quote='"')
            chunks.append(re.sub(r"[^\n]", " ", source[index:literal_end]))
            index = literal_end
            continue
        if char == "'":
            literal_end = _advance_go_quoted_literal(source, index + 1, quote="'")
            chunks.append(re.sub(r"[^\n]", " ", source[index:literal_end]))
            index = literal_end
            continue
        chunks.append(char)
        index += 1
    return "".join(chunks)


def _scan_go_expression(
    source: str,
    start_offset: int,
    *,
    stop_chars: frozenset[str],
    stop_at_newline: bool = False,
) -> tuple[str, int]:
    index = start_offset
    depth = 0
    while index < len(source):
        if source.startswith("//", index):
            newline_index = source.find("\n", index)
            if newline_index == -1:
                return source[start_offset:index], len(source)
            if stop_at_newline and depth == 0:
                return source[start_offset:index], index
            index = newline_index + 1
            continue
        if source.startswith("/*", index):
            block_end = source.find("*/", index + 2)
            index = len(source) if block_end == -1 else block_end + 2
            continue
        char = source[index]
        if char == "`":
            end_offset = source.find("`", index + 1)
            index = len(source) if end_offset == -1 else end_offset + 1
            continue
        if char == '"':
            index = _advance_go_quoted_literal(source, index + 1, quote='"')
            continue
        if char == "'":
            index = _advance_go_quoted_literal(source, index + 1, quote="'")
            continue
        if stop_at_newline and char == "\n" and depth == 0:
            if source[start_offset:index].rstrip().endswith("+"):
                index += 1
                continue
            break
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0 and char in stop_chars:
                break
            depth = max(0, depth - 1)
        elif char in stop_chars and depth == 0:
            break
        index += 1
    return source[start_offset:index], index


def _advance_go_quoted_literal(source: str, start_offset: int, *, quote: str) -> int:
    escaped = False
    index = start_offset
    while index < len(source):
        char = source[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index + 1
        index += 1
    return len(source)


def _simple_identifier(expression_text: str) -> str | None:
    rendered = expression_text.strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", rendered):
        return rendered
    return None


def _is_runtime_go_path(relative_path: str) -> bool:
    path = Path(relative_path)
    if relative_path.endswith("_test.go"):
        return False
    markers = {part.lower() for part in path.parts}
    markers.add(path.stem.lower())
    return not any(marker in _RUNTIME_EXCLUDED_PATH_MARKERS for marker in markers)


def _looks_like_go_log_receiver(receiver: str) -> bool:
    tokens = _shared_split_identifier_tokens(receiver.split(".")[-1])
    return any(token in {"log", "logger"} for token in tokens)


def _go_sensitive_logging_identity(expression_text: str) -> tuple[str | None, str | None]:
    if _go_expression_is_masked(expression_text):
        return None, None
    for identifier_name in _iter_go_sensitive_candidate_names(expression_text):
        sensitivity_kind = _shared_sensitive_logging_name_kind(identifier_name)
        if sensitivity_kind is None:
            continue
        return identifier_name, sensitivity_kind
    return None, None


def _iter_go_sensitive_candidate_names(expression_text: str) -> tuple[str, ...]:
    candidates: list[str] = []
    seen: set[str] = set()
    stripped = _strip_go_string_literals(expression_text)
    for identifier in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped):
        if identifier not in seen:
            seen.add(identifier)
            candidates.append(identifier)
    for _, _, literal_value in _iter_go_string_literals(expression_text):
        normalized = literal_value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)
    return tuple(candidates)


def _go_expression_is_masked(expression_text: str) -> bool:
    if re.search(r"\[[^\]]*:[^\]]*\]", expression_text):
        return True
    stripped = _strip_go_string_literals(expression_text)
    return any(
        _shared_is_masked_sensitive_logging_name(identifier)
        for identifier in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped)
    )


def _is_plain_go_string_literal(expression_text: str) -> bool:
    stripped = expression_text.strip()
    if stripped.startswith("`"):
        end_offset = stripped.find("`", 1)
        return end_offset == len(stripped) - 1
    if stripped.startswith('"'):
        return _advance_go_quoted_literal(stripped, 1, quote='"') == len(stripped)
    return False


def _line_range_for_offsets(source: str, start_offset: int, end_offset: int) -> range:
    start_line = source.count("\n", 0, start_offset) + 1
    end_line = source.count("\n", 0, end_offset) + 1
    return range(start_line, end_line + 1)


def _combine_line_ranges(first: range, second: range) -> range:
    start_line = min(first.start, second.start)
    end_line = max(first.stop, second.stop) - 1
    return range(start_line, end_line + 1)


def _latest_go_assignment_before(
    assignments: Sequence[_GoDynamicSqlSource], line_number: int
) -> _GoDynamicSqlSource | None:
    candidates = [assignment for assignment in assignments if assignment.line_number <= line_number]
    if not candidates:
        return None
    return max(candidates, key=lambda assignment: assignment.line_number)


def _looks_like_env_default_helper(function_name: str) -> bool:
    normalized = function_name.lower()
    return normalized in {"envordefault", "getenvordefault", "envdefault"} or (
        "env" in normalized and "default" in normalized
    )


def _is_go_function_declaration(source: str, start_offset: int) -> bool:
    line_start = source.rfind("\n", 0, start_offset) + 1
    prefix = source[line_start:start_offset].strip()
    return prefix == "func" or prefix.startswith("func(") or prefix.startswith("func (")


def _normalize_go_construction_pattern(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip())
    if normalized.endswith("{"):
        return normalized[:-1].strip()
    return normalized.removesuffix("(").strip()


def _normalize_go_rooted_context_access(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip())
    if normalized.startswith("context.With"):
        if "context.TODO()" in normalized:
            return normalized.split("(", 1)[0] + "(context.TODO())"
        return normalized.split("(", 1)[0] + "(context.Background())"
    return normalized


def _go_function_body(source: str, function_name: str) -> tuple[str | None, range | None]:
    for match in _GO_FUNCTION_DECL_PATTERN.finditer(source):
        if match.group("name") != function_name:
            continue
        brace_index = source.find("{", match.end())
        if brace_index == -1:
            continue
        body, end_offset = _scan_go_block(source, brace_index)
        if body is None:
            continue
        return body, _line_range_for_offsets(source, match.start("name"), end_offset)
    return None, None


def _scan_go_block(source: str, brace_index: int) -> tuple[str | None, int]:
    if brace_index < 0 or brace_index >= len(source) or source[brace_index] != "{":
        return None, brace_index
    depth = 0
    index = brace_index
    while index < len(source):
        if source.startswith("//", index):
            newline_index = source.find("\n", index)
            index = len(source) if newline_index == -1 else newline_index + 1
            continue
        if source.startswith("/*", index):
            block_end = source.find("*/", index + 2)
            index = len(source) if block_end == -1 else block_end + 2
            continue
        char = source[index]
        if char == "`":
            end_offset = source.find("`", index + 1)
            index = len(source) if end_offset == -1 else end_offset + 1
            continue
        if char == '"':
            index = _advance_go_quoted_literal(source, index + 1, quote='"')
            continue
        if char == "'":
            index = _advance_go_quoted_literal(source, index + 1, quote="'")
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace_index + 1 : index], index + 1
        index += 1
    return None, len(source)


def _go_has_log_only_background_outcome(body_text: str) -> bool:
    return _GO_LOG_CALL_PATTERN.search(body_text) is not None and (
        _GO_BACKGROUND_SURFACE_PATTERN.search(body_text) is None
    )


def _iter_go_http_handler_contexts(source: str) -> tuple[_GoFunctionContext, ...]:
    contexts: list[_GoFunctionContext] = []
    for match in _GO_FUNCTION_DECL_PATTERN.finditer(source):
        params_text, params_end = _scan_go_expression(
            source,
            match.end(),
            stop_chars=frozenset({")"}),
        )
        if "http.ResponseWriter" not in params_text or "*http.Request" not in params_text:
            continue
        brace_index = source.find("{", params_end)
        if brace_index == -1:
            continue
        body, end_offset = _scan_go_block(source, brace_index)
        if body is None:
            continue
        contexts.append(
            _GoFunctionContext(
                name=match.group("name"),
                body=body,
                line_range=_line_range_for_offsets(source, match.start("name"), end_offset),
                body_start_line=_line_range_for_offsets(
                    source, brace_index + 1, brace_index + 1
                ).start,
                request_param_name=_go_request_param_name(params_text),
            )
        )
    return tuple(contexts)


def _iter_go_http_handler_like_contexts(source: str) -> tuple[_GoFunctionContext, ...]:
    return (
        *_iter_go_http_handler_contexts(source),
        *_iter_go_http_handler_func_literal_contexts(source),
    )


def _iter_go_http_handler_func_literal_contexts(source: str) -> tuple[_GoFunctionContext, ...]:
    contexts: list[_GoFunctionContext] = []
    for index, match in enumerate(_GO_HANDLER_FUNC_LITERAL_PATTERN.finditer(source), start=1):
        params_text, params_end = _scan_go_expression(
            source,
            match.end(),
            stop_chars=frozenset({")"}),
        )
        if "http.ResponseWriter" not in params_text or "*http.Request" not in params_text:
            continue
        brace_index = source.find("{", params_end)
        if brace_index == -1:
            continue
        body, end_offset = _scan_go_block(source, brace_index)
        if body is None:
            continue
        contexts.append(
            _GoFunctionContext(
                name=f"<handler-func-{index}>",
                body=body,
                line_range=_line_range_for_offsets(source, match.start(), end_offset),
                body_start_line=_line_range_for_offsets(
                    source, brace_index + 1, brace_index + 1
                ).start,
                request_param_name=_go_request_param_name(params_text),
            )
        )
    return tuple(contexts)


def _go_request_param_name(params_text: str) -> str | None:
    match = re.search(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+\*http\.Request\b", params_text)
    if match is None:
        return None
    return match.group("name")


def _shift_go_line_range(line_range: range, *, line_delta: int) -> range:
    return range(line_range.start + line_delta, line_range.stop + line_delta)


def _go_control_flow_lines(body_text: str, *, start_line: int) -> tuple[_GoControlLine, ...]:
    sanitized = _strip_go_string_literals(_strip_go_comments(body_text))
    lines: list[_GoControlLine] = []
    depth = 0
    for index, text in enumerate(sanitized.splitlines(), start=start_line):
        start_depth = depth
        depth = max(0, depth + text.count("{") - text.count("}"))
        lines.append(
            _GoControlLine(
                text=text,
                line_number=index,
                start_depth=start_depth,
                end_depth=depth,
            )
        )
    return tuple(lines)


def _go_line_is_control_structure(stripped_line: str) -> bool:
    if not stripped_line:
        return True
    if stripped_line in {"{", "}"}:
        return True
    normalized = stripped_line.lstrip("}").strip()
    if not normalized:
        return True
    if normalized.startswith("else"):
        return True
    if normalized.startswith(("if ", "if{", "for ", "for{", "switch ", "switch{", "select{")):
        return True
    return bool(normalized.startswith(("case ", "default:")))


def _go_line_starts_sibling_branch(stripped_line: str) -> bool:
    normalized = stripped_line.lstrip("}").strip()
    return normalized.startswith(("else", "case ", "default:"))


def _go_line_is_safe_return(stripped_line: str) -> bool:
    return stripped_line == "return" or stripped_line.startswith("return ")


def _go_has_inline_safe_return(line_fragment: str) -> bool:
    return re.search(r"\breturn\b", line_fragment) is not None


def _go_call_end_index(
    lines: Sequence[_GoControlLine], *, start_index: int, start_offset: int
) -> int:
    balance = 0
    for index in range(start_index, len(lines)):
        text = lines[index].text[start_offset:] if index == start_index else lines[index].text
        balance += text.count("(") - text.count(")")
        if balance <= 0:
            return index
        start_offset = 0
    return start_index


def _go_first_meaningful_line_after(
    lines: Sequence[_GoControlLine], *, start_index: int
) -> _GoControlLine | None:
    for line in lines[start_index:]:
        if line.text.strip():
            return line
    return None


def _iter_go_error_response_matches(source: str) -> tuple[_GoErrorResponseMatch, ...]:
    matches: list[_GoErrorResponseMatch] = []
    for context in _iter_go_http_handler_like_contexts(source):
        scannable_body = _strip_go_comments(context.body)
        for match in _GO_HTTP_ERROR_RESPONSE_PATTERN.finditer(scannable_body):
            arguments, call_end = _extract_go_call_arguments(scannable_body, match.end())
            if len(arguments) < 2:
                continue
            detail_kind = _go_http_error_detail_kind(arguments[1])
            if detail_kind is None:
                continue
            line_range = _match_line_range(scannable_body, match.start("access"), call_end)
            shifted_range = range(
                line_range.start + context.body_start_line - 1,
                line_range.stop + context.body_start_line - 1,
            )
            matches.append(
                _GoErrorResponseMatch(
                    line_range=shifted_range,
                    line_number=shifted_range.start,
                    access_pattern="http.Error",
                    detail_kind=detail_kind,
                    symbol=context.name,
                )
            )
    return tuple(matches)


def _iter_go_strict_json_body_matches(source: str) -> tuple[_GoStrictJsonBodyMatch, ...]:
    matches: list[_GoStrictJsonBodyMatch] = []
    for context in _iter_go_http_handler_like_contexts(source):
        if context.request_param_name is None:
            continue
        scannable_body = _strip_go_string_literals(_strip_go_comments(context.body))
        for match in _GO_BARE_REQUEST_JSON_DECODE_PATTERN.finditer(scannable_body):
            if match.group("request") != context.request_param_name:
                continue
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            shifted_range = range(
                line_range.start + context.body_start_line - 1,
                line_range.stop + context.body_start_line - 1,
            )
            matches.append(
                _GoStrictJsonBodyMatch(
                    line_range=shifted_range,
                    line_number=shifted_range.start,
                    access_pattern="json.NewDecoder(...).Decode",
                    strictness_kind="missing-disallow-unknown-fields",
                    symbol=context.name,
                )
            )
        decoder_strictness: dict[str, bool] = {}
        events: list[tuple[int, str, re.Match[str]]] = []
        for match in _GO_JSON_DECODER_ASSIGNMENT_PATTERN.finditer(scannable_body):
            events.append((match.start(), "assign", match))
        for match in _GO_JSON_DECODER_STRICT_CALL_PATTERN.finditer(scannable_body):
            events.append((match.start(), "strict", match))
        for match in _GO_JSON_DECODER_DECODE_CALL_PATTERN.finditer(scannable_body):
            events.append((match.start(), "decode", match))
        events.sort(key=lambda item: item[0])
        for _, event_kind, match in events:
            if event_kind == "assign":
                decoder_name = match.group("var_name") or match.group("assign_name")
                if decoder_name is None:
                    continue
                if match.group("request") == context.request_param_name:
                    decoder_strictness[decoder_name] = False
                else:
                    decoder_strictness.pop(decoder_name, None)
                continue
            decoder_name = match.group("name")
            if decoder_name not in decoder_strictness:
                continue
            if event_kind == "strict":
                decoder_strictness[decoder_name] = True
                continue
            if decoder_strictness[decoder_name]:
                continue
            _, call_end = _extract_go_call_arguments(scannable_body, match.end())
            line_range = _match_line_range(scannable_body, match.start("name"), call_end)
            shifted_range = _shift_go_line_range(line_range, line_delta=context.body_start_line - 1)
            matches.append(
                _GoStrictJsonBodyMatch(
                    line_range=shifted_range,
                    line_number=shifted_range.start,
                    access_pattern=f"{decoder_name}.Decode",
                    strictness_kind="missing-disallow-unknown-fields",
                    symbol=context.name,
                )
            )
    return tuple(matches)


def _iter_go_handler_persistence_boundary_matches(
    source: str,
) -> tuple[_GoPersistenceBoundaryMatch, ...]:
    matches: list[_GoPersistenceBoundaryMatch] = []
    for context in _iter_go_http_handler_like_contexts(source):
        scannable_body = _strip_go_comments(context.body)
        for match in _GO_HANDLER_PERSISTENCE_CALL_PATTERN.finditer(scannable_body):
            _, call_end = _extract_go_call_arguments(scannable_body, match.end())
            line_range = _match_line_range(scannable_body, match.start("access"), call_end)
            shifted_range = range(
                line_range.start + context.body_start_line - 1,
                line_range.stop + context.body_start_line - 1,
            )
            access_pattern = match.group("access")
            matches.append(
                _GoPersistenceBoundaryMatch(
                    line_range=shifted_range,
                    line_number=shifted_range.start,
                    access_pattern=access_pattern,
                    persistence_kind=_go_handler_persistence_kind(access_pattern),
                    symbol=context.name,
                )
            )
    return tuple(matches)


def _go_handler_persistence_kind(access_pattern: str) -> str:
    if access_pattern.endswith(".BeginTx"):
        return "transaction-start"
    return "sql-execution"


def _go_http_error_detail_kind(expression_text: str) -> str | None:
    normalized = expression_text.strip()
    if re.search(r"\berr\.Error\s*\(\s*\)", normalized):
        return "err.Error()"
    call_match = re.match(r"fmt\.(?P<func>Sprint|Sprintf|Errorf)\s*\(", normalized)
    if call_match is None:
        return None
    arguments, _ = _extract_go_call_arguments(normalized, call_match.end())
    if not arguments:
        return None
    start_index = 0 if call_match.group("func") == "Sprint" else 1
    if any(
        re.search(r"\berr(?:\.Error\s*\(\s*\))?\b", argument)
        for argument in arguments[start_index:]
    ):
        return f"fmt.{call_match.group('func')}(err)"
    return None


def _go_response_fallthrough_line(
    lines: Sequence[_GoControlLine], *, response_index: int, call_end_index: int
) -> int | None:
    current_line = lines[response_index]
    current_depth = current_line.start_depth
    sibling_branch = False
    branch_end_index: int | None = None
    for index in range(call_end_index + 1, len(lines)):
        line = lines[index]
        stripped = line.text.strip()
        if not stripped:
            continue
        if sibling_branch:
            if line.end_depth < current_depth:
                branch_end_index = index + 1
                break
            continue
        if line.start_depth == current_depth and _go_line_starts_sibling_branch(stripped):
            sibling_branch = True
            continue
        if line.start_depth == current_depth and _go_line_is_safe_return(stripped):
            return None
        if line.start_depth == current_depth and not _go_line_is_control_structure(stripped):
            return line.line_number
        if line.end_depth < current_depth:
            branch_end_index = index + 1
            break
    if branch_end_index is None:
        branch_end_index = len(lines)
    next_line = _go_first_meaningful_line_after(lines, start_index=branch_end_index)
    if next_line is None:
        return None
    if _go_line_is_safe_return(next_line.text.strip()):
        return None
    return next_line.line_number


def _iter_go_response_lifecycle_matches(source: str) -> tuple[_GoResponseLifecycleMatch, ...]:
    scannable_source = _strip_go_comments(source)
    matches: list[_GoResponseLifecycleMatch] = []
    for context in _iter_go_http_handler_contexts(scannable_source):
        control_lines = _go_control_flow_lines(context.body, start_line=context.body_start_line)
        for index, line in enumerate(control_lines):
            match = _GO_TERMINAL_RESPONSE_CALL_PATTERN.search(line.text)
            if match is None:
                continue
            if _go_has_inline_safe_return(line.text[match.end() :]):
                continue
            call_end_index = _go_call_end_index(
                control_lines,
                start_index=index,
                start_offset=match.start(),
            )
            continuation_line = _go_response_fallthrough_line(
                control_lines,
                response_index=index,
                call_end_index=call_end_index,
            )
            if continuation_line is None:
                continue
            matches.append(
                _GoResponseLifecycleMatch(
                    line_range=range(line.line_number, continuation_line + 1),
                    line_number=line.line_number,
                    access_pattern=match.group("access"),
                    lifecycle_kind="terminal-response-fallthrough",
                )
            )
    return tuple(matches)


def _iter_go_service_locator_matches(source: str) -> tuple[_GoServiceLocatorMatch, ...]:
    scannable_source = _strip_go_comments(source)
    package_singletons = _collect_go_package_singletons(scannable_source)
    matches: list[_GoServiceLocatorMatch] = []
    for line_number, line in enumerate(scannable_source.splitlines(), start=1):
        stripped_line = line.lstrip()
        if stripped_line.startswith("func "):
            continue
        getter_match = _GO_SERVICE_LOCATOR_CALL_PATTERN.search(line)
        if getter_match is not None:
            access_pattern = getter_match.group("access").strip()
            line_range = range(line_number, line_number + 1)
            matches.append(
                _GoServiceLocatorMatch(
                    line_range=line_range,
                    line_number=line_number,
                    access_pattern=access_pattern,
                    resolution_kind="singleton-getter",
                )
            )
        for access_pattern in _iter_go_package_singleton_access_patterns(
            line, package_singletons=package_singletons
        ):
            line_range = range(line_number, line_number + 1)
            matches.append(
                _GoServiceLocatorMatch(
                    line_range=line_range,
                    line_number=line_number,
                    access_pattern=access_pattern,
                    resolution_kind="package-global",
                )
            )
    return tuple(matches)


def _iter_go_detached_goroutine_matches(source: str) -> tuple[_GoDetachedGoroutineMatch, ...]:
    scannable_source = _strip_go_comments(source)
    matches: list[_GoDetachedGoroutineMatch] = []
    for match in _GO_GOROUTINE_PATTERN.finditer(scannable_source):
        access_pattern = match.group("access")
        base_name = access_pattern.rsplit(".", 1)[-1]
        if base_name == "func":
            continue
        if _looks_like_go_lifecycle_worker(base_name):
            continue
        arguments, call_end = _extract_go_call_arguments(scannable_source, match.end())
        if _go_goroutine_has_context_handoff(arguments):
            continue
        line_range = _match_line_range(scannable_source, match.start("access"), call_end)
        matches.append(
            _GoDetachedGoroutineMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                launch_kind="named-goroutine",
            )
        )
    for match in _GO_ANONYMOUS_GOROUTINE_PATTERN.finditer(scannable_source):
        params_text, params_end = _scan_go_expression(
            scannable_source,
            match.end(),
            stop_chars=frozenset({")"}),
        )
        _ = params_text
        brace_index = scannable_source.find("{", params_end)
        if brace_index == -1:
            continue
        body, end_offset = _scan_go_block(scannable_source, brace_index)
        if body is None:
            continue
        invocation_start = _skip_go_argument_whitespace(scannable_source, end_offset)
        arguments: tuple[str, ...] = ()
        call_end = end_offset
        if invocation_start < len(scannable_source) and scannable_source[invocation_start] == "(":
            arguments, call_end = _extract_go_call_arguments(scannable_source, invocation_start + 1)
        if _go_goroutine_has_context_handoff(arguments) or _go_goroutine_has_context_handoff(
            (body,)
        ):
            continue
        access_pattern = _go_anonymous_goroutine_access_pattern(body)
        if access_pattern is None:
            continue
        line_range = _match_line_range(scannable_source, match.start(), call_end)
        matches.append(
            _GoDetachedGoroutineMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                launch_kind="anonymous-goroutine",
            )
        )
    return tuple(matches)


def _iter_go_rooted_context_matches(source: str) -> tuple[_GoRootedContextMatch, ...]:
    scannable_source = _strip_go_comments(source)
    matches: list[_GoRootedContextMatch] = []
    for line_number, line in enumerate(scannable_source.splitlines(), start=1):
        match = _GO_ROOTED_CONTEXT_PATTERN.search(line)
        if match is None:
            continue
        line_range = range(line_number, line_number + 1)
        matches.append(
            _GoRootedContextMatch(
                line_range=line_range,
                line_number=line_number,
                access_pattern=_normalize_go_rooted_context_access(match.group("access")),
                propagation_kind="rooted-background-context",
            )
        )
    return tuple(matches)


def _iter_go_background_observability_matches(
    source: str,
) -> tuple[_GoBackgroundObservabilityMatch, ...]:
    scannable_source = _strip_go_comments(source)
    matches: list[_GoBackgroundObservabilityMatch] = []
    seen: set[tuple[str, int]] = set()
    for match in _GO_GOROUTINE_PATTERN.finditer(scannable_source):
        access_pattern = match.group("access")
        base_name = access_pattern.rsplit(".", 1)[-1]
        if base_name == "func":
            continue
        if _looks_like_go_lifecycle_worker(base_name):
            continue
        body, line_range = _go_function_body(scannable_source, base_name)
        if body is None or line_range is None:
            continue
        if not _go_has_log_only_background_outcome(body):
            continue
        dedupe_key = (access_pattern, line_range.start)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        matches.append(
            _GoBackgroundObservabilityMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                observability_kind="log-only-background-outcome",
            )
        )
    return tuple(matches)


def _collect_go_package_singletons(source: str) -> frozenset[str]:
    singleton_names: set[str] = set()
    brace_depth = 0
    in_var_block = False
    for raw_line in source.splitlines():
        stripped = raw_line.strip()
        if brace_depth == 0:
            if in_var_block:
                if stripped == ")":
                    in_var_block = False
                else:
                    name = _go_var_declaration_name(stripped)
                    if name is not None and _looks_like_go_locator_holder_name(name):
                        singleton_names.add(name)
            elif stripped.startswith("var ("):
                in_var_block = True
            else:
                name = _go_top_level_var_name(stripped)
                if name is not None and _looks_like_go_locator_holder_name(name):
                    singleton_names.add(name)
        brace_depth += raw_line.count("{") - raw_line.count("}")
    return frozenset(singleton_names)


def _go_top_level_var_name(line: str) -> str | None:
    match = re.match(
        r"^var\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b(?:[^=]*)=\s*(?P<value>.+)$",
        line,
    )
    if match is None:
        return None
    if not _looks_like_go_singleton_initializer(match.group("value")):
        return None
    return match.group("name")


def _go_var_declaration_name(line: str) -> str | None:
    match = re.match(
        r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b(?:[^=]*)=\s*(?P<value>.+)$",
        line,
    )
    if match is None:
        return None
    if not _looks_like_go_singleton_initializer(match.group("value")):
        return None
    return match.group("name")


def _looks_like_go_singleton_initializer(value: str) -> bool:
    normalized = value.strip()
    return "(" in normalized or "{" in normalized or normalized.startswith("&")


def _iter_go_package_singleton_access_patterns(
    line: str, *, package_singletons: frozenset[str]
) -> Iterator[str]:
    if ":=" in line or line.lstrip().startswith("var "):
        return
    for name in package_singletons:
        selector_match = re.search(
            rf"\b{re.escape(name)}\.(?P<member>[A-Za-z_][A-Za-z0-9_]*)",
            line,
        )
        if selector_match is not None:
            member_name = selector_match.group("member")
            if _looks_like_go_singleton_getter_name(member_name):
                continue
            yield f"{name}.{member_name}"
            continue
        if re.search(rf"\b{re.escape(name)}\s*\(", line):
            yield name


def _looks_like_go_locator_holder_name(name: str) -> bool:
    tokens = set(_shared_split_identifier_tokens(name))
    return bool(tokens & _GO_SERVICE_LOCATOR_HOLDER_MARKERS)


def _looks_like_go_singleton_getter_name(name: str) -> bool:
    return (
        re.fullmatch(
            r"(?:"
            r"(?:Get|Default)[A-Z][A-Za-z0-9_]*(?:Registry|Store|Client|Provider|Manager|Pool|Singleton|Instance)"
            r"|[A-Za-z_][A-Za-z0-9_]*GetInstance"
            r")",
            name,
        )
        is not None
    )


def _looks_like_go_lifecycle_worker(name: str) -> bool:
    tokens = set(_shared_split_identifier_tokens(name))
    return bool(tokens & _GO_GOROUTINE_LIFECYCLE_MARKERS)


def _go_goroutine_has_context_handoff(arguments: Sequence[str]) -> bool:
    for argument in arguments:
        normalized = argument.lower()
        if ".context()" in normalized:
            return True
        tokens = set(_shared_split_identifier_tokens(argument))
        if "ctx" in tokens or "done" in tokens or "cancel" in tokens:
            return True
        if "context" in tokens and "background" not in tokens and "todo" not in tokens:
            return True
    return False


def _go_anonymous_goroutine_access_pattern(body_text: str) -> str | None:
    match = re.search(
        r"\b(?P<access>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*)\s*\(",
        body_text,
    )
    if match is None:
        return None
    access_pattern = match.group("access")
    if access_pattern in {"if", "for", "func", "select", "switch"}:
        return None
    return access_pattern


def _match_line_range(source: str, start_offset: int, end_offset: int) -> range:
    start_line = source.count("\n", 0, start_offset) + 1
    end_line = source.count("\n", 0, end_offset) + 1
    return range(start_line, end_line + 1)


def _changed_lines_for_path(
    *, repo_root: Path, relative_path: str, mode: ExecutionMode, total_lines: int
) -> frozenset[int] | None:
    if mode is not ExecutionMode.DIFF:
        return None

    from .python import _changed_lines_for_path as _python_changed_lines_for_path

    return _python_changed_lines_for_path(
        repo_root=repo_root,
        relative_path=relative_path,
        mode=mode,
        total_lines=total_lines,
    )


DEFAULT_ADAPTERS = (GoAdapter(),)
