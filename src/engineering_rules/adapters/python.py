"""Python adapter for diff-first engineering rules."""

from __future__ import annotations

import ast
import re
import subprocess
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..engine import AdapterContext, RulesAdapter
from ..models import (
    ExecutionMode,
    FindingLocation,
    NormalizedFinding,
    RepoLanguage,
    RuleDefinition,
)
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

_PUBLIC_API_RULE_ID = "python.typing.explicit-public-api"
_OVERSIZED_RUNTIME_FUNCTION_RULE_ID = "python.maintainability.no-oversized-runtime-function"
_OVERSIZED_RUNTIME_MODULE_RULE_ID = "python.maintainability.no-oversized-runtime-module"
_CYCLOMATIC_HOTSPOT_METHOD_RULE_ID = "python.maintainability.no-cyclomatic-hotspot-method"
_LARGE_RUNTIME_MODULE_WITHOUT_TEST_FILE_RULE_ID = (
    "python.testing.no-large-runtime-module-without-test-file"
)
_UNTYPED_TEMPLATE_CATALOG_RULE_ID = "python.typing.no-untyped-template-catalog"
_ASYNC_BLOCKING_RULE_ID = "python.correctness.async-blocking-call"
_UNBOUNDED_ASYNC_LOCK_POOL_RULE_ID = "python.concurrency.no-unbounded-async-lock-pool"
_RACY_LOCK_POOL_CREATION_RULE_ID = "python.concurrency.no-racy-lock-pool-creation"
_SYNC_DB_ON_ASYNC_PATH_RULE_ID = "python.correctness.no-sync-db-client-on-async-path"
_UNBOUNDED_UPLOAD_READ_RULE_ID = "python.resource.no-unbounded-upload-read"
_REQUEST_LAYER_ENV_RULE_ID = "python.config.no-request-layer-env-read"
_REQUEST_LAYER_FILE_IO_RULE_ID = "python.architecture.no-request-layer-local-file-io"
_REQUEST_LAYER_CONCRETE_DEPENDENCY_RULE_ID = (
    "python.architecture.no-request-layer-concrete-dependency"
)
_REQUEST_LAYER_ASYNC_RULE_ID = "python.architecture.no-request-layer-detached-async-task"
_REQUEST_LAYER_CONTEXT_COPY_RULE_ID = (
    "python.architecture.no-request-layer-thread-hop-without-context-copy"
)
_REQUEST_LAYER_EXCEPTION_SINK_RULE_ID = (
    "python.architecture.no-request-layer-log-only-task-exception-sink"
)
_REQUEST_LAYER_GLOBAL_RESOLUTION_RULE_ID = (
    "python.architecture.no-request-layer-global-collaborator-resolution"
)
_SERVICE_LAYER_ASYNC_RULE_ID = "python.architecture.no-service-layer-detached-async-task"
_SERVICE_LAYER_CONTEXT_COPY_RULE_ID = (
    "python.architecture.no-service-layer-thread-hop-without-context-copy"
)
_SERVICE_LAYER_EXCEPTION_SINK_RULE_ID = (
    "python.architecture.no-service-layer-log-only-task-exception-sink"
)
_SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID = (
    "python.architecture.no-service-layer-outbound-client-construction"
)
_SERVICE_LAYER_HTTPX_TIMEOUT_RULE_ID = (
    "python.architecture.no-service-layer-httpx-client-without-timeout-shaping"
)
_SERVICE_LAYER_GLOBAL_RESOLUTION_RULE_ID = (
    "python.architecture.no-service-layer-global-collaborator-resolution"
)
_DAEMON_TASK_FAILURE_SINK_RULE_ID = "python.architecture.no-daemon-task-without-failure-sink"
_WEBHOOK_PAYLOAD_NORMALIZATION_RULE_ID = (
    "python.architecture.no-webhook-payload-without-normalization"
)
_SECRET_FALLBACK_RULE_ID = "python.security.no-secret-fallback-literal"
_DYNAMIC_SQL_RULE_ID = "python.security.no-dynamic-sql-execution"
_EXTERNAL_LITERAL_RULE_ID = "python.reliability.no-hardcoded-external-literals"
_ERROR_RESPONSE_RULE_ID = "python.security.no-raw-exception-detail-response"
_OUTBOUND_SANITIZATION_RULE_ID = "python.security.no-outbound-html-or-url-without-sanitization"
_BARE_EXCEPT_CLEANUP_RULE_ID = "python.error-handling.no-bare-except-cleanup"
_REQUEST_JSON_BODY_RULE_ID = "python.reliability.no-route-request-json-without-invalid-json-guard"
_FASTAPI_DTO_ALIAS_RULE_ID = "python.architecture.no-public-fastapi-model-without-field-aliases"
_FASTAPI_DTO_INVARIANT_RULE_ID = (
    "python.reliability.no-public-fastapi-model-without-cross-field-invariants"
)
_STATE_DATETIME_RULE_ID = "python.reliability.no-state-layer-naive-datetime"
_ATOMIC_STATE_WRITE_RULE_ID = "python.reliability.no-durable-state-overwrite-without-atomic-replace"
_CREDENTIAL_LOGGING_RULE_ID = "python.security.no-raw-credential-logging"
_PII_LOGGING_RULE_ID = "python.security.no-raw-pii-logging"
_AI_UNVALIDATED_LLM_OUTPUT_RULE_ID = "python.ai.no-unvalidated-llm-output-on-customer-channel"
_AI_RAW_TOOL_RESPONSE_RULE_ID = "python.ai.no-raw-tool-response-to-llm"
_AI_GENERIC_SESSION_IDENTITY_RULE_ID = "python.ai.no-generic-session-identity-collapse"
_AI_MCP_PROCESS_LEAK_RULE_ID = "python.ai.no-mcp-process-leak"
_CORRECTNESS_TIMEOUT_KWARG_RULE_ID = (
    "python.correctness.no-timeout-kwarg-to-async-callable-without-signature"
)
_SECURITY_WEBHOOK_REPLAY_RULE_ID = "python.security.no-webhook-replay-without-origin-validation"
_RELIABILITY_DB_SSLMODE_RULE_ID = "python.reliability.no-db-sslmode-require-with-verification"
_CORRECTNESS_CONTEXT_MANAGER_EXIT_RULE_ID = (
    "python.correctness.no-context-manager-exit-suppressing-exceptions"
)
_SECURITY_TENANT_SHARED_WEBHOOK_SECRET_RULE_ID = "python.security.no-tenant-shared-webhook-secret"
_RELIABILITY_LIFESPAN_CLEANUP_RULE_ID = "python.reliability.no-lifespan-without-cleanup-guard"
_RELIABILITY_ORPHANED_ASYNC_TASK_RULE_ID = "python.reliability.no-orphaned-async-task-on-disconnect"
_LONG_POLL_READ_TIMEOUT_RULE_ID = "python.reliability.no-long-poll-read-timeout-mismatch"
_UNHANDLED_IDEMPOTENT_DUPLICATE_RULE_ID = (
    "python.reliability.no-unhandled-idempotent-duplicate-api-response"
)
_TELEGRAM_POLLING_PATTERN = re.compile(r"\b(?:start_polling|getUpdates)\s*\(")
_APPLICATION_BUILDER_PATTERN = re.compile(r"\bApplicationBuilder\s*\(")
_GET_UPDATES_READ_TIMEOUT_PATTERN = re.compile(r"\bget_updates_read_timeout\s*\(")
_RAISE_FOR_STATUS_PATTERN = re.compile(r"\.raise_for_status\s*\(")
_DUPLICATE_ERROR_CODE_CONSTANT_PATTERN = re.compile(
    r"\bDUPLICATE_[A-Z0-9_]+\b|\bduplicate[_ ]error[_ ]code\b",
    re.IGNORECASE,
)
_DUPLICATE_ERROR_HANDLING_BRANCH_PATTERN = re.compile(
    r"\b_is_duplicate\s*\(|if\s+[^\n]*(?:duplicate|DUPLICATE_|error_code)",
    re.IGNORECASE,
)
_POST_PUT_HTTP_CALL_PATTERN = re.compile(r"\.(?:post|put)\s*\(", re.IGNORECASE)
_PYTHON_OVERSIZED_FUNCTION_LINE_THRESHOLD = 80
_PYTHON_OVERSIZED_FUNCTION_COMPLEXITY_THRESHOLD = 12
_PYTHON_OVERSIZED_MODULE_LINE_THRESHOLD = 600
_PYTHON_CYCLOMATIC_HOTSPOT_SCORE_THRESHOLD = 10
_PYTHON_CYCLOMATIC_HOTSPOT_HIGH_SCORE_THRESHOLD = 14
_PYTHON_CYCLOMATIC_HOTSPOT_NESTING_THRESHOLD = 3
_PYTHON_CYCLOMATIC_HOTSPOT_LINE_THRESHOLD = 20
_PYTHON_RUNTIME_MODULE_TEST_LINE_THRESHOLD = 350
_TEMPLATE_CATALOG_NAME_MARKERS = frozenset(
    {"catalog", "message", "messages", "status", "template", "templates"}
)
_PREFERRED_ADAPTER_TEST_PREFIXES = ("tests/test_", "tests/")
_PUBLIC_DTO_PATH_MARKERS = frozenset({"dto", "model", "models", "request", "response", "schema"})
_SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "tests",
        "venv",
    }
)
_TEST_DISCOVERY_SKIP_DIRECTORIES = _SKIP_DIRECTORIES - frozenset({"tests"})
_REQUESTS_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "request"}
)
_HTTPX_CLIENT_CALL_NAMES = frozenset({"httpx.AsyncClient", "httpx.Client"})
_BLOCKING_CALL_SUGGESTIONS = {
    "open": "Move file I/O behind asyncio.to_thread(...) or switch to aiofiles.",
    "subprocess.call": "Use asyncio.create_subprocess_exec(...) for async subprocess work.",
    "subprocess.check_call": "Use asyncio.create_subprocess_exec(...) for async subprocess work.",
    "subprocess.check_output": "Use asyncio.create_subprocess_exec(...) for async subprocess work.",
    "subprocess.Popen": "Use asyncio.create_subprocess_exec(...) for async subprocess work.",
    "subprocess.run": "Use asyncio.create_subprocess_exec(...) for async subprocess work.",
    "time.sleep": "Replace time.sleep(...) with await asyncio.sleep(...).",
    "urllib.request.urlopen": (
        "Use an async HTTP client such as httpx.AsyncClient or move the call "
        "to asyncio.to_thread(...)."
    ),
}
_TRANSPORT_DIRECTORY_NAMES = frozenset(
    {"api", "handlers", "routes", "routers", "views", "webhooks"}
)
_TRANSPORT_STEM_MARKERS = frozenset({"api", "route", "router", "view", "views", "webhook"})
_INGRESS_NORMALIZATION_DIRECTORY_NAMES = frozenset(
    {"channels", "media", "message", "messages", "webhook", "webhooks"}
)
_INGRESS_NORMALIZATION_RAW_ROOT_NAMES = frozenset(
    {
        "attachment",
        "attachments",
        "body",
        "change",
        "changes",
        "entry",
        "event",
        "media",
        "message",
        "metadata",
        "meta",
        "payload",
        "raw",
        "user_meta",
        "value",
    }
)
_INGRESS_NORMALIZATION_CONTEXT_KEYS = frozenset(
    {
        "attachment_context",
        "attachments",
        "booking_context",
        "captured_context",
        "document",
        "image_data",
        "media",
        "reminder_context",
        "reply_correlation",
        "thread_type",
        "user_meta",
    }
)
_INGRESS_NORMALIZATION_HELPER_MARKERS = frozenset({"normalize", "canonical", "coerce"})
_CONTRACT_SURFACE_DIRECTORY_MARKERS = frozenset({"contract", "contracts", "schema", "schemas"})
_CONTRACT_SURFACE_STEM_MARKERS = frozenset({"contract", "contracts", "schema", "schemas"})
_CONTRACT_SURFACE_EXACT_STEMS = frozenset({"sidecar_eval_gates"})
_CONTRACT_TEST_MARKERS = frozenset(
    {"canary", "canaries", "contract", "contracts", "eval", "gates", "schema", "snapshot"}
)
_DEPLOY_ENV_DIRECTORY_MARKERS = frozenset({"config", "configs", "deploy", "deployment", "tenancy"})
_DEPLOY_ENV_STEM_MARKERS = frozenset(
    {"config", "health", "readiness", "registry", "settings", "sla", "snapshot", "tenant"}
)
_DEPLOY_ENV_TEST_MARKERS = frozenset(
    {"config", "contract", "deploy", "env", "health", "readiness", "snapshot", "tenant"}
)
_ROUTE_DECORATOR_NAMES = frozenset(
    {"api_route", "delete", "get", "head", "options", "patch", "post", "put", "websocket"}
)
_SERVICE_LAYER_PATH_MARKERS = frozenset(
    {
        "alert",
        "alerts",
        "consumer",
        "consumers",
        "dispatch",
        "dispatcher",
        "monitor",
        "orchestrator",
        "orchestrators",
        "proxy",
        "scheduler",
        "schedulers",
        "service",
        "services",
        "sidecar",
        "worker",
        "workers",
        "workflow",
        "workflows",
    }
)
_SERVICE_LAYER_EXCLUDED_MARKERS = frozenset(
    {
        "api",
        "app",
        "bootstrap",
        "client",
        "clients",
        "config",
        "configs",
        "factory",
        "factories",
        "main",
        "provider",
        "providers",
        "settings",
    }
)
_STATE_DATETIME_PATH_MARKERS = frozenset(
    {
        "event",
        "events",
        "monitor",
        "persistence",
        "scheduler",
        "schedulers",
        "session",
        "sessions",
        "state",
        "store",
        "stores",
    }
)
_ATOMIC_STATE_WRITE_WEBHOOK_DIRECTORY = "webhooks"
_ATOMIC_STATE_WRITE_EVENT_DIRECTORY = "events"
_ATOMIC_STATE_WRITE_EVENT_STEMS = frozenset({"monitor"})
_LOCK_POOL_EVICTION_METHODS = frozenset({"clear", "pop", "popitem"})
_GUARD_CONTEXT_MARKERS = frozenset({"guard", "lock", "locks"})
_UPLOAD_PARAMETER_NAME_MARKERS = frozenset({"file", "upload"})
_SYNC_DB_CONNECT_CALL_NAMES = frozenset(
    {
        "MySQLdb.connect",
        "cx_Oracle.connect",
        "duckdb.connect",
        "mysql.connector.connect",
        "oracledb.connect",
        "pg8000.connect",
        "psycopg.connect",
        "psycopg2.connect",
        "pymysql.connect",
        "pyodbc.connect",
        "sqlite3.connect",
    }
)
_SYNC_DB_BINDING_FACTORY_METHODS = frozenset({"cursor"})
_SYNC_DB_QUERY_METHODS = frozenset(
    {"commit", "execute", "executemany", "fetchall", "fetchmany", "fetchone", "rollback"}
)
_SYNC_DB_TYPE_TAILS = frozenset({"Connection", "Cursor"})
_SYNC_DB_MODULE_PREFIXES = (
    "MySQLdb",
    "cx_Oracle",
    "duckdb",
    "mysql.connector",
    "oracledb",
    "pg8000",
    "psycopg",
    "psycopg2",
    "pymysql",
    "pyodbc",
    "sqlite3",
)
_GLOBAL_LOCATOR_HOLDER_MARKERS = frozenset({"pool", "registry", "store"})
_GLOBAL_CONTEXT_HOLDER_MARKERS = frozenset({"context"})
_GLOBAL_LOCATOR_EXACT_NAMES = frozenset({"pool"})
_ENV_ACCESS_CALL_NAMES = frozenset({"os.getenv", "os.environ.get", "os.environ.__getitem__"})
_REQUEST_FILE_IO_CALL_NAMES = frozenset({"open", "aiofiles.open"})
_REQUEST_FILE_IO_PATH_METHODS = frozenset(
    {"open", "read_text", "write_text", "read_bytes", "write_bytes"}
)
_ASYNC_TASK_LAUNCH_CALL_NAMES = frozenset(
    {"asyncio.create_task", "asyncio.ensure_future", "create_task", "ensure_future"}
)
_ASYNC_TASK_MANAGEMENT_CALL_NAMES = frozenset(
    {"asyncio.gather", "asyncio.shield", "asyncio.wait", "asyncio.wait_for"}
)
_TENANT_SCOPE_MARKERS = frozenset(
    {
        "org",
        "orgs",
        "organization",
        "organizations",
        "project",
        "projects",
        "tenant",
        "tenants",
        "workspace",
        "workspaces",
    }
)
_USER_SCOPED_RUNTIME_STORE_SCOPE_MARKERS = frozenset(
    {
        "confirmation",
        "continuity",
        "orchestration",
        "orchestrations",
        "orchestrator",
        "orchestrators",
        "router",
        "routers",
        "runtime",
        "session",
        "sessions",
    }
)
_USER_SCOPED_RUNTIME_STORE_CONTAINER_MARKERS = frozenset({"cache", "store"})
_USER_SCOPED_RUNTIME_STORE_CONTEXT_MARKERS = frozenset(
    {"confirmation", "continuity", "runtime", "session", "sessions"}
)
_USER_SCOPED_RUNTIME_STORE_KEY_MARKERS = ("user", "owner", "channel", "session")
_USER_SCOPED_RUNTIME_STORE_ACCESS_METHODS = frozenset({"get", "pop", "setdefault"})
_DAEMON_TASK_CONTEXT_MARKERS = frozenset(
    {
        "background",
        "daemon",
        "manager",
        "managers",
        "monitor",
        "monitors",
        "orchestrator",
        "orchestrators",
        "poller",
        "pollers",
        "scheduler",
        "schedulers",
        "start",
        "startup",
        "watcher",
        "watchers",
        "worker",
        "workers",
    }
)
_DAEMON_TASK_SIGNAL_MARKERS = (
    "daemon",
    "background",
    "monitor",
    "refresh",
    "poll",
    "watch",
    "loop",
)
_DAEMON_TASK_SUPERVISION_CALL_MARKERS = frozenset({"guard", "own", "retain", "supervise"})
_EXECUTOR_HOP_CALL_NAMES = frozenset({"run_in_executor"})
_COPY_CONTEXT_CALL_NAMES = frozenset({"contextvars.copy_context", "copy_context"})
_SQL_BUILDER_CALL_NAMES = frozenset({"sqlalchemy.text", "text"})
_SQL_EXECUTION_KEYWORDS = frozenset({"query", "sql", "statement"})
_SQL_KEYWORD_PATTERN = re.compile(
    r"\b("
    r"select|insert|update|delete|with|create|drop|alter|where|from|into|join|values|set|"
    r"and|or|order|limit|offset|group|having|union"
    r")\b",
    re.IGNORECASE,
)
_EXTERNAL_URL_PATTERN = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s]*)?$")
_EXTERNAL_DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+\.[a-z]{2,}$")
_DATABASE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,}$")
_EXTERNAL_IDENTIFIER_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")
_URL_CONTEXT_MARKERS = frozenset(
    {"api", "base", "base_url", "domain", "endpoint", "host", "uri", "url"}
)
_DOMAIN_CONTEXT_MARKERS = frozenset({"domain", "host", "public_host", "public_domain"})
_DATABASE_CONTEXT_MARKERS = frozenset({"database", "database_name", "db_name", "dbname"})
_IDENTIFIER_CONTEXT_MARKERS = frozenset(
    {"channel", "provider", "integration", "integration_type", "owner_role"}
)
_EXCEPTION_DETAIL_ATTRIBUTE_NAMES = frozenset({"detail", "message"})
_SQL_LOCAL_NAME_MARKERS = frozenset({"query", "sql", "statement", "stmt"})
_PYTHON_LOG_METHODS = frozenset(
    {"critical", "debug", "error", "exception", "fatal", "info", "warn", "warning"}
)
_LLM_OUTPUT_CALL_NAMES = frozenset(
    {
        "agent.run",
        "llm.chat",
        "llm.generate",
        "llm.invoke",
        "llm.call",
        "model.chat",
        "model.generate",
        "model.invoke",
        "chat",
        "generate",
        "invoke",
        "completion",
        "call",
    }
)
_CUSTOMER_CHANNEL_SEND_NAMES = frozenset(
    {"send", "reply", "respond", "post", "message", "whatsapp", "instagram"}
)
_TOOL_CALL_NAMES = frozenset(
    {"tool", "function", "mcp", "call_tool", "invoke_tool", "run_tool", "use_tool"}
)
_MCP_CONSTRUCTOR_NAMES = frozenset(
    {"MCPClient", "MCPServer", "mcp.server", "mcp.Client", "mcp.Session"}
)
_GENERIC_SESSION_IDS = frozenset({"internal", "guest", "anonymous"})
_WEBHOOK_VERIFY_MARKERS = frozenset(
    {"verify", "signature", "hmac", "check_signature", "validate_signature"}
)
_ORIGIN_VALIDATE_MARKERS = frozenset(
    {"ipaddress", "is_global", "ip_address", "validate_origin", "check_origin"}
)
_EXTERNAL_CHANNEL_NAMES = frozenset({"whatsapp", "instagram", "web", "customer", "external"})
_CHAIN_CONFIRMATION_MARKERS = frozenset({"chain", "confirmation", "confirm", "multi_step"})
_COMMERCE_PRICE_MARKERS = frozenset({"₹", "INR", "price", "MRP"})
_PAYROLL_MARKERS = frozenset({"salary", "payroll", "employee directory"})
_WEBHOOK_HANDLER_PATH_MARKERS = frozenset({"webhook", "webhooks"})
_WEBHOOK_SECRET_GLOBAL_MARKERS = frozenset({"WEBHOOK_SECRET", "SHARED_SECRET", "GLOBAL_SECRET"})
_LIFESPAN_DECORATOR_NAMES = frozenset({"asynccontextmanager", "contextlib.asynccontextmanager"})
_WEBSOCKET_ROUTE_MARKERS = frozenset({"websocket", "ws"})
_RETRY_LOOP_MARKERS = frozenset({"retry", "retries", "attempt", "attempts"})
_RUNTIME_EXCLUDED_PATH_MARKERS = frozenset(
    {
        "benchmarks",
        "eval",
        "evals",
        "fixtures",
        "script",
        "scripts",
        "tool",
        "tools",
    }
)
_ENV_LITERAL_REVIEW_EXCLUDED_PATH_MARKERS = frozenset(
    {
        "demo",
        "demos",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "script",
        "scripts",
        "test",
        "tests",
    }
)
_OVERSIZED_RUNTIME_MODULE_EXCLUDED_PATH_MARKERS = frozenset(
    {"alembic", "generated", "migration", "migrations", "vendor", "vendors"}
)
_PYTHON_RUNTIME_REVIEW_EXCLUDED_PATH_MARKERS = frozenset(
    {
        "contract",
        "contracts",
        "dto",
        "dtos",
        "fixture",
        "fixtures",
        "mock",
        "mocks",
        "model",
        "models",
        "schema",
        "schemas",
        "serializer",
        "serializers",
        "stub",
        "stubs",
        "test",
        "tests",
        "typing",
        "types",
        "util",
        "utils",
    }
)
_PYTHON_RUNTIME_REVIEW_SERVICE_HINT_MARKERS = frozenset({"mcp", "orchestration", "orchestrations"})
_BARE_EXCEPT_CLEANUP_EXCLUDED_PATH_MARKERS = frozenset(
    {"alembic", "generated", "migration", "migrations", "vendor", "vendors"}
)
_PYTHON_CLEANUP_CALL_TAILS = frozenset(
    {"cleanup", "finalize", "rollback", "rmdir", "rmtree", "teardown", "unlink"}
)
_PYTHON_CONDITIONAL_CLEANUP_CALL_TAILS = frozenset({"delete", "remove"})
_PYTHON_CLEANUP_CALL_TOKEN_MARKERS = frozenset(
    {"cleanup", "finalize", "finalizer", "rollback", "teardown", "unlink"}
)
_PYTHON_RESOURCE_CLEANUP_RECEIVER_TOKENS = frozenset(
    {
        "artifact",
        "archive",
        "directory",
        "dir",
        "file",
        "folder",
        "path",
        "snapshot",
        "temp",
        "tmp",
    }
)


@dataclass(frozen=True)
class _ParsedPythonFile:
    relative_path: str
    module: ast.Module
    import_aliases: Mapping[str, str]
    exported_names: frozenset[str] | None
    changed_lines: frozenset[int] | None
    source_lines: tuple[str, ...]


class _PythonBranchComplexityVisitor(ast.NodeVisitor):
    def __init__(self, root: ast.AST) -> None:
        self._root = root
        self.complexity = 1

    def generic_visit(self, node: ast.AST) -> None:
        if node is not self._root and isinstance(
            node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            return
        if isinstance(node, ast.BoolOp):
            self.complexity += max(len(node.values) - 1, 0)
        elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp)):
            self.complexity += 1
        elif isinstance(node, ast.Try):
            self.complexity += max(len(node.handlers), 1)
            if node.orelse:
                self.complexity += 1
        elif isinstance(node, ast.Match):
            self.complexity += max(len(node.cases), 1)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self.complexity += sum(
                len(generator.ifs) + int(getattr(generator, "is_async", 0))
                for generator in node.generators
            )
        super().generic_visit(node)


@dataclass(frozen=True)
class _BlockingCallMatch:
    node: ast.Call
    call_name: str


@dataclass(frozen=True)
class _EnvAccessMatch:
    node: ast.expr
    call_name: str
    env_name: str | None
    default_value: str | None
    default_node: ast.expr | None = None


@dataclass(frozen=True)
class _RequestFileIOMatch:
    node: ast.Call
    access_pattern: str


@dataclass(frozen=True)
class _DynamicSqlMatch:
    node: ast.Call
    sql_expression: ast.expr
    execution_call_name: str
    construction_kind: str


@dataclass(frozen=True)
class _ExternalLiteralMatch:
    node: ast.expr
    context_name: str
    literal_kind: str
    literal_value: str


@dataclass(frozen=True)
class _SensitiveLoggingMatch:
    log_call: ast.Call
    value_node: ast.expr
    sensitivity_kind: str
    identifier_name: str
    log_method: str


@dataclass(frozen=True)
class _TemplateCatalogMatch:
    node: ast.Assign
    catalog_name: str


@dataclass(frozen=True)
class _OutboundSanitizationMatch:
    node: ast.JoinedStr
    symbol: str
    unsafe_tokens: tuple[str, ...]


@dataclass(frozen=True)
class _ConcreteDependencyMatch:
    node: ast.Call
    constructor_name: str
    symbol: str | None


@dataclass(frozen=True)
class _HttpxTimeoutMatch:
    node: ast.Call
    access_pattern: str
    timeout_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _ServiceLocatorMatch:
    node: ast.AST
    access_pattern: str
    resolution_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _AsyncLaunchMatch:
    node: ast.Call
    access_pattern: str
    management_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _ContextPropagationMatch:
    node: ast.Call
    access_pattern: str
    propagation_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _TaskExceptionSinkMatch:
    node: ast.Call
    access_pattern: str
    sink_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _UserScopedRuntimeStoreMatch:
    node: ast.AST
    access_pattern: str
    store_name: str
    key_name: str | None
    key_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _DaemonTaskMatch:
    node: ast.Call
    access_pattern: str
    daemon_signal: str
    ownership_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _ResponseErrorDetailMatch:
    node: ast.AST
    detail_node: ast.AST
    detail_kind: str
    response_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _RequestJsonBodyMatch:
    node: ast.Call
    access_pattern: str
    guard_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _StateDatetimeMatch:
    node: ast.AST
    access_pattern: str
    usage_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _AtomicStateWriteMatch:
    node: ast.AST
    write_pattern: str
    target_name: str | None
    symbol: str | None


@dataclass(frozen=True)
class _AsyncLockPoolMatch:
    node: ast.AST
    pool_name: str
    creation_pattern: str
    symbol: str | None
    has_eviction: bool
    has_capacity_guard: bool
    guarded_by_lock: bool


@dataclass(frozen=True)
class _UploadReadMatch:
    node: ast.Call
    access_pattern: str
    upload_parameter: str
    symbol: str | None


@dataclass(frozen=True)
class _SyncDbAsyncPathMatch:
    node: ast.Call
    access_pattern: str
    usage_kind: str
    symbol: str | None


@dataclass(frozen=True)
class _IngressNormalizationMatch:
    node: ast.AST
    access_pattern: str
    payload_key: str
    symbol: str | None


@dataclass(frozen=True)
class _BareExceptCleanupMatch:
    try_node: ast.Try
    handler: ast.ExceptHandler
    cleanup_patterns: tuple[str, ...]
    symbol: str | None


@dataclass(frozen=True)
class _LlmOutputMatch:
    node: ast.AST
    access_pattern: str
    symbol: str | None


@dataclass(frozen=True)
class _ToolResponseMatch:
    node: ast.AST
    access_pattern: str
    symbol: str | None


@dataclass(frozen=True)
class _SessionIdentityMatch:
    node: ast.Assign
    session_name: str
    literal_value: str


@dataclass(frozen=True)
class _McpProcessLeakMatch:
    node: ast.Call
    constructor_name: str
    symbol: str | None


@dataclass(frozen=True)
class _TimeoutKwargsMatch:
    node: ast.Call
    call_name: str
    symbol: str | None


@dataclass(frozen=True)
class _WebhookReplayMatch:
    node: ast.AST
    access_pattern: str
    symbol: str | None


@dataclass(frozen=True)
class _DbSslmodeMatch:
    node: ast.AST
    literal_value: str


@dataclass(frozen=True)
class _ChainConfirmationMatch:
    node: ast.AST
    access_pattern: str
    symbol: str | None


@dataclass(frozen=True)
class _ContextManagerExitMatch:
    node: ast.FunctionDef
    symbol: str | None


@dataclass(frozen=True)
class _CommercePriceLeakMatch:
    node: ast.AST
    literal_value: str
    symbol: str | None


@dataclass(frozen=True)
class _PayrollLeakMatch:
    node: ast.AST
    literal_value: str
    symbol: str | None


@dataclass(frozen=True)
class _TenantWebhookSecretMatch:
    node: ast.AST
    access_pattern: str
    symbol: str | None


@dataclass(frozen=True)
class _LifespanCleanupMatch:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    symbol: str | None


@dataclass(frozen=True)
class _OrphanedAsyncTaskMatch:
    node: ast.Call
    access_pattern: str
    symbol: str | None


@dataclass(frozen=True)
class _RetryCounterMatch:
    node: ast.AST
    access_pattern: str
    symbol: str | None


class _BlockingCallVisitor(ast.NodeVisitor):
    def __init__(self, *, aliases: Mapping[str, str]) -> None:
        self._aliases = aliases
        self.matches: list[_BlockingCallMatch] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _resolve_call_name(node.func, self._aliases)
        if call_name == "asyncio.to_thread":
            self._visit_nodes((*node.args[1:], *(keyword.value for keyword in node.keywords)))
            return
        if call_name and call_name.endswith(".run_in_executor"):
            self._visit_nodes(
                (
                    *node.args[:1],
                    *node.args[2:],
                    *(keyword.value for keyword in node.keywords),
                )
            )
            return

        blocking_name = _normalize_blocking_call_name(call_name)
        if blocking_name is not None:
            self.matches.append(_BlockingCallMatch(node=node, call_name=blocking_name))
        self.generic_visit(node)

    def _visit_nodes(self, nodes: Iterable[ast.AST]) -> None:
        for node in nodes:
            self.visit(node)


class PythonAdapter(RulesAdapter):
    adapter_key = "python"

    def __init__(self, registry: RulesRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> Sequence[NormalizedFinding]:
        requested_rule_ids = tuple(dict.fromkeys(rule_ids))
        if not requested_rule_ids:
            return ()

        discovered_python_test_paths = (
            _discover_python_test_paths(context.repo_root)
            if any(
                rule_id in requested_rule_ids
                for rule_id in (
                    _LARGE_RUNTIME_MODULE_WITHOUT_TEST_FILE_RULE_ID,
                )
            )
            else frozenset()
        )
        parsed_files = tuple(self._iter_python_files(context))
        findings: list[NormalizedFinding] = []

        if _PUBLIC_API_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_PUBLIC_API_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_public_api_typing_findings(parsed_file, rule))

        if _UNTYPED_TEMPLATE_CATALOG_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_UNTYPED_TEMPLATE_CATALOG_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_untyped_template_catalog_findings(parsed_file, rule))

        if _OVERSIZED_RUNTIME_FUNCTION_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_OVERSIZED_RUNTIME_FUNCTION_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_oversized_runtime_function_findings(parsed_file, rule)
                    )

        if _OVERSIZED_RUNTIME_MODULE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_OVERSIZED_RUNTIME_MODULE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_oversized_runtime_module_findings(parsed_file, rule))

        if _CYCLOMATIC_HOTSPOT_METHOD_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_CYCLOMATIC_HOTSPOT_METHOD_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_cyclomatic_hotspot_method_findings(parsed_file, rule)
                    )

        if _LARGE_RUNTIME_MODULE_WITHOUT_TEST_FILE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_LARGE_RUNTIME_MODULE_WITHOUT_TEST_FILE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_large_runtime_module_without_test_file_findings(
                            parsed_file,
                            rule,
                            discovered_python_test_paths=discovered_python_test_paths,
                        )
                    )

        if _ASYNC_BLOCKING_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_ASYNC_BLOCKING_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_async_blocking_findings(parsed_file, rule))

        if _UNBOUNDED_ASYNC_LOCK_POOL_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_UNBOUNDED_ASYNC_LOCK_POOL_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_unbounded_async_lock_pool_findings(parsed_file, rule)
                    )

        if _RACY_LOCK_POOL_CREATION_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_RACY_LOCK_POOL_CREATION_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_racy_lock_pool_creation_findings(parsed_file, rule))

        if _SYNC_DB_ON_ASYNC_PATH_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SYNC_DB_ON_ASYNC_PATH_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_sync_db_client_on_async_path_findings(parsed_file, rule)
                    )

        if _REQUEST_LAYER_ENV_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_ENV_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_request_layer_env_findings(parsed_file, rule))

        if _REQUEST_LAYER_FILE_IO_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_FILE_IO_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_request_layer_file_io_findings(parsed_file, rule))

        if _UNBOUNDED_UPLOAD_READ_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_UNBOUNDED_UPLOAD_READ_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_unbounded_upload_read_findings(parsed_file, rule))

        if _WEBHOOK_PAYLOAD_NORMALIZATION_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_WEBHOOK_PAYLOAD_NORMALIZATION_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_webhook_payload_normalization_findings(parsed_file, rule)
                    )

        if _REQUEST_LAYER_CONCRETE_DEPENDENCY_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_CONCRETE_DEPENDENCY_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_request_layer_concrete_dependency_findings(parsed_file, rule)
                    )

        if _REQUEST_LAYER_ASYNC_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_ASYNC_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_request_layer_detached_async_findings(parsed_file, rule)
                    )

        if _REQUEST_LAYER_CONTEXT_COPY_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_CONTEXT_COPY_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_request_layer_executor_context_gap_findings(parsed_file, rule)
                    )

        if _REQUEST_LAYER_EXCEPTION_SINK_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_EXCEPTION_SINK_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_request_layer_task_exception_sink_findings(parsed_file, rule)
                    )

        if _REQUEST_LAYER_GLOBAL_RESOLUTION_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_LAYER_GLOBAL_RESOLUTION_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_request_layer_global_resolution_findings(parsed_file, rule)
                    )

        if _SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_service_layer_outbound_client_findings(parsed_file, rule)
                    )

        if _SERVICE_LAYER_HTTPX_TIMEOUT_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SERVICE_LAYER_HTTPX_TIMEOUT_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_service_layer_httpx_timeout_findings(parsed_file, rule)
                    )

        if _SERVICE_LAYER_ASYNC_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SERVICE_LAYER_ASYNC_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_service_layer_detached_async_findings(parsed_file, rule)
                    )

        if _SERVICE_LAYER_CONTEXT_COPY_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SERVICE_LAYER_CONTEXT_COPY_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_service_layer_executor_context_gap_findings(parsed_file, rule)
                    )

        if _SERVICE_LAYER_EXCEPTION_SINK_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SERVICE_LAYER_EXCEPTION_SINK_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_service_layer_task_exception_sink_findings(parsed_file, rule)
                    )

        if _SERVICE_LAYER_GLOBAL_RESOLUTION_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SERVICE_LAYER_GLOBAL_RESOLUTION_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_service_layer_global_resolution_findings(parsed_file, rule)
                    )

        if _DAEMON_TASK_FAILURE_SINK_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_DAEMON_TASK_FAILURE_SINK_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_daemon_task_without_failure_sink_findings(parsed_file, rule)
                    )

        if _SECRET_FALLBACK_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SECRET_FALLBACK_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_secret_fallback_findings(parsed_file, rule))

        if _EXTERNAL_LITERAL_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_EXTERNAL_LITERAL_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_hardcoded_external_literal_findings(parsed_file, rule)
                    )

        if _DYNAMIC_SQL_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_DYNAMIC_SQL_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_dynamic_sql_findings(parsed_file, rule))

        if _ERROR_RESPONSE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_ERROR_RESPONSE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_request_layer_error_response_findings(parsed_file, rule)
                    )

        if _OUTBOUND_SANITIZATION_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_OUTBOUND_SANITIZATION_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_outbound_html_or_url_sanitization_findings(parsed_file, rule)
                    )

        if _BARE_EXCEPT_CLEANUP_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_BARE_EXCEPT_CLEANUP_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_bare_except_cleanup_findings(parsed_file, rule))

        if _FASTAPI_DTO_ALIAS_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_FASTAPI_DTO_ALIAS_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_public_fastapi_model_alias_findings(parsed_file, rule)
                    )

        if _FASTAPI_DTO_INVARIANT_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_FASTAPI_DTO_INVARIANT_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_public_fastapi_model_invariant_findings(parsed_file, rule)
                    )

        if _REQUEST_JSON_BODY_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_REQUEST_JSON_BODY_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_request_layer_json_body_findings(parsed_file, rule))

        if _STATE_DATETIME_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_STATE_DATETIME_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_state_datetime_findings(parsed_file, rule))

        if _ATOMIC_STATE_WRITE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_ATOMIC_STATE_WRITE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_atomic_state_write_findings(parsed_file, rule))

        if _CREDENTIAL_LOGGING_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_CREDENTIAL_LOGGING_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_sensitive_logging_findings(
                            parsed_file,
                            rule,
                            sensitivity_kind="credential",
                        )
                    )

        if _PII_LOGGING_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_PII_LOGGING_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_sensitive_logging_findings(
                            parsed_file,
                            rule,
                            sensitivity_kind="pii",
                        )
                    )

        if _AI_UNVALIDATED_LLM_OUTPUT_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_AI_UNVALIDATED_LLM_OUTPUT_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_unvalidated_llm_output_findings(parsed_file, rule))

        if _AI_RAW_TOOL_RESPONSE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_AI_RAW_TOOL_RESPONSE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_raw_tool_response_findings(parsed_file, rule))

        if _AI_GENERIC_SESSION_IDENTITY_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_AI_GENERIC_SESSION_IDENTITY_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_generic_session_identity_findings(parsed_file, rule))

        if _AI_MCP_PROCESS_LEAK_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_AI_MCP_PROCESS_LEAK_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_mcp_process_leak_findings(parsed_file, rule))

        if _CORRECTNESS_TIMEOUT_KWARG_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_CORRECTNESS_TIMEOUT_KWARG_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_timeout_kwarg_findings(parsed_file, rule))

        if _SECURITY_WEBHOOK_REPLAY_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SECURITY_WEBHOOK_REPLAY_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_webhook_replay_findings(parsed_file, rule))

        if _RELIABILITY_DB_SSLMODE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_RELIABILITY_DB_SSLMODE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_db_sslmode_findings(parsed_file, rule))

        if _CORRECTNESS_CONTEXT_MANAGER_EXIT_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_CORRECTNESS_CONTEXT_MANAGER_EXIT_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_context_manager_exit_findings(parsed_file, rule))

        if _SECURITY_TENANT_SHARED_WEBHOOK_SECRET_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_SECURITY_TENANT_SHARED_WEBHOOK_SECRET_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_tenant_shared_webhook_secret_findings(parsed_file, rule)
                    )

        if _RELIABILITY_LIFESPAN_CLEANUP_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_RELIABILITY_LIFESPAN_CLEANUP_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_lifespan_cleanup_findings(parsed_file, rule))

        if _RELIABILITY_ORPHANED_ASYNC_TASK_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_RELIABILITY_ORPHANED_ASYNC_TASK_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_orphaned_async_task_findings(parsed_file, rule))

        if _LONG_POLL_READ_TIMEOUT_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_LONG_POLL_READ_TIMEOUT_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(self._find_long_poll_read_timeout_findings(parsed_file, rule))

        if _UNHANDLED_IDEMPOTENT_DUPLICATE_RULE_ID in requested_rule_ids:
            rule = self._registry.get(_UNHANDLED_IDEMPOTENT_DUPLICATE_RULE_ID)
            if rule is not None:
                for parsed_file in parsed_files:
                    findings.extend(
                        self._find_unhandled_idempotent_duplicate_api_response_findings(
                            parsed_file, rule
                        )
                    )

        return tuple(findings)

    def _iter_python_files(self, context: AdapterContext) -> Iterator[_ParsedPythonFile]:
        for relative_path in _candidate_python_files(context):
            file_path = context.repo_root / relative_path
            if not file_path.is_file():
                continue

            try:
                source = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            try:
                module = ast.parse(source, filename=relative_path)
            except SyntaxError:
                continue

            source_lines = tuple(source.splitlines())
            changed_lines = _changed_lines_for_path(
                repo_root=context.repo_root,
                relative_path=relative_path,
                mode=context.mode,
                total_lines=len(source_lines),
            )
            yield _ParsedPythonFile(
                relative_path=relative_path,
                module=module,
                import_aliases=_collect_import_aliases(module.body),
                exported_names=_resolve_exported_names(module),
                changed_lines=changed_lines,
                source_lines=source_lines,
            )

    def _find_public_api_typing_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for callable_node, container_name in _iter_public_api_callables(
            parsed_file.module,
            exported_names=parsed_file.exported_names,
        ):
            signature_lines = _signature_line_range(callable_node)
            if not _lines_intersect(parsed_file.changed_lines, signature_lines):
                continue

            missing_parameters = _missing_parameter_annotations(callable_node)
            missing_return = callable_node.returns is None
            if not missing_parameters and not missing_return:
                continue

            symbol_name = (
                f"{container_name}.{callable_node.name}"
                if container_name is not None
                else callable_node.name
            )
            message = _public_api_message(
                symbol_name=symbol_name,
                missing_parameters=missing_parameters,
                missing_return=missing_return,
            )
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=message,
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=callable_node.lineno,
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Add explicit parameter and return type annotations to the public API."
                    ),
                    metadata={
                        "symbol": symbol_name,
                        "missing_parameters": ",".join(missing_parameters) or "none",
                        "missing_return": "yes" if missing_return else "no",
                    },
                )
            )
        return findings

    def _find_oversized_runtime_function_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if _is_service_layer_python_path(parsed_file.relative_path):
            scope = "service-layer"
            callables = tuple(_iter_runtime_callables(parsed_file.module))
        elif _is_request_async_python_path(parsed_file):
            scope = "request-layer"
            callables = tuple(
                _iter_route_callables(
                    parsed_file.module,
                    aliases=parsed_file.import_aliases,
                )
            )
        else:
            return []

        findings: list[NormalizedFinding] = []
        for callable_node, container_name in callables:
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(callable_node)):
                continue

            line_count = _effective_python_line_count(parsed_file.source_lines, callable_node)
            branch_complexity = _python_branch_complexity(callable_node)
            if (
                line_count <= _PYTHON_OVERSIZED_FUNCTION_LINE_THRESHOLD
                and branch_complexity <= _PYTHON_OVERSIZED_FUNCTION_COMPLEXITY_THRESHOLD
            ):
                continue

            symbol_name = (
                f"{container_name}.{callable_node.name}"
                if container_name is not None
                else callable_node.name
            )
            triggers: list[str] = []
            if line_count > _PYTHON_OVERSIZED_FUNCTION_LINE_THRESHOLD:
                triggers.append(f"{line_count} effective lines")
            if branch_complexity > _PYTHON_OVERSIZED_FUNCTION_COMPLEXITY_THRESHOLD:
                triggers.append(f"branch complexity {branch_complexity}")

            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Python {scope.replace('-', ' ')} callable `{symbol_name}` is oversized "
                        f"({', '.join(triggers)}); split orchestration and branching into "
                        "smaller helpers."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=callable_node.lineno,
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Extract validation, branching, and outbound work into smaller helpers so "
                        "the runtime callable stays easy to review and unit test."
                    ),
                    metadata={
                        "symbol": symbol_name,
                        "scope": scope,
                        "line_count": str(line_count),
                        "branch_complexity": str(branch_complexity),
                        "line_threshold": str(_PYTHON_OVERSIZED_FUNCTION_LINE_THRESHOLD),
                        "complexity_threshold": str(
                            _PYTHON_OVERSIZED_FUNCTION_COMPLEXITY_THRESHOLD
                        ),
                    },
                )
            )
        return findings

    def _find_oversized_runtime_module_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        scope = _oversized_runtime_module_scope(parsed_file)
        if scope is None or not _python_file_has_changed_behavior_lines(parsed_file):
            return []

        line_count = _effective_python_module_line_count(parsed_file.source_lines)
        if line_count <= _PYTHON_OVERSIZED_MODULE_LINE_THRESHOLD:
            return []

        callable_count = sum(1 for _ in _iter_runtime_python_callables(parsed_file.module))
        return [
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Python {scope.replace('-', ' ')} module '{parsed_file.relative_path}' is "
                    f"oversized ({line_count} effective lines); split routes, webhooks, or "
                    "workflow orchestration into smaller modules."
                ),
                location=FindingLocation(path=parsed_file.relative_path, line=1),
                adapter_id=self.adapter_key,
                language=RepoLanguage.PYTHON,
                suggestion=(
                    "Move related handlers, orchestration helpers, or shared runtime flows into "
                    "smaller modules so changed request/service code stays reviewable."
                ),
                metadata={
                    "scope": scope,
                    "line_count": str(line_count),
                    "line_threshold": str(_PYTHON_OVERSIZED_MODULE_LINE_THRESHOLD),
                    "callable_count": str(callable_count),
                },
            )
        ]

    def _find_cyclomatic_hotspot_method_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        scope = _python_reviewable_runtime_scope(parsed_file)
        if scope is None:
            return []

        findings: list[NormalizedFinding] = []
        for callable_node, container_name in _iter_runtime_callables(parsed_file.module):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(callable_node)):
                continue

            line_count = _effective_python_line_count(parsed_file.source_lines, callable_node)
            if line_count < _PYTHON_CYCLOMATIC_HOTSPOT_LINE_THRESHOLD:
                continue

            cyclomatic_score = _python_branch_complexity(callable_node)
            if cyclomatic_score < _PYTHON_CYCLOMATIC_HOTSPOT_SCORE_THRESHOLD:
                continue

            max_nesting = _python_max_control_nesting(callable_node)
            if (
                cyclomatic_score < _PYTHON_CYCLOMATIC_HOTSPOT_HIGH_SCORE_THRESHOLD
                and max_nesting < _PYTHON_CYCLOMATIC_HOTSPOT_NESTING_THRESHOLD
            ):
                continue

            symbol_name = (
                f"{container_name}.{callable_node.name}"
                if container_name is not None
                else callable_node.name
            )
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Python {scope.replace('-', ' ')} callable `{symbol_name}` reaches "
                        f"cyclomatic score {cyclomatic_score} with max nesting {max_nesting}."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=callable_node.lineno,
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Split branch-heavy orchestration into smaller helpers so each runtime "
                        "path is easier to review and test."
                    ),
                    metadata={
                        "symbol": symbol_name,
                        "scope": scope,
                        "cyclomatic_score": str(cyclomatic_score),
                        "line_count": str(line_count),
                        "max_nesting": str(max_nesting),
                    },
                )
            )
        return findings

    def _find_large_runtime_module_without_test_file_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
        *,
        discovered_python_test_paths: frozenset[str],
    ) -> list[NormalizedFinding]:
        scope = _python_reviewable_runtime_scope(parsed_file)
        if scope is None or not _python_file_has_changed_behavior_lines(parsed_file):
            return []

        line_count = _effective_python_module_line_count(parsed_file.source_lines)
        if line_count <= _PYTHON_RUNTIME_MODULE_TEST_LINE_THRESHOLD:
            return []

        callable_count = sum(1 for _ in _iter_runtime_python_callables(parsed_file.module))
        if callable_count == 0:
            return []

        if (
            _find_nearby_python_test_path(
                parsed_file.relative_path,
                discovered_python_test_paths=discovered_python_test_paths,
            )
            is not None
        ):
            return []

        expected_tests = ", ".join(
            _preferred_python_runtime_test_patterns(parsed_file.relative_path)
        )
        suggestion = (
            "Add a dedicated test file for this runtime module before expanding the surface "
            "further."
        )
        if expected_tests:
            suggestion = (
                "Add a dedicated test file for this runtime module before expanding the surface "
                f"further (for example: {expected_tests})."
            )

        return [
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Python {scope.replace('-', ' ')} module '{parsed_file.relative_path}' "
                    f"spans {line_count} effective lines without a nearby dedicated test file."
                ),
                location=FindingLocation(path=parsed_file.relative_path, line=1),
                adapter_id=self.adapter_key,
                language=RepoLanguage.PYTHON,
                suggestion=suggestion,
                metadata={
                    "scope": scope,
                    "line_count": str(line_count),
                    "line_threshold": str(_PYTHON_RUNTIME_MODULE_TEST_LINE_THRESHOLD),
                    "callable_count": str(callable_count),
                    "expected_tests": expected_tests,
                },
            )
        ]

    def _find_untyped_template_catalog_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_untyped_template_catalog_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service-layer template catalog "
                        f"`{match.catalog_name}` needs an explicit type annotation."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Add a concrete annotation for the catalog (for example TypedDict, "
                        "dataclass-backed values, or dict[str, TemplateSpec]) before expanding it."
                    ),
                    metadata={
                        "catalog_name": match.catalog_name,
                        "annotation_kind": "missing-type-annotation",
                    },
                )
            )
        return findings

    def _find_async_blocking_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for async_node, container_name in _iter_async_callables(parsed_file.module):
            visitor = _BlockingCallVisitor(
                aliases={
                    **parsed_file.import_aliases,
                    **_collect_import_aliases(async_node.body),
                }
            )
            for statement in async_node.body:
                visitor.visit(statement)

            async_name = (
                f"{container_name}.{async_node.name}"
                if container_name is not None
                else async_node.name
            )
            for match in visitor.matches:
                if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Blocking call '{match.call_name}' runs inside async function "
                            f"'{async_name}'."
                        ),
                        location=FindingLocation(
                            path=parsed_file.relative_path,
                            line=match.node.lineno,
                            column=match.node.col_offset + 1,
                            end_line=getattr(match.node, "end_lineno", None),
                            end_column=_normalized_end_column(match.node),
                        ),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.PYTHON,
                        suggestion=_blocking_call_suggestion(match.call_name),
                        metadata={
                            "symbol": async_name,
                            "blocking_call": match.call_name,
                        },
                    )
                )
        return findings

    def _find_unbounded_async_lock_pool_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_async_lock_pool_matches(parsed_file):
            if match.has_eviction or match.has_capacity_guard:
                continue
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python runtime/service code lazily grows asyncio lock pool "
                        f"'{match.pool_name}' without any visible eviction or capacity guard."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Bound the per-key lock pool or evict stale keys instead of retaining one "
                        "asyncio.Lock per key indefinitely."
                    ),
                    metadata={
                        "pool_name": match.pool_name,
                        "creation_pattern": match.creation_pattern,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_racy_lock_pool_creation_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_async_lock_pool_matches(parsed_file):
            if match.guarded_by_lock:
                continue
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python runtime/service code lazily creates per-key lock in pool "
                        f"'{match.pool_name}' without an outer guard lock."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Protect lazy lock creation with a dedicated guard lock (for example: "
                        "async with self._locks_lock:) so concurrent callers cannot create "
                        "different locks for the same key."
                    ),
                    metadata={
                        "pool_name": match.pool_name,
                        "creation_pattern": match.creation_pattern,
                        "guard_kind": "missing-outer-lock",
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_sync_db_client_on_async_path_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_sync_db_on_async_path_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python async code uses synchronous database access via "
                        f"'{match.access_pattern}'."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Switch the async path to an async-native database client or move the "
                        "synchronous database work behind asyncio.to_thread(...)."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "usage_kind": match.usage_kind,
                        "symbol": match.symbol or "<async-callable>",
                    },
                )
            )
        return findings

    def _find_unbounded_upload_read_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_unbounded_upload_read_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request/webhook code reads upload "
                        f"'{match.upload_parameter}' fully into memory via "
                        f"'{match.access_pattern}'."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Check the upload size before reading it or stream the body in bounded "
                        "chunks instead of calling await file.read() with no size cap."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "upload_parameter": match.upload_parameter,
                        "symbol": match.symbol or "<request-callable>",
                    },
                )
            )
        return findings

    def _find_webhook_payload_normalization_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_webhook_payload_without_normalization_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python webhook/media handler reads nested raw payload key "
                        f"'{match.payload_key}' via '{match.access_pattern}' without a "
                        "normalization helper."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Normalize nested webhook/media metadata first, then branch on the "
                        "normalized structure instead of the raw payload."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "payload_key": match.payload_key,
                        "symbol": match.symbol or "<handler>",
                    },
                )
            )
        return findings

    def _find_request_layer_env_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_transport_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_env_access_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            rendered_env_name = match.env_name or "<dynamic>"
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request/webhook surface reads environment variable "
                        f"'{rendered_env_name}' directly."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Resolve config or secrets in a shared config/helper layer and inject "
                        "the value into the request surface instead of calling os.getenv(...)."
                    ),
                    metadata={
                        "env_access": match.call_name,
                        "env_name": rendered_env_name,
                    },
                )
            )
        return findings

    def _find_request_layer_file_io_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_transport_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_file_io_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message="Python request-entry surface performs local file I/O directly.",
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Move the local file access behind a storage/helper collaborator and "
                        "call that from the request surface instead of opening files inline."
                    ),
                    metadata={"access_pattern": match.access_pattern},
                )
            )
        return findings

    def _find_request_layer_concrete_dependency_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_transport_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_concrete_dependency_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request-entry surface constructs concrete dependency "
                        f"'{match.constructor_name}' inline."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Create or inject the collaborator at the boundary/bootstrap layer and "
                        "use it from the route handler instead of constructing it inline."
                    ),
                    metadata={
                        "constructor_name": match.constructor_name,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_service_layer_outbound_client_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_service_layer_outbound_client_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service/workflow code constructs outbound client "
                        f"'{match.constructor_name}' inline."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Move outbound client wiring into a dedicated boundary, factory, or "
                        "bootstrap seam and inject it into the service/workflow code."
                    ),
                    metadata={
                        "constructor_name": match.constructor_name,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_service_layer_httpx_timeout_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_service_layer_httpx_timeout_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service/workflow code constructs outbound httpx client "
                        f"'{match.access_pattern}' without explicit client or per-request "
                        "timeout shaping."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Set timeout= on the httpx client itself or pass timeout= on each direct "
                        "request call inside the client context before using it from "
                        "service/workflow code."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "timeout_kind": match.timeout_kind,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_request_layer_global_resolution_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_transport_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_global_resolution_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request-entry surface resolves collaborator from global/context "
                        f"holder '{match.access_pattern}' at runtime."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Resolve the collaborator earlier in bootstrap or boundary wiring and "
                        "pass it into the request surface instead of reading it from global or "
                        "request-context state at runtime."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "resolution_kind": match.resolution_kind,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_request_layer_detached_async_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_request_async_python_path(parsed_file):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_detached_async_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request-entry surface launches detached async task via "
                        f"'{match.access_pattern}' without an explicit await/cancel boundary."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Await the task, return it to a caller-owned lifecycle boundary, or "
                        "explicitly manage and cancel/join it instead of fire-and-forget "
                        "launching it from request code."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "management_kind": match.management_kind,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_request_layer_executor_context_gap_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_request_async_python_path(parsed_file):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_executor_context_gap_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request-entry code hops into an executor via "
                        f"'{match.access_pattern}' without wrapping the call in "
                        "contextvars.copy_context().run."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Wrap executor-dispatched work with contextvars.copy_context().run or "
                        "pass tenant/request state explicitly before hopping out of the request "
                        "task."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "propagation_kind": match.propagation_kind,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_request_layer_task_exception_sink_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_request_async_python_path(parsed_file):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_task_exception_sink_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python request-entry background-task helper consumes "
                        f"'{match.access_pattern}' without any durable failure surface."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Log, capture, or persist task failures explicitly instead of just "
                        "calling task.exception() inside a done-callback helper."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "sink_kind": match.sink_kind,
                        "observability_kind": "log-only-task-exception",
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_service_layer_global_resolution_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_service_layer_global_resolution_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service/workflow code resolves collaborator from global/context "
                        f"holder '{match.access_pattern}' at runtime."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Move the collaborator resolution into bootstrap, factory, or explicit "
                        "boundary wiring and inject it into the service/workflow code."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "resolution_kind": match.resolution_kind,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_user_scoped_runtime_store_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_user_scoped_runtime_store_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python tenant-aware runtime/session store "
                        f"'{match.store_name}' indexes by {match.key_kind} "
                        f"'{match.key_name or '<key>'}' without tenant/org/workspace/project "
                        "scoping."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Scope runtime/session stores by tenant/org/workspace/project before "
                        "indexing them by user, owner, channel, or session ids."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "key_kind": match.key_kind,
                        "key_name": match.key_name or "<dynamic>",
                        "store_name": match.store_name,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_daemon_task_without_failure_sink_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_python_daemon_task_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python background/startup code launches daemon-like async task via "
                        f"'{match.access_pattern}' for '{match.daemon_signal}' without "
                        "add_done_callback supervision or a supervising helper."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Attach add_done_callback-based failure handling or route daemon-style "
                        "tasks through a supervising helper that owns and reports failures."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "daemon_signal": match.daemon_signal,
                        "ownership_kind": match.ownership_kind,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_service_layer_detached_async_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_service_layer_detached_async_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service/workflow code launches detached async task via "
                        f"'{match.access_pattern}' without an explicit await/cancel boundary."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Await the task, return it to a caller-owned lifecycle boundary, or "
                        "explicitly manage and cancel/join it instead of launching detached "
                        "background work from service/workflow code."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "management_kind": match.management_kind,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_service_layer_executor_context_gap_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_service_layer_executor_context_gap_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service/workflow code hops into an executor via "
                        f"'{match.access_pattern}' without wrapping the call in "
                        "contextvars.copy_context().run."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Wrap executor-dispatched work with contextvars.copy_context().run or "
                        "pass tenant/request state explicitly before hopping out of the service "
                        "task."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "propagation_kind": match.propagation_kind,
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_service_layer_task_exception_sink_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_service_layer_task_exception_sink_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python service/workflow background-task helper consumes "
                        f"'{match.access_pattern}' without any durable failure surface."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Log, capture, or persist task failures explicitly instead of just "
                        "calling task.exception() inside a done-callback helper."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "sink_kind": match.sink_kind,
                        "observability_kind": "log-only-task-exception",
                        "symbol": match.symbol or "<callable>",
                    },
                )
            )
        return findings

    def _find_secret_fallback_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_python_env_literal_review_path(parsed_file.relative_path):
            return []
        findings: list[NormalizedFinding] = []
        for match in _iter_env_access_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            if match.env_name is None or match.default_value is None:
                continue
            if not _looks_like_secret_env_name(match.env_name):
                continue
            if _shared_looks_like_placeholder(match.default_value):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python env lookup for secret-like variable "
                        f"'{match.env_name}' embeds a literal fallback value."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Remove the literal secret fallback and source the value from runtime "
                        "configuration or a secret store."
                    ),
                    metadata={
                        "env_access": match.call_name,
                        "env_name": match.env_name,
                    },
                )
            )
        return findings

    def _find_hardcoded_external_literal_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_python_env_literal_review_path(parsed_file.relative_path):
            return []
        findings: list[NormalizedFinding] = []
        for match in _iter_hardcoded_external_literal_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python config/default surface hardcodes "
                        f"{match.literal_kind} literal via '{match.context_name}'."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=match.node.col_offset + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Move the literal into typed runtime configuration, tenant metadata, "
                        "or a tight enum/allowlist instead of hardcoding it in code."
                    ),
                    metadata={
                        "context_name": match.context_name,
                        "literal_kind": match.literal_kind,
                        "literal_value": match.literal_value,
                    },
                )
            )
        return findings

    def _find_dynamic_sql_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_dynamic_sql_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            sql_line = getattr(match.sql_expression, "lineno", match.node.lineno)
            sql_column = getattr(match.sql_expression, "col_offset", match.node.col_offset)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python SQL execution surface "
                        f"'{match.execution_call_name}' receives dynamically constructed SQL "
                        f"via {match.construction_kind}."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=sql_line,
                        column=sql_column + 1,
                        end_line=getattr(match.sql_expression, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.sql_expression),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Use query parameters for values. If identifiers truly must vary, "
                        "map them through a tight allowlist before composing the SQL."
                    ),
                    metadata={
                        "execution_call": match.execution_call_name,
                        "sql_construction": match.construction_kind,
                    },
                )
            )
        return findings

    def _find_sensitive_logging_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
        *,
        sensitivity_kind: str,
    ) -> list[NormalizedFinding]:
        if not _is_runtime_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_sensitive_logging_matches(parsed_file):
            if match.sensitivity_kind != sensitivity_kind:
                continue
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.log_call)):
                continue
            descriptor = (
                "credential-bearing value" if sensitivity_kind == "credential" else "PII value"
            )
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Python runtime log statement emits raw {descriptor} via "
                        f"'{match.identifier_name}'."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.value_node.lineno,
                        column=match.value_node.col_offset + 1,
                        end_line=getattr(match.value_node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.value_node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
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

    def _find_request_layer_error_response_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_error_response_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.detail_node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python route/webhook response exposes raw exception detail via "
                        f"{match.detail_kind}."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.detail_node.lineno,
                        column=getattr(match.detail_node, "col_offset", 0) + 1,
                        end_line=getattr(match.detail_node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.detail_node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Return a stable client-facing error message and log the exception "
                        "detail separately instead of serializing the raw exception into the "
                        "response body."
                    ),
                    metadata={
                        "detail_kind": match.detail_kind,
                        "response_kind": match.response_kind,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_outbound_html_or_url_sanitization_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_service_layer_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for match in _iter_outbound_html_or_url_sanitization_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Outbound HTML/URL content in "
                        f"`{match.symbol}` interpolates raw values without sanitization: "
                        f"{', '.join(match.unsafe_tokens)}."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Validate outbound URLs and HTML-escape interpolated content before "
                        "embedding them into rendered email or CTA markup."
                    ),
                    metadata={
                        "symbol": match.symbol,
                        "unsafe_tokens": ",".join(match.unsafe_tokens),
                    },
                )
            )
        return findings

    def _find_bare_except_cleanup_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_bare_except_cleanup_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.try_node)):
                continue
            cleanup_patterns = ", ".join(match.cleanup_patterns)
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python runtime cleanup block swallows every exception with bare "
                        f"`except:` around '{cleanup_patterns}'."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.handler.lineno,
                        column=match.handler.col_offset + 1,
                        end_line=getattr(match.handler, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.handler),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Catch the expected cleanup failure explicitly (for example "
                        "FileNotFoundError or OSError), or use a targeted suppress/missing_ok "
                        "helper instead of swallowing every exception."
                    ),
                    metadata={
                        "cleanup_patterns": cleanup_patterns,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_public_fastapi_model_alias_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_public_dto_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for model_class, fields in _iter_public_pydantic_model_fields(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(model_class)):
                continue
            missing_alias_fields = [
                field_name
                for field_name, field_node in fields
                if (
                    "_" in field_name
                    and _field_alias_value(field_node, parsed_file.import_aliases) is None
                )
            ]
            if not missing_alias_fields:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Public FastAPI model "
                        f"`{model_class.name}` exposes snake_case field(s) without explicit "
                        f"aliases: {', '.join(missing_alias_fields)}."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=model_class.lineno,
                        column=model_class.col_offset + 1,
                        end_line=getattr(model_class, "end_lineno", None),
                        end_column=_normalized_node_end_column(model_class),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Add Field(alias=...) coverage (and matching model_config) so the public "
                        "FastAPI contract stays explicit and stable."
                    ),
                    metadata={
                        "model": model_class.name,
                        "fields": ",".join(missing_alias_fields),
                    },
                )
            )
        return findings

    def _find_public_fastapi_model_invariant_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        if not _is_public_dto_python_path(parsed_file.relative_path):
            return []

        findings: list[NormalizedFinding] = []
        for model_class, fields in _iter_public_pydantic_model_fields(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(model_class)):
                continue
            discriminator_field = _pydantic_cross_field_invariant_discriminator(fields)
            if discriminator_field is None:
                continue
            if _pydantic_model_has_cross_field_validator(model_class, parsed_file.import_aliases):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Public FastAPI model "
                        f"`{model_class.name}` needs a cross-field validator for "
                        f"`{discriminator_field}`-driven invariants."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=model_class.lineno,
                        column=model_class.col_offset + 1,
                        end_line=getattr(model_class, "end_lineno", None),
                        end_column=_normalized_node_end_column(model_class),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Add a model_validator/field_validator that enforces the payload "
                        "combinations implied by the public DTO discriminator."
                    ),
                    metadata={
                        "model": model_class.name,
                        "discriminator_field": discriminator_field,
                    },
                )
            )
        return findings

    def _find_request_layer_json_body_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_request_layer_json_body_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python route/webhook parses request JSON via "
                        f"{match.access_pattern} without an explicit invalid-JSON guard."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Wrap request.json() in a route-local invalid-body guard or route through "
                        "a shared helper that returns a stable 400 response for malformed JSON."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "guard_kind": match.guard_kind,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_state_datetime_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_state_datetime_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python persistence/event/scheduler state code uses naive datetime access "
                        f"'{match.access_pattern}'."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Use a timezone-aware UTC timestamp (for example: datetime.now(UTC) or "
                        "datetime.now(timezone.utc)) instead of datetime.utcnow() or bare "
                        "datetime.now() in durable state code."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "usage_kind": match.usage_kind,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_atomic_state_write_findings(
        self,
        parsed_file: _ParsedPythonFile,
        rule: RuleDefinition,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_atomic_state_write_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Python webhook/event durable-state code overwrites JSON state via "
                        f"{match.write_pattern} without an atomic temp-file replace."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Persist durable JSON state through JSONStore.write_atomic(...) or a "
                        "same-directory temp file followed by os.replace(...)."
                    ),
                    metadata={
                        "write_pattern": match.write_pattern,
                        "target_name": match.target_name or "<unknown>",
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_unvalidated_llm_output_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_unvalidated_llm_output_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Raw LLM output is forwarded to a customer channel without "
                        f"validation or gating ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Pass LLM output through a validate() or gate() helper before "
                        "sending it to customer-facing channels."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_raw_tool_response_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_raw_tool_response_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Tool response is passed back to the LLM without field stripping "
                        f"or redaction ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Strip internal-only fields with _strip_fields() or a redaction "
                        "helper before returning tool output to the LLM."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_generic_session_identity_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_generic_session_identity_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Generic placeholder session ID '{match.literal_value}' is used "
                        f"for '{match.session_name}' without a unique per-request seed."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Generate a unique session ID per request instead of reusing "
                        "generic placeholders."
                    ),
                    metadata={
                        "session_name": match.session_name,
                        "literal_value": match.literal_value,
                    },
                )
            )
        return findings

    def _find_mcp_process_leak_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_mcp_process_leak_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"MCP session created via '{match.constructor_name}' without "
                        "visible cleanup (atexit, finally, or shared-client recycling)."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Register MCP session cleanup with atexit or wrap creation in "
                        "try/finally, or recycle a shared client."
                    ),
                    metadata={
                        "constructor_name": match.constructor_name,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_timeout_kwarg_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_timeout_kwarg_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Passing 'timeout' to '{match.call_name}' which may not accept it; "
                        "use asyncio.wait_for() instead."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Wrap the async call in asyncio.wait_for(...) instead of passing "
                        "timeout= to a callable that does not declare it."
                    ),
                    metadata={
                        "call_name": match.call_name,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_webhook_replay_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_webhook_replay_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Webhook handler verifies signature but does not validate origin "
                        f"IP ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Add an origin IP check using ipaddress.ip_address().is_global "
                        "or similar before processing webhook payloads."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_db_sslmode_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_db_sslmode_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, getattr(match.node, "lineno", 1)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Database connection string uses 'sslmode=require' combined with "
                        f"verifying TLS context ('{match.literal_value}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Map sslmode=require to TLS without CA validation, or use "
                        "verify-full with a proper CA bundle."
                    ),
                    metadata={
                        "literal_value": match.literal_value,
                    },
                )
            )
        return findings

    def _find_chain_confirmation_external_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_chain_confirmation_external_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Multi-step chain confirmation flow is triggered from an external "
                        f"customer channel ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Move chain confirmation flows to internal channels or add "
                        "strict gating before exposing them on external channels."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_context_manager_exit_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_context_manager_exit_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "__exit__ method does not explicitly return False, which can "
                        "suppress exceptions."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Add 'return False' at the end of __exit__ to ensure exceptions "
                        "are propagated correctly."
                    ),
                    metadata={
                        "symbol": match.symbol or "<class>",
                    },
                )
            )
        return findings

    def _find_commerce_price_leak_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_commerce_price_leak_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, getattr(match.node, "lineno", 1)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Commerce price language detected in customer-facing output "
                        f"('{match.literal_value}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Remove or mask pricing tokens before sending LLM output to "
                        "customer channels."
                    ),
                    metadata={
                        "literal_value": match.literal_value,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_employee_payroll_leak_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_employee_payroll_leak_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, getattr(match.node, "lineno", 1)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Payroll or employee directory language detected in customer-facing "
                        f"output ('{match.literal_value}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Remove or mask payroll and employee data before sending LLM "
                        "output to customer channels."
                    ),
                    metadata={
                        "literal_value": match.literal_value,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_tenant_shared_webhook_secret_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_tenant_shared_webhook_secret_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Webhook verification uses a shared global secret instead of a "
                        f"per-tenant lookup ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Look up the webhook secret per-tenant rather than using a single "
                        "global constant."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_lifespan_cleanup_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_lifespan_cleanup_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "FastAPI lifespan or async context manager lacks a try/finally "
                        f"cleanup guard ('{match.symbol}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Wrap lifespan initialization in try/finally to ensure resources "
                        "are cleaned up on shutdown."
                    ),
                    metadata={
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_orphaned_async_task_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_orphaned_async_task_matches(parsed_file):
            if not _line_in_scope(parsed_file.changed_lines, match.node.lineno):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "WebSocket handler spawns an async task without cancelling it on "
                        f"disconnect ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=match.node.lineno,
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Cancel the async task in a finally block or on disconnect handler."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<route>",
                    },
                )
            )
        return findings

    def _find_retry_counter_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for match in _iter_retry_counter_matches(parsed_file):
            if not _lines_intersect(parsed_file.changed_lines, _node_line_range(match.node)):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Retry logic checks a single reference without aggregating all "
                        f"candidates ('{match.access_pattern}')."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=getattr(match.node, "lineno", 1),
                        column=getattr(match.node, "col_offset", 0) + 1,
                        end_line=getattr(match.node, "end_lineno", None),
                        end_column=_normalized_node_end_column(match.node),
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Aggregate all retry candidates and select the highest attempt "
                        "number instead of relying on a single reference."
                    ),
                    metadata={
                        "access_pattern": match.access_pattern,
                        "symbol": match.symbol or "<module>",
                    },
                )
            )
        return findings

    def _find_long_poll_read_timeout_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        source = "\n".join(parsed_file.source_lines)
        if not _TELEGRAM_POLLING_PATTERN.search(source):
            return []
        if _GET_UPDATES_READ_TIMEOUT_PATTERN.search(source):
            return []
        if not _lines_intersect(
            parsed_file.changed_lines,
            _matching_line_numbers(source, _TELEGRAM_POLLING_PATTERN),
        ):
            return []
        findings: list[NormalizedFinding] = []
        for line_number in _matching_line_numbers(source, _TELEGRAM_POLLING_PATTERN):
            if not _line_in_scope(parsed_file.changed_lines, line_number):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Telegram long polling is configured without get_updates_read_timeout "
                        "exceeding the poll timeout."
                    ),
                    location=FindingLocation(
                        path=parsed_file.relative_path,
                        line=line_number,
                    ),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.PYTHON,
                    suggestion=(
                        "Configure ApplicationBuilder(...).get_updates_read_timeout(...) "
                        "above the polling interval."
                    ),
                    metadata={"matched_pattern": "long-poll-read-timeout-mismatch"},
                )
            )
            break
        return findings

    def _find_unhandled_idempotent_duplicate_api_response_findings(
        self, parsed_file: _ParsedPythonFile, rule: RuleDefinition
    ) -> list[NormalizedFinding]:
        source = "\n".join(parsed_file.source_lines)
        if not _RAISE_FOR_STATUS_PATTERN.search(source):
            return []
        if not _DUPLICATE_ERROR_CODE_CONSTANT_PATTERN.search(source):
            return []
        if not _POST_PUT_HTTP_CALL_PATTERN.search(source):
            return []
        raise_lines = _matching_line_numbers(source, _RAISE_FOR_STATUS_PATTERN)
        handling_lines = _matching_line_numbers(source, _DUPLICATE_ERROR_HANDLING_BRANCH_PATTERN)
        if not raise_lines or not handling_lines:
            return []
        if min(raise_lines) >= min(handling_lines):
            return []
        if not _lines_intersect(parsed_file.changed_lines, raise_lines):
            return []
        findings: list[NormalizedFinding] = []
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "HTTP client calls raise_for_status on POST/PUT before handling "
                    "idempotent duplicate error responses."
                ),
                location=FindingLocation(
                    path=parsed_file.relative_path,
                    line=min(raise_lines),
                ),
                adapter_id=self.adapter_key,
                language=RepoLanguage.PYTHON,
                suggestion=(
                    "Check duplicate/idempotent error codes in 400 responses before "
                    "calling raise_for_status()."
                ),
                metadata={"matched_pattern": "unhandled-idempotent-duplicate-api-response"},
            )
        )
        return findings


def _matching_line_numbers(source: str, pattern: re.Pattern[str]) -> frozenset[int]:
    line_numbers: set[int] = set()
    for match in pattern.finditer(source):
        line_numbers.add(source.count("\n", 0, match.start()) + 1)
    return frozenset(line_numbers)


def _candidate_python_files(context: AdapterContext) -> tuple[str, ...]:
    if context.mode is ExecutionMode.DIFF:
        return tuple(
            path
            for path in context.target_files
            if path.endswith(".py") and not _should_skip_file(path)
        )

    candidates: list[str] = []
    for file_path in sorted(context.repo_root.rglob("*.py")):
        try:
            relative_path = file_path.relative_to(context.repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_file(relative_path):
            continue
        candidates.append(relative_path)
    return tuple(candidates)


def _should_skip_file(relative_path: str) -> bool:
    path = Path(relative_path)
    parts = path.parts
    if any(part in _SKIP_DIRECTORIES for part in parts):
        return True
    name = path.name
    return name.startswith("test_") or name.endswith("_test.py")


def _discover_python_test_paths(repo_root: Path) -> frozenset[str]:
    discovered: set[str] = set()
    for file_path in sorted(repo_root.rglob("*.py")):
        try:
            relative_path = file_path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_python_test_discovery_path(relative_path):
            continue
        if _is_python_test_path(relative_path):
            discovered.add(relative_path)
    return frozenset(discovered)


def _iter_untyped_template_catalog_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_TemplateCatalogMatch]:
    for node in parsed_file.module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if not _looks_like_template_catalog_name(target.id):
            continue
        if not _looks_like_template_catalog_literal(node.value):
            continue
        yield _TemplateCatalogMatch(node=node, catalog_name=target.id)


def _looks_like_template_catalog_name(name: str) -> bool:
    tokens = _split_python_identifier_tokens(name)
    return bool(tokens & _TEMPLATE_CATALOG_NAME_MARKERS)


def _looks_like_template_catalog_literal(node: ast.expr) -> bool:
    if not isinstance(node, ast.Dict) or not node.keys:
        return False
    for key_node, value_node in zip(node.keys, node.values, strict=False):
        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
            return False
        if not isinstance(value_node, ast.Dict) or not value_node.keys:
            return False
        for nested_key in value_node.keys:
            if not isinstance(nested_key, ast.Constant) or not isinstance(nested_key.value, str):
                return False
    return True


def _is_adapter_behavior_module_path(relative_path: str) -> bool:
    path = Path(relative_path)
    markers = _python_path_markers(relative_path)
    return "adapter" in markers or path.stem.lower().endswith("adapters")


def _module_has_adapter_behavior_surface(module: ast.Module) -> bool:
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name.endswith("Adapter"):
            return True
    return False


def _preferred_adapter_test_path(relative_path: str) -> str:
    path = Path(relative_path)
    parent_tokens = [
        part.lower() for part in path.parts[:-1] if part.lower() not in {"src", "__init__"}
    ]
    stem = path.stem.lower()
    base_name = "_".join(token for token in (*parent_tokens[-1:], stem) if token)
    return f"tests/test_{base_name}.py"


def _has_behavior_parity_test(
    relative_path: str, *, discovered_python_test_paths: frozenset[str]
) -> bool:
    preferred_path = _preferred_adapter_test_path(relative_path)
    if preferred_path in discovered_python_test_paths:
        return True
    path_tokens = _python_path_markers(relative_path)
    for test_path in discovered_python_test_paths:
        test_tokens = _python_path_markers(test_path)
        if "adapter" in test_tokens and len(path_tokens & test_tokens) >= 2:
            return True
    return False


def _iter_outbound_html_or_url_sanitization_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_OutboundSanitizationMatch]:
    for callable_node, container_name in _iter_runtime_callables(parsed_file.module):
        symbol_name = (
            f"{container_name}.{callable_node.name}"
            if container_name is not None
            else callable_node.name
        )
        sanitized_names = _collect_outbound_sanitized_names(
            callable_node,
            aliases={**parsed_file.import_aliases, **_collect_nested_import_aliases(callable_node)},
        )
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.JoinedStr):
                continue
            if not _joined_str_has_outbound_markup_or_url_context(node):
                continue
            unsafe_tokens = _unsafe_outbound_formatted_tokens(node, sanitized_names=sanitized_names)
            if unsafe_tokens:
                yield _OutboundSanitizationMatch(
                    node=node,
                    symbol=symbol_name,
                    unsafe_tokens=unsafe_tokens,
                )


def _collect_outbound_sanitized_names(
    callable_node: ast.FunctionDef | ast.AsyncFunctionDef, *, aliases: Mapping[str, str]
) -> frozenset[str]:
    sanitized: set[str] = set()
    for node in ast.walk(callable_node):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None or not _is_sanitized_outbound_expression(value, aliases=aliases):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        for target in targets:
            if isinstance(target, ast.Name):
                sanitized.add(target.id)
    return frozenset(sanitized)


def _joined_str_has_outbound_markup_or_url_context(node: ast.JoinedStr) -> bool:
    literal_chunks = [
        value.value.lower()
        for value in node.values
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    ]
    combined = "".join(literal_chunks)
    return "<a" in combined or "<html" in combined or "href=" in combined or "http" in combined


def _unsafe_outbound_formatted_tokens(
    node: ast.JoinedStr, *, sanitized_names: frozenset[str]
) -> tuple[str, ...]:
    unsafe: list[str] = []
    for value in node.values:
        if not isinstance(value, ast.FormattedValue):
            continue
        if _is_sanitized_outbound_expression(value.value, sanitized_names=sanitized_names):
            continue
        token = _python_expr_simple_label(value.value) or "<expression>"
        unsafe.append(token)
    return tuple(dict.fromkeys(unsafe))


def _is_sanitized_outbound_expression(
    node: ast.expr,
    *,
    sanitized_names: frozenset[str] = frozenset(),
    aliases: Mapping[str, str] | None = None,
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in sanitized_names
    if not isinstance(node, ast.Call):
        return False
    call_name = _resolve_call_name(node.func, aliases or {})
    if call_name in {"html.escape", "escape"}:
        if not node.args:
            return False
        inner_expression = node.args[0]
        if isinstance(inner_expression, ast.Call):
            inner_call_name = _resolve_call_name(inner_expression.func, aliases or {})
            if inner_call_name and ("validate" in inner_call_name or "sanitize" in inner_call_name):
                return True
        return True
    return bool(call_name and ("validate" in call_name or "sanitize" in call_name))


def _is_public_dto_python_path(relative_path: str) -> bool:
    return bool(_python_path_markers(relative_path) & _PUBLIC_DTO_PATH_MARKERS)


def _iter_public_pydantic_model_fields(
    parsed_file: _ParsedPythonFile,
) -> Iterator[tuple[ast.ClassDef, tuple[tuple[str, ast.AnnAssign], ...]]]:
    for node in parsed_file.module.body:
        if not isinstance(node, ast.ClassDef) or not _is_public_name(node.name):
            continue
        if not _class_extends_pydantic_base_model(node, parsed_file.import_aliases):
            continue
        fields = tuple(_iter_pydantic_model_fields(node))
        if fields:
            yield node, fields


def _class_extends_pydantic_base_model(node: ast.ClassDef, aliases: Mapping[str, str]) -> bool:
    for base in node.bases:
        call_name = _resolve_call_name(base, aliases)
        if call_name in {"BaseModel", "pydantic.BaseModel"}:
            return True
    return False


def _iter_pydantic_model_fields(node: ast.ClassDef) -> Iterator[tuple[str, ast.AnnAssign]]:
    for child in node.body:
        if (
            isinstance(child, ast.AnnAssign)
            and isinstance(child.target, ast.Name)
            and _is_public_name(child.target.id)
        ):
            yield child.target.id, child


def _field_alias_value(node: ast.AnnAssign, aliases: Mapping[str, str]) -> str | None:
    value = node.value
    if not isinstance(value, ast.Call):
        return None
    call_name = _resolve_call_name(value.func, aliases)
    if call_name not in {"Field", "pydantic.Field"}:
        return None
    keyword_value = _call_keyword_value(value, "alias")
    if isinstance(keyword_value, ast.Constant) and isinstance(keyword_value.value, str):
        return keyword_value.value
    return None


def _call_keyword_value(node: ast.Call, keyword_name: str) -> ast.expr | None:
    for keyword in node.keywords:
        if keyword.arg == keyword_name:
            return keyword.value
    return None


def _pydantic_model_has_cross_field_validator(
    node: ast.ClassDef, aliases: Mapping[str, str]
) -> bool:
    for child in node.body:
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in child.decorator_list:
            call_name = _resolve_call_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator,
                aliases,
            )
            if call_name in {
                "field_validator",
                "model_validator",
                "pydantic.field_validator",
                "pydantic.model_validator",
                "root_validator",
                "validator",
            }:
                return True
    return False


def _pydantic_cross_field_invariant_discriminator(
    fields: Sequence[tuple[str, ast.AnnAssign]],
) -> str | None:
    field_names = {field_name for field_name, _ in fields}
    if "message_type" in field_names and ({"body", "template_name", "document_url"} & field_names):
        return "message_type"
    if "channel" in field_names and {"customer_phone", "customer_email"} & field_names:
        return "channel"
    return None


def _should_skip_python_test_discovery_path(relative_path: str) -> bool:
    path = Path(relative_path)
    return any(part in _TEST_DISCOVERY_SKIP_DIRECTORIES for part in path.parts)


def _is_python_test_path(relative_path: str) -> bool:
    normalized_parts = tuple(part.lower() for part in Path(relative_path).parts)
    file_name = Path(relative_path).name.lower()
    return (
        file_name.startswith("test_")
        or file_name.endswith("_test.py")
        or "tests" in normalized_parts
        or "__tests__" in normalized_parts
    )


def _collect_import_aliases(statements: Sequence[ast.stmt]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in statements:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _collect_nested_import_aliases(node: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for child in ast.walk(node):
        if isinstance(child, ast.Import):
            for alias in child.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(child, ast.ImportFrom) and child.module is not None:
            for alias in child.names:
                aliases[alias.asname or alias.name] = f"{child.module}.{alias.name}"
    return aliases


def _resolve_exported_names(module: ast.Module) -> frozenset[str] | None:
    exported_names: set[str] = set()
    found_assignment = False
    for node in module.body:
        value = _dunder_all_value(node)
        if value is None:
            continue

        rendered = _string_sequence_literal(value)
        if rendered is None:
            return None
        exported_names.update(rendered)
        found_assignment = True
    if not found_assignment:
        return None
    return frozenset(exported_names)


def _string_sequence_literal(node: ast.expr) -> tuple[str, ...] | None:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return None
        values.append(element.value)
    return tuple(values)


def _dunder_all_value(node: ast.stmt) -> ast.expr | None:
    if isinstance(node, ast.Assign):
        if any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            return node.value
        return None
    if (
        isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "__all__"
    ):
        return node.value
    return None


def _iter_public_api_callables(
    module: ast.Module, *, exported_names: frozenset[str] | None
) -> Iterator[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]]:
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_public_symbol(
            node.name, exported_names
        ):
            yield node, None
            continue
        if not isinstance(node, ast.ClassDef) or not _is_public_symbol(node.name, exported_names):
            continue
        for class_body_node in node.body:
            if isinstance(
                class_body_node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and _is_public_name(class_body_node.name):
                yield class_body_node, node.name


def _iter_runtime_callables(
    module: ast.Module,
) -> Iterator[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]]:
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node, None
            continue
        if not isinstance(node, ast.ClassDef):
            continue
        for class_body_node in node.body:
            if isinstance(class_body_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield class_body_node, node.name


def _iter_async_callables(
    module: ast.Module,
) -> Iterator[tuple[ast.AsyncFunctionDef, str | None]]:
    for node in module.body:
        if isinstance(node, ast.AsyncFunctionDef):
            yield node, None
            continue
        if not isinstance(node, ast.ClassDef):
            continue
        for class_body_node in node.body:
            if isinstance(class_body_node, ast.AsyncFunctionDef):
                yield class_body_node, node.name


def _iter_route_callables(
    module: ast.Module, *, aliases: Mapping[str, str]
) -> Iterator[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]]:
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            _is_route_decorator(decorator, aliases) for decorator in node.decorator_list
        ):
            yield node, None
            continue
        if not isinstance(node, ast.ClassDef):
            continue
        for class_body_node in node.body:
            if isinstance(class_body_node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                _is_route_decorator(decorator, aliases)
                for decorator in class_body_node.decorator_list
            ):
                yield class_body_node, node.name


def _is_public_symbol(name: str, exported_names: frozenset[str] | None) -> bool:
    if exported_names is not None:
        return name in exported_names
    return _is_public_name(name)


def _is_public_name(name: str) -> bool:
    return not name.startswith("_")


def _missing_parameter_annotations(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    missing: list[str] = []
    for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
        if argument.arg in {"self", "cls"}:
            continue
        if argument.annotation is None:
            missing.append(argument.arg)
    if node.args.vararg is not None and node.args.vararg.annotation is None:
        missing.append(f"*{node.args.vararg.arg}")
    if node.args.kwarg is not None and node.args.kwarg.annotation is None:
        missing.append(f"**{node.args.kwarg.arg}")
    return tuple(missing)


def _public_api_message(
    *, symbol_name: str, missing_parameters: Sequence[str], missing_return: bool
) -> str:
    message = f"Public API '{symbol_name}' is missing explicit "
    if missing_parameters and missing_return:
        return (
            f"{message}annotations for parameter(s): {', '.join(missing_parameters)} "
            "and its return type."
        )
    if missing_parameters:
        return f"{message}annotations for parameter(s): {', '.join(missing_parameters)}."
    return f"{message}return type annotation."


def _signature_line_range(node: ast.FunctionDef | ast.AsyncFunctionDef) -> range:
    if not node.body:
        return range(node.lineno, node.lineno + 1)
    first_body_line = node.body[0].lineno
    signature_end = node.lineno if first_body_line == node.lineno else first_body_line - 1
    return range(node.lineno, signature_end + 1)


def _resolve_call_name(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base_name = _resolve_call_name(node.value, aliases)
        if base_name is None:
            return None
        return f"{base_name}.{node.attr}"
    return None


def _python_access_path(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base_name = _python_access_path(node.value)
        if base_name is None:
            return None
        return f"{base_name}.{node.attr}"
    return None


def _python_expr_simple_label(node: ast.expr | None) -> str | None:
    access_path = _python_access_path(node)
    if access_path is not None:
        return access_path
    if isinstance(node, ast.Subscript):
        base_label = _python_expr_simple_label(node.value)
        key_label = _python_expr_simple_label(node.slice)
        if base_label is None or key_label is None:
            return None
        return f"{base_label}[{key_label}]"
    if isinstance(node, ast.Tuple):
        labels = tuple(_python_expr_simple_label(element) for element in node.elts)
        if any(label is None for label in labels):
            return None
        return f"({', '.join(label for label in labels if label is not None)})"
    return None


def _normalize_python_async_launch_call_name(call_name: str | None) -> str | None:
    if call_name is None:
        return None
    if call_name in _ASYNC_TASK_LAUNCH_CALL_NAMES:
        return call_name
    if call_name.endswith(".create_task") or call_name.endswith(".ensure_future"):
        return call_name
    return None


def _python_parent_map(root: ast.AST) -> dict[ast.AST, ast.AST]:
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(root):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    return parent_map


def _python_ancestor_nodes(
    node: ast.AST, parent_map: Mapping[ast.AST, ast.AST]
) -> Iterator[ast.AST]:
    current = parent_map.get(node)
    while current is not None:
        yield current
        current = parent_map.get(current)


def _python_detached_async_management_kind(
    *,
    node: ast.Call,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_map: Mapping[ast.AST, ast.AST],
    aliases: Mapping[str, str],
) -> str | None:
    ancestors = tuple(_python_ancestor_nodes(node, parent_map))
    if any(isinstance(ancestor, (ast.Await, ast.Return)) for ancestor in ancestors):
        return None

    parent = parent_map.get(node)
    if isinstance(parent, ast.Assign):
        if len(parent.targets) != 1:
            return "detached-async-assignment"
        target = parent.targets[0]
        if isinstance(target, ast.Name):
            if _python_task_name_has_explicit_management(
                scope_node=scope_node,
                task_name=target.id,
                aliases=aliases,
            ):
                return None
            return "local-task-without-await"
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            return None
        return "detached-async-assignment"

    if isinstance(parent, ast.AnnAssign):
        if isinstance(parent.target, ast.Name):
            if _python_task_name_has_explicit_management(
                scope_node=scope_node,
                task_name=parent.target.id,
                aliases=aliases,
            ):
                return None
            return "local-task-without-await"
        if isinstance(parent.target, (ast.Attribute, ast.Subscript)):
            return None
        return "detached-async-assignment"

    if isinstance(parent, ast.Expr):
        return "fire-and-forget"

    if any(
        isinstance(ancestor, ast.Call)
        and _resolve_call_name(ancestor.func, aliases) in _ASYNC_TASK_MANAGEMENT_CALL_NAMES
        for ancestor in ancestors
    ):
        return None

    return "detached-task-passed-through"


def _python_task_name_has_explicit_management(
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    task_name: str,
    aliases: Mapping[str, str],
) -> bool:
    for child in ast.walk(scope_node):
        if (
            isinstance(child, ast.Assign)
            and any(isinstance(target, (ast.Attribute, ast.Subscript)) for target in child.targets)
            and (_python_expr_mentions_name(child.value, task_name))
        ):
            return True

        if (
            isinstance(child, ast.AnnAssign)
            and isinstance(child.target, (ast.Attribute, ast.Subscript))
            and _python_expr_mentions_name(child.value, task_name)
        ):
            return True

        if isinstance(child, ast.Return) and _python_expr_mentions_name(child.value, task_name):
            return True

        if isinstance(child, ast.Await):
            awaited_value = child.value
            if isinstance(awaited_value, ast.Name) and awaited_value.id == task_name:
                return True
            if isinstance(awaited_value, ast.Call):
                awaited_call_name = _resolve_call_name(awaited_value.func, aliases)
                if awaited_call_name in _ASYNC_TASK_MANAGEMENT_CALL_NAMES and any(
                    _python_expr_mentions_name(argument, task_name)
                    for argument in (
                        *awaited_value.args,
                        *(keyword.value for keyword in awaited_value.keywords),
                    )
                ):
                    return True

        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id == task_name
            and child.func.attr == "cancel"
        ):
            return True
    return False


def _python_expr_mentions_name(node: ast.AST | None, name: str) -> bool:
    if node is None:
        return False
    return any(isinstance(child, ast.Name) and child.id == name for child in ast.walk(node))


def _python_user_scoped_runtime_store_match_from_subscript(
    *, node: ast.Subscript, symbol: str
) -> _UserScopedRuntimeStoreMatch | None:
    store_name = _python_access_path(node.value)
    if store_name is None or not _looks_like_python_user_scoped_runtime_store_name(store_name):
        return None
    key_kind = _python_user_scoped_store_key_kind(node.slice)
    if key_kind is None:
        return None
    key_name = _python_expr_simple_label(node.slice)
    access_pattern = f"{store_name}[{key_name or '<key>'}]"
    return _UserScopedRuntimeStoreMatch(
        node=node,
        access_pattern=access_pattern,
        store_name=store_name,
        key_name=key_name,
        key_kind=key_kind,
        symbol=symbol,
    )


def _python_user_scoped_runtime_store_match_from_call(
    *, node: ast.Call, symbol: str
) -> _UserScopedRuntimeStoreMatch | None:
    if (
        not isinstance(node.func, ast.Attribute)
        or node.func.attr not in _USER_SCOPED_RUNTIME_STORE_ACCESS_METHODS
    ):
        return None
    store_name = _python_access_path(node.func.value)
    if store_name is None or not _looks_like_python_user_scoped_runtime_store_name(store_name):
        return None
    key_node = node.args[0] if node.args else None
    if key_node is None:
        return None
    key_kind = _python_user_scoped_store_key_kind(key_node)
    if key_kind is None:
        return None
    return _UserScopedRuntimeStoreMatch(
        node=node,
        access_pattern=f"{store_name}.{node.func.attr}",
        store_name=store_name,
        key_name=_python_expr_simple_label(key_node),
        key_kind=key_kind,
        symbol=symbol,
    )


def _python_daemon_task_ownership(
    node: ast.Call, parent_map: Mapping[ast.AST, ast.AST]
) -> tuple[ast.expr, str] | None:
    parent = parent_map.get(node)
    if isinstance(parent, ast.Assign):
        if len(parent.targets) != 1:
            return None
        target = parent.targets[0]
    elif isinstance(parent, ast.AnnAssign):
        target = parent.target
    else:
        return None
    if isinstance(target, ast.Attribute):
        return target, "attribute-owned-task"
    if isinstance(target, ast.Subscript):
        return target, "mapping-owned-task"
    return None


def _python_daemon_task_signal(
    *, node: ast.Call, aliases: Mapping[str, str], task_target: ast.expr
) -> str | None:
    coroutine_node = node.args[0] if node.args else _keyword_argument(node, "coro")
    signal_tokens = _python_ast_identifier_tokens(coroutine_node, include_string_literals=True)
    if isinstance(coroutine_node, ast.Call):
        signal_tokens |= _split_python_identifier_tokens(
            _resolve_call_name(coroutine_node.func, aliases) or ""
        )
    task_name = _constant_string_argument(_keyword_argument(node, "name"))
    if task_name is not None:
        signal_tokens |= _split_python_identifier_tokens(task_name)
    target_label = _python_expr_simple_label(task_target)
    if target_label is not None:
        signal_tokens |= _split_python_identifier_tokens(target_label)
    return _python_first_matching_token(signal_tokens, _DAEMON_TASK_SIGNAL_MARKERS)


def _python_daemon_task_has_supervision(
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    task_target: ast.expr,
    launch_node: ast.Call,
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> bool:
    for candidate in ast.walk(scope_node):
        if not isinstance(candidate, ast.Call) or candidate is launch_node:
            continue
        if _is_python_nested_scope_node(candidate, scope_node, parent_map):
            continue
        if (
            isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr == "add_done_callback"
            and _python_ast_equivalent(candidate.func.value, task_target)
        ):
            return True
        call_name = _resolve_call_name(candidate.func, aliases)
        if call_name is None:
            continue
        call_tokens = _split_python_identifier_tokens(call_name)
        if not call_tokens & _DAEMON_TASK_SUPERVISION_CALL_MARKERS:
            continue
        if any(
            _python_ast_equivalent(argument, task_target)
            for argument in (*candidate.args, *(keyword.value for keyword in candidate.keywords))
        ):
            return True
    return False


def _constant_string_argument(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword_argument(node: ast.Call, name: str) -> ast.expr | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _normalize_env_access_name(call_name: str | None) -> str | None:
    if call_name in _ENV_ACCESS_CALL_NAMES:
        return call_name
    if call_name in {"getenv", "environ.get", "environ.__getitem__"}:
        return call_name
    return None


def _python_env_access_match_from_call(
    node: ast.Call, aliases: Mapping[str, str]
) -> _EnvAccessMatch | None:
    raw_call_name = _resolve_call_name(node.func, aliases)
    call_name = _normalize_env_access_name(raw_call_name)
    if call_name is None:
        return None
    env_name = _constant_string_argument(node.args[0]) if node.args else None
    default_value = None
    default_node: ast.expr | None = None
    if len(node.args) >= 2:
        default_node = node.args[1]
        default_value = _constant_string_argument(default_node)
    elif call_name.endswith(".get") or call_name.endswith("getenv"):
        default_node = _keyword_argument(node, "default")
        default_value = _constant_string_argument(default_node)
    return _EnvAccessMatch(
        node=node,
        call_name=call_name,
        env_name=env_name,
        default_value=default_value,
        default_node=default_node,
    )


def _python_find_env_access_in_expression(
    node: ast.expr, aliases: Mapping[str, str]
) -> _EnvAccessMatch | None:
    if isinstance(node, ast.Call):
        direct_match = _python_env_access_match_from_call(node, aliases)
        if direct_match is not None:
            return direct_match
        if isinstance(node.func, ast.Attribute):
            return _python_find_env_access_in_expression(node.func.value, aliases)
        return None
    if isinstance(node, ast.Attribute):
        return _python_find_env_access_in_expression(node.value, aliases)
    if isinstance(node, ast.Subscript):
        return _python_find_env_access_in_expression(node.value, aliases)
    return None


def _python_env_access_fallback_match(
    node: ast.BoolOp, aliases: Mapping[str, str]
) -> _EnvAccessMatch | None:
    if not isinstance(node.op, ast.Or) or len(node.values) < 2:
        return None
    default_node = node.values[-1]
    default_value = _constant_string_argument(default_node)
    if default_value is None:
        return None
    for candidate in node.values[:-1]:
        env_match = _python_find_env_access_in_expression(candidate, aliases)
        if env_match is None:
            continue
        return _EnvAccessMatch(
            node=node,
            call_name=env_match.call_name,
            env_name=env_match.env_name,
            default_value=default_value,
            default_node=default_node,
        )
    return None


def _iter_env_access_matches(parsed_file: _ParsedPythonFile) -> Iterator[_EnvAccessMatch]:
    for node in ast.walk(parsed_file.module):
        if isinstance(node, ast.Call):
            match = _python_env_access_match_from_call(node, parsed_file.import_aliases)
            if match is not None:
                yield match
            continue
        if isinstance(node, ast.BoolOp):
            match = _python_env_access_fallback_match(node, parsed_file.import_aliases)
            if match is not None:
                yield match


def _iter_request_layer_file_io_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_RequestFileIOMatch]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.Call):
            continue
        call_name = _resolve_call_name(node.func, parsed_file.import_aliases)
        if call_name in _REQUEST_FILE_IO_CALL_NAMES:
            yield _RequestFileIOMatch(node=node, access_pattern=call_name)
            continue
        path_access_pattern = _path_file_io_access_pattern(node, parsed_file.import_aliases)
        if path_access_pattern is None:
            continue
        yield _RequestFileIOMatch(node=node, access_pattern=path_access_pattern)


def _iter_request_layer_concrete_dependency_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ConcreteDependencyMatch]:
    for route_function in _iter_route_functions(parsed_file):
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, parsed_file.import_aliases)
            if not _is_python_dependency_boundary_call(call_name, outbound_only=False):
                continue
            yield _ConcreteDependencyMatch(
                node=node,
                constructor_name=call_name or "<dynamic>",
                symbol=route_function.name,
            )


def _iter_service_layer_outbound_client_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ConcreteDependencyMatch]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.Call):
            continue
        call_name = _resolve_call_name(node.func, parsed_file.import_aliases)
        if not _is_python_dependency_boundary_call(call_name, outbound_only=True):
            continue
        yield _ConcreteDependencyMatch(
            node=node,
            constructor_name=call_name or "<dynamic>",
            symbol=_enclosing_python_symbol(parsed_file.module, node),
        )


def _iter_service_layer_httpx_timeout_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_HttpxTimeoutMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(callable_node),
        }
        parent_map = _python_parent_map(callable_node)
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Call):
                continue
            if _is_python_nested_scope_node(node, callable_node, parent_map):
                continue
            call_name = _resolve_call_name(node.func, aliases)
            if call_name not in _HTTPX_CLIENT_CALL_NAMES:
                continue
            if _python_call_has_non_none_keyword(node, "timeout"):
                continue
            if _python_httpx_context_manager_calls_have_timeout_shaping(
                node=node,
                scope_node=callable_node,
                parent_map=parent_map,
            ):
                continue
            yield _HttpxTimeoutMatch(
                node=node,
                access_pattern=call_name,
                timeout_kind="missing-timeout-shaping",
                symbol=callable_node.name,
            )


def _iter_request_layer_detached_async_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_AsyncLaunchMatch]:
    yield from _iter_python_detached_async_matches(parsed_file)


def _iter_service_layer_detached_async_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_AsyncLaunchMatch]:
    yield from _iter_python_detached_async_matches(parsed_file)


def _iter_request_layer_executor_context_gap_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ContextPropagationMatch]:
    yield from _iter_python_executor_context_gap_matches(parsed_file)


def _iter_service_layer_executor_context_gap_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ContextPropagationMatch]:
    yield from _iter_python_executor_context_gap_matches(parsed_file)


def _iter_request_layer_task_exception_sink_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_TaskExceptionSinkMatch]:
    yield from _iter_python_task_exception_sink_matches(parsed_file)


def _iter_service_layer_task_exception_sink_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_TaskExceptionSinkMatch]:
    yield from _iter_python_task_exception_sink_matches(parsed_file)


def _iter_user_scoped_runtime_store_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_UserScopedRuntimeStoreMatch]:
    if not _is_runtime_python_path(parsed_file.relative_path):
        return
    for callable_node, container_name in _iter_runtime_callables(parsed_file.module):
        context_tokens = _python_runtime_callable_context_tokens(
            parsed_file.relative_path,
            callable_name=callable_node.name,
            container_name=container_name,
        )
        if not context_tokens & _USER_SCOPED_RUNTIME_STORE_SCOPE_MARKERS:
            continue
        scope_tokens = context_tokens | _python_scope_identifier_tokens(callable_node)
        if not scope_tokens & _TENANT_SCOPE_MARKERS:
            continue
        parent_map = _python_parent_map(callable_node)
        for node in ast.walk(callable_node):
            if _is_python_nested_scope_node(node, callable_node, parent_map):
                continue
            if isinstance(node, ast.Subscript):
                match = _python_user_scoped_runtime_store_match_from_subscript(
                    node=node,
                    symbol=callable_node.name,
                )
            elif isinstance(node, ast.Call):
                match = _python_user_scoped_runtime_store_match_from_call(
                    node=node,
                    symbol=callable_node.name,
                )
            else:
                continue
            if match is not None:
                yield match


def _iter_python_detached_async_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_AsyncLaunchMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(callable_node),
        }
        task_group_aliases = _collect_python_task_group_aliases(callable_node, aliases)
        yield from _iter_python_detached_async_matches_for_scope(
            scope_node=callable_node,
            aliases=aliases,
            task_group_aliases=task_group_aliases,
            symbol=callable_node.name,
        )


def _iter_python_detached_async_matches_for_scope(
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
    task_group_aliases: frozenset[str],
    symbol: str,
) -> Iterator[_AsyncLaunchMatch]:
    parent_map = _python_parent_map(scope_node)
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Call):
            continue
        root_name = _root_python_name(node.func)
        if root_name in task_group_aliases:
            continue
        access_pattern = _normalize_python_async_launch_call_name(
            _resolve_call_name(node.func, aliases)
        )
        if access_pattern is None:
            continue
        management_kind = _python_detached_async_management_kind(
            node=node,
            scope_node=scope_node,
            parent_map=parent_map,
            aliases=aliases,
        )
        if management_kind is None:
            continue
        yield _AsyncLaunchMatch(
            node=node,
            access_pattern=access_pattern,
            management_kind=management_kind,
            symbol=symbol,
        )


def _iter_python_daemon_task_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_DaemonTaskMatch]:
    if not _is_runtime_python_path(parsed_file.relative_path) or _is_request_async_python_path(
        parsed_file
    ):
        return
    for callable_node, container_name in _iter_runtime_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(callable_node),
        }
        parent_map = _python_parent_map(callable_node)
        context_tokens = _python_runtime_callable_context_tokens(
            parsed_file.relative_path,
            callable_name=callable_node.name,
            container_name=container_name,
        )
        if not context_tokens & _DAEMON_TASK_CONTEXT_MARKERS:
            continue
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Call):
                continue
            if _is_python_nested_scope_node(node, callable_node, parent_map):
                continue
            access_pattern = _normalize_python_async_launch_call_name(
                _resolve_call_name(node.func, aliases)
            )
            if access_pattern is None:
                continue
            ownership = _python_daemon_task_ownership(node, parent_map)
            if ownership is None:
                continue
            task_target, ownership_kind = ownership
            daemon_signal = _python_daemon_task_signal(
                node=node,
                aliases=aliases,
                task_target=task_target,
            )
            if daemon_signal is None:
                continue
            if _python_daemon_task_has_supervision(
                scope_node=callable_node,
                task_target=task_target,
                launch_node=node,
                aliases=aliases,
                parent_map=parent_map,
            ):
                continue
            yield _DaemonTaskMatch(
                node=node,
                access_pattern=access_pattern,
                daemon_signal=daemon_signal,
                ownership_kind=ownership_kind,
                symbol=callable_node.name,
            )


def _iter_python_executor_context_gap_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ContextPropagationMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(callable_node),
        }
        copy_context_aliases = _collect_python_copy_context_aliases(callable_node, aliases)
        yield from _iter_python_executor_context_gap_matches_for_scope(
            scope_node=callable_node,
            aliases=aliases,
            copy_context_aliases=copy_context_aliases,
            symbol=callable_node.name,
        )


def _iter_python_executor_context_gap_matches_for_scope(
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
    copy_context_aliases: frozenset[str],
    symbol: str,
) -> Iterator[_ContextPropagationMatch]:
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Call):
            continue
        call_name = _resolve_call_name(node.func, aliases)
        if call_name is None:
            continue
        if not (call_name in _EXECUTOR_HOP_CALL_NAMES or call_name.endswith(".run_in_executor")):
            continue
        if _python_run_in_executor_uses_context_copy(node, aliases, copy_context_aliases):
            continue
        yield _ContextPropagationMatch(
            node=node,
            access_pattern=call_name,
            propagation_kind="missing-copy-context",
            symbol=symbol,
        )


def _iter_python_task_exception_sink_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_TaskExceptionSinkMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        for scope_node in _iter_python_observability_callables(callable_node):
            aliases = {
                **parsed_file.import_aliases,
                **_collect_nested_import_aliases(scope_node),
            }
            param_names = _python_callable_parameter_names(scope_node)
            if not param_names:
                continue
            parent_map = _python_parent_map(scope_node)
            if _python_scope_has_durable_background_surface(
                scope_node=scope_node,
                aliases=aliases,
                parent_map=parent_map,
            ):
                continue
            for node in ast.walk(scope_node):
                if not isinstance(node, ast.Call):
                    continue
                if _is_python_nested_scope_node(node, scope_node, parent_map):
                    continue
                if not _is_python_task_exception_sink_call(
                    node=node,
                    aliases=aliases,
                    parent_map=parent_map,
                    param_names=param_names,
                ):
                    continue
                access_pattern = _resolve_call_name(node.func, aliases) or "task.exception"
                yield _TaskExceptionSinkMatch(
                    node=node,
                    access_pattern=access_pattern,
                    sink_kind="task-exception-consumed",
                    symbol=scope_node.name,
                )


def _collect_python_task_group_aliases(
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
) -> frozenset[str]:
    task_group_aliases: set[str] = set()
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.AsyncWith):
            continue
        for item in node.items:
            if not isinstance(item.optional_vars, ast.Name):
                continue
            context_name = _resolve_call_name(item.context_expr, aliases)
            if context_name is None and isinstance(item.context_expr, ast.Call):
                context_name = _resolve_call_name(item.context_expr.func, aliases)
            if context_name in {"TaskGroup", "asyncio.TaskGroup"} or (
                context_name is not None and context_name.endswith(".TaskGroup")
            ):
                task_group_aliases.add(item.optional_vars.id)
    return frozenset(task_group_aliases)


def _collect_python_copy_context_aliases(
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
) -> frozenset[str]:
    context_aliases: set[str] = set()
    for node in ast.walk(scope_node):
        if isinstance(node, ast.Assign):
            if not _is_python_copy_context_call(node.value, aliases):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    context_aliases.add(target.id)
            continue
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and _is_python_copy_context_call(node.value, aliases)
        ):
            context_aliases.add(node.target.id)
    return frozenset(context_aliases)


def _python_run_in_executor_uses_context_copy(
    node: ast.Call,
    aliases: Mapping[str, str],
    copy_context_aliases: frozenset[str],
) -> bool:
    callable_arg = node.args[1] if len(node.args) >= 2 else _keyword_argument(node, "func")
    return _is_python_copy_context_runner(callable_arg, aliases, copy_context_aliases)


def _is_python_copy_context_runner(
    node: ast.expr | None,
    aliases: Mapping[str, str],
    copy_context_aliases: frozenset[str],
) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != "run":
        return False
    receiver = node.value
    if isinstance(receiver, ast.Name):
        return receiver.id in copy_context_aliases
    return isinstance(receiver, ast.Call) and _is_python_copy_context_call(receiver, aliases)


def _is_python_copy_context_call(node: ast.expr | None, aliases: Mapping[str, str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    call_name = _resolve_call_name(node.func, aliases)
    return call_name in _COPY_CONTEXT_CALL_NAMES and not node.args and not node.keywords


def _is_python_task_exception_sink_call(
    *,
    node: ast.Call,
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
    param_names: frozenset[str],
) -> bool:
    if node.args or node.keywords:
        return False
    if not isinstance(parent_map.get(node), ast.Expr):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "exception":
        return False
    root_name = _root_python_name(node.func)
    if root_name is None or root_name not in param_names:
        return False
    call_name = _resolve_call_name(node.func, aliases)
    return call_name is None or call_name.endswith(".exception")


def _iter_python_non_nested_returns(
    node: ast.ExceptHandler,
    parent_map: Mapping[ast.AST, ast.AST],
) -> Iterator[ast.Return]:
    for descendant in ast.walk(node):
        if not isinstance(descendant, ast.Return) or descendant.value is None:
            continue
        if _is_python_nested_scope_node(descendant, node, parent_map):
            continue
        yield descendant


def _python_node_position(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", -1), getattr(node, "col_offset", -1))


def _python_local_name_assignment_before(
    *,
    name: str,
    scope_node: ast.AST,
    parent_map: Mapping[ast.AST, ast.AST],
    before_node: ast.AST,
) -> ast.expr | None:
    latest_assignment: tuple[tuple[int, int], ast.expr] | None = None
    for candidate in ast.walk(scope_node):
        if _is_python_nested_scope_node(candidate, scope_node, parent_map):
            continue
        if isinstance(candidate, ast.Assign):
            if name not in (
                target.id for target in candidate.targets if isinstance(target, ast.Name)
            ):
                continue
            value = candidate.value
        elif isinstance(candidate, ast.AnnAssign):
            if not isinstance(candidate.target, ast.Name) or candidate.target.id != name:
                continue
            value = candidate.value
        else:
            continue
        if value is None or _python_node_position(candidate) >= _python_node_position(before_node):
            continue
        candidate_position = _python_node_position(candidate)
        if latest_assignment is None or candidate_position > latest_assignment[0]:
            latest_assignment = (candidate_position, value)
    return None if latest_assignment is None else latest_assignment[1]


def _python_resolve_local_name_once(
    node: ast.expr,
    *,
    scope_node: ast.AST,
    parent_map: Mapping[ast.AST, ast.AST],
    before_node: ast.AST,
    name_filter: Callable[[str], bool] | None = None,
) -> ast.expr:
    if not isinstance(node, ast.Name):
        return node
    if name_filter is not None and not name_filter(node.id):
        return node
    return (
        _python_local_name_assignment_before(
            name=node.id,
            scope_node=scope_node,
            parent_map=parent_map,
            before_node=before_node,
        )
        or node
    )


def _python_enclosing_local_scope(
    node: ast.AST, module: ast.Module, parent_map: Mapping[ast.AST, ast.AST]
) -> ast.AST:
    current = parent_map.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parent_map.get(current)
    return module


def _python_exception_detail_access_kind(node: ast.expr, exc_name: str) -> str | None:
    if _python_is_exception_name(node, exc_name):
        return exc_name
    if (
        isinstance(node, ast.Attribute)
        and node.attr in _EXCEPTION_DETAIL_ATTRIBUTE_NAMES
        and _python_is_exception_name(node.value, exc_name)
    ):
        return f"{exc_name}.{node.attr}"
    if not isinstance(node, ast.Subscript):
        return None
    if not (
        isinstance(node.value, ast.Attribute)
        and node.value.attr == "args"
        and _python_is_exception_name(node.value.value, exc_name)
    ):
        return None
    if isinstance(node.slice, ast.Constant) and node.slice.value == 0:
        return f"{exc_name}.args[0]"
    return None


def _python_response_error_detail_match(
    node: ast.expr,
    *,
    exc_name: str,
    aliases: Mapping[str, str],
    scope_node: ast.AST,
    parent_map: Mapping[ast.AST, ast.AST],
    before_node: ast.AST,
    allow_local_resolution: bool = True,
) -> tuple[ast.AST, str] | None:
    if allow_local_resolution:
        resolved_node = _python_resolve_local_name_once(
            node,
            scope_node=scope_node,
            parent_map=parent_map,
            before_node=before_node,
        )
        if resolved_node is not node:
            return _python_response_error_detail_match(
                resolved_node,
                exc_name=exc_name,
                aliases=aliases,
                scope_node=scope_node,
                parent_map=parent_map,
                before_node=before_node,
                allow_local_resolution=False,
            )
    detail_kind = _python_exception_detail_access_kind(node, exc_name)
    if detail_kind is not None:
        return node, detail_kind
    if isinstance(node, ast.Call):
        call_name = _resolve_call_name(node.func, aliases)
        if call_name == "str" and len(node.args) == 1:
            detail_arg = _python_resolve_local_name_once(
                node.args[0],
                scope_node=scope_node,
                parent_map=parent_map,
                before_node=before_node,
            )
            detail_kind = _python_exception_detail_access_kind(detail_arg, exc_name)
            if detail_kind is not None:
                if detail_kind == exc_name:
                    return node, "str(exc)"
                return node, f"str({detail_kind})"
        for argument in node.args:
            nested = _python_response_error_detail_match(
                argument,
                exc_name=exc_name,
                aliases=aliases,
                scope_node=scope_node,
                parent_map=parent_map,
                before_node=before_node,
            )
            if nested is not None:
                return nested
        for keyword in node.keywords:
            nested = _python_response_error_detail_match(
                keyword.value,
                exc_name=exc_name,
                aliases=aliases,
                scope_node=scope_node,
                parent_map=parent_map,
                before_node=before_node,
            )
            if nested is not None:
                return nested
        return None
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            if _python_fstring_is_exception_detail(value.value, exc_name, aliases):
                return value, "f-string exception interpolation"
        return None
    if isinstance(node, ast.BinOp):
        left = _python_response_error_detail_match(
            node.left,
            exc_name=exc_name,
            aliases=aliases,
            scope_node=scope_node,
            parent_map=parent_map,
            before_node=before_node,
        )
        if left is not None:
            return left
        return _python_response_error_detail_match(
            node.right,
            exc_name=exc_name,
            aliases=aliases,
            scope_node=scope_node,
            parent_map=parent_map,
            before_node=before_node,
        )
    if isinstance(node, ast.Dict):
        for value in node.values:
            nested = _python_response_error_detail_match(
                value,
                exc_name=exc_name,
                aliases=aliases,
                scope_node=scope_node,
                parent_map=parent_map,
                before_node=before_node,
            )
            if nested is not None:
                return nested
        return None
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        for element in node.elts:
            nested = _python_response_error_detail_match(
                element,
                exc_name=exc_name,
                aliases=aliases,
                scope_node=scope_node,
                parent_map=parent_map,
                before_node=before_node,
            )
            if nested is not None:
                return nested
        return None
    return None


def _python_is_exception_name(node: ast.expr, exc_name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == exc_name


def _python_fstring_is_exception_detail(
    node: ast.expr,
    exc_name: str,
    aliases: Mapping[str, str],
) -> bool:
    if _python_exception_detail_access_kind(node, exc_name) is not None:
        return True
    if not isinstance(node, ast.Call):
        return False
    call_name = _resolve_call_name(node.func, aliases)
    return (
        call_name == "str"
        and len(node.args) == 1
        and _python_exception_detail_access_kind(node.args[0], exc_name) is not None
    )


def _python_response_kind_label(node: ast.expr, aliases: Mapping[str, str]) -> str:
    if isinstance(node, ast.Call):
        call_name = _resolve_call_name(node.func, aliases)
        return call_name.split(".")[-1] if call_name else "call-response"
    if isinstance(node, ast.Dict):
        return "dict-response"
    if isinstance(node, ast.Tuple):
        return "tuple-response"
    if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
        return "string-response"
    return node.__class__.__name__.lower()


def _python_callable_parameter_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    names = {
        argument.arg
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        if argument.arg not in {"self", "cls"}
    }
    if node.args.vararg is not None:
        names.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        names.add(node.args.kwarg.arg)
    return frozenset(names)


def _iter_python_observability_callables(
    root: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    yield root
    for child in ast.iter_child_nodes(root):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from _iter_python_observability_callables(child)
            continue
        if isinstance(child, ast.ClassDef):
            continue
        yield from _iter_python_nested_observability_callables(child)


def _iter_python_nested_observability_callables(
    node: ast.AST,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from _iter_python_observability_callables(child)
            continue
        if isinstance(child, ast.ClassDef):
            continue
        yield from _iter_python_nested_observability_callables(child)


def _is_python_nested_scope_node(
    node: ast.AST,
    scope_node: ast.AST,
    parent_map: Mapping[ast.AST, ast.AST],
) -> bool:
    current = parent_map.get(node)
    while current is not None and current is not scope_node:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return True
        current = parent_map.get(current)
    return False


def _python_httpx_context_manager_calls_have_timeout_shaping(
    *,
    node: ast.Call,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_map: Mapping[ast.AST, ast.AST],
) -> bool:
    with_info = _python_httpx_with_manager(node, parent_map)
    if with_info is None:
        return False
    with_node, alias_name = with_info
    saw_request_call = False
    for descendant in ast.walk(with_node):
        if not isinstance(descendant, ast.Call):
            continue
        if _is_python_nested_scope_node(descendant, scope_node, parent_map):
            continue
        if not _is_python_httpx_alias_request_call(descendant, alias_name):
            continue
        saw_request_call = True
        if not _python_call_has_non_none_keyword(descendant, "timeout"):
            return False
    return saw_request_call


def _python_httpx_with_manager(
    node: ast.Call, parent_map: Mapping[ast.AST, ast.AST]
) -> tuple[ast.With | ast.AsyncWith, str] | None:
    parent = parent_map.get(node)
    if not isinstance(parent, ast.withitem) or parent.context_expr is not node:
        return None
    if not isinstance(parent.optional_vars, ast.Name):
        return None
    with_node = parent_map.get(parent)
    if not isinstance(with_node, (ast.With, ast.AsyncWith)):
        return None
    return with_node, parent.optional_vars.id


def _is_python_httpx_alias_request_call(node: ast.Call, alias_name: str) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if not isinstance(node.func.value, ast.Name) or node.func.value.id != alias_name:
        return False
    return node.func.attr in _REQUESTS_METHODS


def _python_call_has_non_none_keyword(node: ast.Call, keyword_name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg != keyword_name:
            continue
        return not (isinstance(keyword.value, ast.Constant) and keyword.value.value is None)
    return False


def _python_scope_has_durable_background_surface(
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> bool:
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Call):
            continue
        if _is_python_nested_scope_node(node, scope_node, parent_map):
            continue
        call_name = _resolve_call_name(node.func, aliases)
        if _looks_like_python_background_surface_call(call_name):
            return True
    return False


def _looks_like_python_background_surface_call(call_name: str | None) -> bool:
    if call_name is None:
        return False
    tokens = set(_shared_split_identifier_tokens(call_name.replace(".", "_")))
    if {"metric", "metrics", "counter", "gauge", "histogram", "audit", "incident"} & tokens:
        return True
    if "capture" in tokens and {"exception", "error", "failure", "incident"} & tokens:
        return True
    if {"record", "save", "persist", "update"} & tokens and {
        "failure",
        "error",
        "outcome",
        "result",
        "status",
    } & tokens:
        return True
    return bool({"emit", "publish"} & tokens and {"metric", "metrics", "event", "events"} & tokens)


def _iter_request_layer_global_resolution_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ServiceLocatorMatch]:
    module_singletons = _collect_python_module_singletons(parsed_file)
    for route_function in _iter_route_functions(parsed_file):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(route_function),
        }
        yield from _iter_python_global_resolution_matches_for_scope(
            scope_node=route_function,
            aliases=aliases,
            module_singletons=module_singletons,
            symbol=route_function.name,
        )


def _iter_service_layer_global_resolution_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ServiceLocatorMatch]:
    module_singletons = _collect_python_module_singletons(parsed_file)
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(callable_node),
        }
        yield from _iter_python_global_resolution_matches_for_scope(
            scope_node=callable_node,
            aliases=aliases,
            module_singletons=module_singletons,
            symbol=callable_node.name,
        )


def _iter_python_global_resolution_matches_for_scope(
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
    module_singletons: frozenset[str],
    symbol: str,
) -> Iterator[_ServiceLocatorMatch]:
    for node in ast.walk(scope_node):
        if isinstance(node, ast.Call):
            root_name = _root_python_name(node.func)
            call_name = _resolve_call_name(node.func, aliases)
            match = _python_global_resolution_call_match(
                call_name=call_name,
                root_name=root_name,
                aliases=aliases,
                module_singletons=module_singletons,
            )
            if match is None:
                continue
            access_pattern, resolution_kind = match
            yield _ServiceLocatorMatch(
                node=node,
                access_pattern=access_pattern,
                resolution_kind=resolution_kind,
                symbol=symbol,
            )
            continue
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                continue
            match = _python_registry_instance_assignment_match(node.value, aliases)
            if match is None:
                continue
            access_pattern, resolution_kind = match
            yield _ServiceLocatorMatch(
                node=node.value,
                access_pattern=access_pattern,
                resolution_kind=resolution_kind,
                symbol=symbol,
            )
            continue
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.value, ast.Call):
                continue
            match = _python_registry_instance_assignment_match(node.value, aliases)
            if match is None:
                continue
            access_pattern, resolution_kind = match
            yield _ServiceLocatorMatch(
                node=node.value,
                access_pattern=access_pattern,
                resolution_kind=resolution_kind,
                symbol=symbol,
            )


def _iter_hardcoded_external_literal_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ExternalLiteralMatch]:
    for match in _iter_env_access_matches(parsed_file):
        if match.env_name is None or match.default_node is None:
            continue
        literal_kind = _python_external_literal_kind(match.default_node, match.env_name)
        literal_value = _python_literal_value_for_metadata(match.default_node)
        if literal_kind is None or literal_value is None:
            continue
        yield _ExternalLiteralMatch(
            node=match.default_node,
            context_name=match.env_name,
            literal_kind=literal_kind,
            literal_value=literal_value,
        )

    for node in ast.walk(parsed_file.module):
        if isinstance(node, ast.Assign):
            for target_name in _iter_assignment_target_names(node.targets):
                literal_kind = _python_external_literal_kind(node.value, target_name)
                literal_value = _python_literal_value_for_metadata(node.value)
                if literal_kind is None or literal_value is None:
                    continue
                yield _ExternalLiteralMatch(
                    node=node.value,
                    context_name=target_name,
                    literal_kind=literal_kind,
                    literal_value=literal_value,
                )
        elif isinstance(node, ast.AnnAssign):
            target_name = _assignment_target_name(node.target)
            literal_kind = _python_external_literal_kind(node.value, target_name)
            literal_value = _python_literal_value_for_metadata(node.value)
            if literal_kind is None or literal_value is None:
                continue
            yield _ExternalLiteralMatch(
                node=node.value,
                context_name=target_name,
                literal_kind=literal_kind,
                literal_value=literal_value,
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from _iter_function_default_external_literal_matches(node)
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg is None:
                    continue
                literal_kind = _python_external_literal_kind(keyword.value, keyword.arg)
                literal_value = _python_literal_value_for_metadata(keyword.value)
                if literal_kind is None or literal_value is None:
                    continue
                yield _ExternalLiteralMatch(
                    node=keyword.value,
                    context_name=keyword.arg,
                    literal_kind=literal_kind,
                    literal_value=literal_value,
                )


def _iter_dynamic_sql_matches(parsed_file: _ParsedPythonFile) -> Iterator[_DynamicSqlMatch]:
    parent_map = _python_parent_map(parsed_file.module)
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.Call):
            continue
        execution_call_name = _resolve_call_name(node.func, parsed_file.import_aliases)
        if not _looks_like_python_sql_execution_call(execution_call_name):
            continue
        sql_expression = _sql_expression_from_execution_call(node, parsed_file.import_aliases)
        if sql_expression is None:
            continue
        sql_expression = _python_resolve_local_name_once(
            sql_expression,
            scope_node=_python_enclosing_local_scope(node, parsed_file.module, parent_map),
            parent_map=parent_map,
            before_node=node,
            name_filter=_looks_like_python_sql_binding_name,
        )
        construction_kind = _dynamic_python_sql_construction_kind(sql_expression)
        if construction_kind is None:
            continue
        yield _DynamicSqlMatch(
            node=node,
            sql_expression=sql_expression,
            execution_call_name=execution_call_name or "execute",
            construction_kind=construction_kind,
        )


def _iter_sensitive_logging_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_SensitiveLoggingMatch]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.Call):
            continue
        log_method = _python_log_method_name(node, parsed_file.import_aliases)
        if log_method is None:
            continue
        for value_node in _iter_python_logged_value_nodes(node):
            identifier_name, sensitivity_kind = _python_sensitive_logging_identity(
                value_node, parsed_file.import_aliases
            )
            if identifier_name is None or sensitivity_kind is None:
                continue
            yield _SensitiveLoggingMatch(
                log_call=node,
                value_node=value_node,
                sensitivity_kind=sensitivity_kind,
                identifier_name=identifier_name,
                log_method=log_method,
            )


def _iter_request_layer_error_response_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ResponseErrorDetailMatch]:
    for route_function in _iter_route_functions(parsed_file):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(route_function),
        }
        parent_map = _python_parent_map(route_function)
        for node in ast.walk(route_function):
            if not isinstance(node, ast.ExceptHandler) or not node.name:
                continue
            for return_node in _iter_python_non_nested_returns(node, parent_map):
                detail_match = _python_response_error_detail_match(
                    return_node.value,
                    exc_name=node.name,
                    aliases=aliases,
                    scope_node=node,
                    parent_map=parent_map,
                    before_node=return_node,
                )
                if detail_match is None:
                    continue
                detail_node, detail_kind = detail_match
                yield _ResponseErrorDetailMatch(
                    node=return_node,
                    detail_node=detail_node,
                    detail_kind=detail_kind,
                    response_kind=_python_response_kind_label(return_node.value, aliases),
                    symbol=route_function.name,
                )


def _iter_request_layer_json_body_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_RequestJsonBodyMatch]:
    for route_function in _iter_route_functions(parsed_file):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(route_function),
        }
        request_param_names = _python_route_request_parameter_names(route_function)
        if not request_param_names:
            continue
        parent_map = _python_parent_map(route_function)
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            if _is_python_nested_scope_node(node, route_function, parent_map):
                continue
            access_pattern = _python_request_json_access_pattern(
                node, request_param_names=request_param_names, aliases=aliases
            )
            if access_pattern is None:
                continue
            if _python_request_json_call_has_invalid_json_guard(
                node=node,
                scope_node=route_function,
                parent_map=parent_map,
                aliases=aliases,
            ):
                continue
            yield _RequestJsonBodyMatch(
                node=node,
                access_pattern=access_pattern,
                guard_kind="missing-invalid-json-guard",
                symbol=route_function.name,
            )


def _iter_bare_except_cleanup_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_BareExceptCleanupMatch]:
    if not _is_bare_except_cleanup_python_path(parsed_file.relative_path):
        return

    yield from _iter_bare_except_cleanup_matches_in_scope(
        parsed_file.module,
        aliases=parsed_file.import_aliases,
        symbol=None,
    )
    for callable_node, container_name in _iter_runtime_callables(parsed_file.module):
        yield from _iter_bare_except_cleanup_matches_in_scope(
            callable_node,
            aliases={
                **parsed_file.import_aliases,
                **_collect_nested_import_aliases(callable_node),
            },
            symbol=_python_scoped_symbol_name(callable_node.name, container_name),
        )


def _iter_bare_except_cleanup_matches_in_scope(
    scope_node: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    aliases: Mapping[str, str],
    symbol: str | None,
) -> Iterator[_BareExceptCleanupMatch]:
    parent_map = _python_parent_map(scope_node)
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Try):
            continue
        if _is_python_nested_scope_node(node, scope_node, parent_map):
            continue
        cleanup_patterns = _python_try_cleanup_patterns(node.body, aliases)
        if not cleanup_patterns:
            continue
        for handler in node.handlers:
            if not _is_silent_bare_except_handler(handler):
                continue
            yield _BareExceptCleanupMatch(
                try_node=node,
                handler=handler,
                cleanup_patterns=cleanup_patterns,
                symbol=symbol,
            )


def _python_try_cleanup_patterns(
    statements: Sequence[ast.stmt], aliases: Mapping[str, str]
) -> tuple[str, ...]:
    patterns: list[str] = []
    for statement in statements:
        statement_patterns = _python_cleanup_statement_patterns(statement, aliases)
        if statement_patterns is None:
            return ()
        patterns.extend(statement_patterns)
    unique_patterns = tuple(dict.fromkeys(patterns))
    return unique_patterns if unique_patterns else ()


def _python_cleanup_statement_patterns(
    statement: ast.stmt, aliases: Mapping[str, str]
) -> tuple[str, ...] | None:
    if isinstance(statement, ast.Expr):
        return _python_cleanup_expression_patterns(statement.value, aliases)
    if isinstance(statement, ast.If):
        body_patterns = _python_try_cleanup_patterns(statement.body, aliases)
        if not body_patterns:
            return None
        if not statement.orelse:
            return body_patterns
        orelse_patterns = _python_try_cleanup_patterns(statement.orelse, aliases)
        if not orelse_patterns:
            return None
        return (*body_patterns, *orelse_patterns)
    return None


def _python_cleanup_expression_patterns(
    node: ast.expr, aliases: Mapping[str, str]
) -> tuple[str, ...] | None:
    expression = node.value if isinstance(node, ast.Await) else node
    if not isinstance(expression, ast.Call):
        return None
    cleanup_pattern = _python_cleanup_call_pattern(expression, aliases)
    if cleanup_pattern is None:
        return None
    return (cleanup_pattern,)


def _python_cleanup_call_pattern(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    call_name = _resolve_call_name(node.func, aliases)
    if call_name is None:
        return None
    tail_name = call_name.rsplit(".", 1)[-1].lower()
    if tail_name in _PYTHON_CLEANUP_CALL_TAILS:
        return call_name
    if tail_name in _PYTHON_CONDITIONAL_CLEANUP_CALL_TAILS:
        receiver_name = _python_cleanup_receiver_name(node.func, aliases)
        if receiver_name is None:
            return None
        receiver_tail = receiver_name.rsplit(".", 1)[-1]
        receiver_tokens = {
            token.lower() for token in _shared_split_identifier_tokens(receiver_tail)
        }
        if receiver_tokens & _PYTHON_RESOURCE_CLEANUP_RECEIVER_TOKENS:
            return call_name
        return None
    tail_tokens = {token.lower() for token in _shared_split_identifier_tokens(tail_name)}
    if tail_tokens & _PYTHON_CLEANUP_CALL_TOKEN_MARKERS:
        return call_name
    return None


def _python_cleanup_receiver_name(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    if not isinstance(node, ast.Attribute):
        return None
    return _resolve_call_name(node.value, aliases)


def _is_silent_bare_except_handler(handler: ast.ExceptHandler) -> bool:
    return (
        handler.type is None
        and bool(handler.body)
        and all(isinstance(statement, ast.Pass) for statement in handler.body)
    )


def _iter_state_datetime_matches(parsed_file: _ParsedPythonFile) -> Iterator[_StateDatetimeMatch]:
    if not _is_state_datetime_python_path(parsed_file.relative_path):
        return

    default_factory_lambda_body_ids: set[int] = set()
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "default_factory":
                continue
            access_pattern = _python_naive_datetime_default_factory_pattern(
                keyword.value, parsed_file.import_aliases
            )
            if access_pattern is None:
                continue
            if isinstance(keyword.value, ast.Lambda) and isinstance(keyword.value.body, ast.Call):
                default_factory_lambda_body_ids.add(id(keyword.value.body))
            yield _StateDatetimeMatch(
                node=keyword.value,
                access_pattern=access_pattern,
                usage_kind="default-factory",
                symbol=_enclosing_python_symbol(parsed_file.module, keyword.value),
            )
        if id(node) in default_factory_lambda_body_ids:
            continue
        access_pattern = _python_naive_datetime_call_pattern(node, parsed_file.import_aliases)
        if access_pattern is not None:
            yield _StateDatetimeMatch(
                node=node,
                access_pattern=access_pattern,
                usage_kind="naive-datetime-call",
                symbol=_enclosing_python_symbol(parsed_file.module, node),
            )


def _iter_atomic_state_write_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_AtomicStateWriteMatch]:
    if not _is_atomic_state_write_python_path(parsed_file.relative_path):
        return

    for node in ast.walk(parsed_file.module):
        if isinstance(node, ast.Call):
            direct_match = _python_direct_state_write_match(node, parsed_file.import_aliases)
            if direct_match is not None:
                write_pattern, target_name = direct_match
                yield _AtomicStateWriteMatch(
                    node=node,
                    write_pattern=write_pattern,
                    target_name=target_name,
                    symbol=_enclosing_python_symbol(parsed_file.module, node),
                )
        if isinstance(node, ast.With):
            for write_pattern, target_name in _python_with_state_write_matches(
                node, parsed_file.import_aliases
            ):
                yield _AtomicStateWriteMatch(
                    node=node,
                    write_pattern=write_pattern,
                    target_name=target_name,
                    symbol=_enclosing_python_symbol(parsed_file.module, node),
                )
            continue
        if isinstance(node, ast.AsyncWith):
            for write_pattern, target_name in _python_async_with_state_write_matches(
                node, parsed_file.import_aliases
            ):
                yield _AtomicStateWriteMatch(
                    node=node,
                    write_pattern=write_pattern,
                    target_name=target_name,
                    symbol=_enclosing_python_symbol(parsed_file.module, node),
                )


def _iter_async_lock_pool_matches(parsed_file: _ParsedPythonFile) -> Iterator[_AsyncLockPoolMatch]:
    if _is_transport_python_path(parsed_file.relative_path) or not _is_runtime_python_path(
        parsed_file.relative_path
    ):
        return

    evicting_pools = _collect_python_lock_pool_evictions(parsed_file)
    for callable_node, container_name in _iter_runtime_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(callable_node),
        }
        parent_map = _python_parent_map(callable_node)
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.If):
                continue
            if _is_python_nested_scope_node(node, callable_node, parent_map):
                continue
            lazy_creation = _python_lazy_lock_pool_if_match(node, aliases)
            if lazy_creation is None:
                continue
            pool_name, creation_node = lazy_creation
            yield _AsyncLockPoolMatch(
                node=creation_node,
                pool_name=pool_name,
                creation_pattern="if-missing-create-lock",
                symbol=_python_scoped_symbol_name(callable_node.name, container_name),
                has_eviction=pool_name in evicting_pools,
                has_capacity_guard=_python_scope_has_lock_pool_capacity_guard(
                    callable_node,
                    pool_name=pool_name,
                    aliases=aliases,
                    parent_map=parent_map,
                ),
                guarded_by_lock=_python_lock_pool_creation_is_guarded(
                    creation_node,
                    scope_node=callable_node,
                    aliases=aliases,
                    parent_map=parent_map,
                ),
            )


def _iter_unbounded_upload_read_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_UploadReadMatch]:
    if not _is_request_async_python_path(parsed_file):
        return

    for async_node, container_name in _iter_async_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(async_node),
        }
        upload_params = _python_upload_parameter_names(async_node, aliases)
        if not upload_params:
            continue
        parent_map = _python_parent_map(async_node)
        guard_lines = _python_upload_size_guard_lines(
            async_node,
            upload_params=upload_params,
            parent_map=parent_map,
        )
        for node in ast.walk(async_node):
            if not isinstance(node, ast.Call):
                continue
            if _is_python_nested_scope_node(node, async_node, parent_map):
                continue
            upload_read = _python_upload_read_call_match(
                node,
                upload_params=upload_params,
                aliases=aliases,
                parent_map=parent_map,
            )
            if upload_read is None:
                continue
            upload_parameter, access_pattern = upload_read
            guard_line = guard_lines.get(upload_parameter)
            if guard_line is not None and guard_line < node.lineno:
                continue
            yield _UploadReadMatch(
                node=node,
                access_pattern=access_pattern,
                upload_parameter=upload_parameter,
                symbol=_python_scoped_symbol_name(async_node.name, container_name),
            )


def _iter_sync_db_on_async_path_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_SyncDbAsyncPathMatch]:
    module_helpers, class_helpers = _collect_python_sync_db_helpers(parsed_file)
    for async_node, container_name in _iter_async_callables(parsed_file.module):
        aliases = {
            **parsed_file.import_aliases,
            **_collect_nested_import_aliases(async_node),
        }
        parent_map = _python_parent_map(async_node)
        sync_bindings = _collect_python_sync_db_bindings(
            async_node,
            aliases=aliases,
            parent_map=parent_map,
        )
        symbol = _python_scoped_symbol_name(async_node.name, container_name)
        for node in ast.walk(async_node):
            if not isinstance(node, ast.Call):
                continue
            if _is_python_nested_scope_node(node, async_node, parent_map):
                continue
            direct_match = _python_direct_sync_db_call_match(
                node,
                aliases=aliases,
                sync_bindings=sync_bindings,
            )
            if direct_match is not None:
                access_pattern, usage_kind = direct_match
                yield _SyncDbAsyncPathMatch(
                    node=node,
                    access_pattern=access_pattern,
                    usage_kind=usage_kind,
                    symbol=symbol,
                )
                continue
            helper_call = _python_same_file_sync_db_helper_call(
                node,
                module_helpers=module_helpers,
                class_helpers=class_helpers.get(container_name or "", frozenset()),
                aliases=aliases,
            )
            if helper_call is None:
                continue
            yield _SyncDbAsyncPathMatch(
                node=node,
                access_pattern=helper_call,
                usage_kind="sync-db-helper",
                symbol=symbol,
            )


def _collect_python_lock_pool_evictions(parsed_file: _ParsedPythonFile) -> frozenset[str]:
    pools: set[str] = set()
    for node in ast.walk(parsed_file.module):
        if isinstance(node, ast.Call):
            call_name = _resolve_call_name(node.func, parsed_file.import_aliases)
            if call_name is None:
                continue
            pool_name, _, method_name = call_name.rpartition(".")
            if not pool_name or method_name not in _LOCK_POOL_EVICTION_METHODS:
                continue
            if _looks_like_python_lock_pool_name(pool_name):
                pools.add(pool_name)
            continue
        if not isinstance(node, ast.Delete):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Subscript):
                continue
            pool_name = _resolve_call_name(target.value, parsed_file.import_aliases)
            if pool_name is not None and _looks_like_python_lock_pool_name(pool_name):
                pools.add(pool_name)
    return frozenset(pools)


def _python_lazy_lock_pool_if_match(
    node: ast.If, aliases: Mapping[str, str]
) -> tuple[str, ast.AST] | None:
    test = node.test
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or len(test.comparators) != 1
        or not isinstance(test.ops[0], ast.NotIn)
    ):
        return None
    pool_name = _resolve_call_name(test.comparators[0], aliases)
    if pool_name is None or not _looks_like_python_lock_pool_name(pool_name):
        return None
    for statement in node.body:
        creation_node = _python_lock_pool_creation_statement(
            statement,
            pool_name=pool_name,
            key_node=test.left,
            aliases=aliases,
        )
        if creation_node is not None:
            return pool_name, creation_node
    return None


def _python_lock_pool_creation_statement(
    statement: ast.stmt,
    *,
    pool_name: str,
    key_node: ast.expr,
    aliases: Mapping[str, str],
) -> ast.AST | None:
    if isinstance(statement, ast.Assign) and _is_asyncio_lock_constructor(statement.value, aliases):
        if any(
            _python_subscript_matches_pool_key(
                target,
                pool_name=pool_name,
                key_node=key_node,
                aliases=aliases,
            )
            for target in statement.targets
        ):
            return statement
        return None
    if (
        isinstance(statement, ast.AnnAssign)
        and _is_asyncio_lock_constructor(statement.value, aliases)
        and _python_subscript_matches_pool_key(
            statement.target,
            pool_name=pool_name,
            key_node=key_node,
            aliases=aliases,
        )
    ):
        return statement
    return None


def _python_subscript_matches_pool_key(
    target: ast.expr,
    *,
    pool_name: str,
    key_node: ast.expr,
    aliases: Mapping[str, str],
) -> bool:
    if not isinstance(target, ast.Subscript):
        return False
    return _resolve_call_name(target.value, aliases) == pool_name and _ast_nodes_equivalent(
        target.slice, key_node
    )


def _ast_nodes_equivalent(left: ast.AST, right: ast.AST) -> bool:
    return ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False)


def _is_asyncio_lock_constructor(node: ast.expr | None, aliases: Mapping[str, str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _resolve_call_name(node.func, aliases) == "asyncio.Lock"


def _looks_like_python_lock_pool_name(name: str) -> bool:
    tail_name = name.rsplit(".", 1)[-1]
    tokens = {token.lower() for token in _shared_split_identifier_tokens(tail_name)}
    return "lock" in tokens or "locks" in tokens


def _python_scope_has_lock_pool_capacity_guard(
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    pool_name: str,
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> bool:
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Compare):
            continue
        if _is_python_nested_scope_node(node, scope_node, parent_map):
            continue
        if _python_compare_mentions_pool_length(node, pool_name=pool_name, aliases=aliases):
            return True
    return False


def _python_compare_mentions_pool_length(
    node: ast.Compare,
    *,
    pool_name: str,
    aliases: Mapping[str, str],
) -> bool:
    return any(
        _python_is_len_call_for_pool(candidate, pool_name=pool_name, aliases=aliases)
        for candidate in (node.left, *node.comparators)
    )


def _python_is_len_call_for_pool(
    node: ast.expr,
    *,
    pool_name: str,
    aliases: Mapping[str, str],
) -> bool:
    return (
        isinstance(node, ast.Call)
        and len(node.args) == 1
        and not node.keywords
        and _resolve_call_name(node.func, aliases) == "len"
        and _resolve_call_name(node.args[0], aliases) == pool_name
    )


def _python_lock_pool_creation_is_guarded(
    node: ast.AST,
    *,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> bool:
    for ancestor in _python_ancestor_nodes(node, parent_map):
        if ancestor is scope_node:
            break
        if not isinstance(ancestor, (ast.With, ast.AsyncWith)):
            continue
        if any(
            _looks_like_python_guard_context_name(item.context_expr, aliases)
            for item in ancestor.items
        ):
            return True
    return False


def _looks_like_python_guard_context_name(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    context_name = _resolve_call_name(node, aliases)
    if context_name is None and isinstance(node, ast.Call):
        context_name = _resolve_call_name(node.func, aliases)
    if context_name is None:
        return False
    tokens = {token.lower() for token in _shared_split_identifier_tokens(context_name)}
    return bool(tokens & _GUARD_CONTEXT_MARKERS)


def _python_scoped_symbol_name(name: str, container_name: str | None) -> str:
    return f"{container_name}.{name}" if container_name is not None else name


def _python_upload_parameter_names(
    scope_node: ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
) -> frozenset[str]:
    names: set[str] = set()
    for argument, default in _iter_python_callable_parameters_with_defaults(scope_node):
        if _python_annotation_mentions_name(argument.annotation, "UploadFile", aliases):
            names.add(argument.arg)
            continue
        if _python_default_is_fastapi_file(default, aliases):
            names.add(argument.arg)
            continue
        tokens = {token.lower() for token in _shared_split_identifier_tokens(argument.arg)}
        if tokens & _UPLOAD_PARAMETER_NAME_MARKERS:
            names.add(argument.arg)
    return frozenset(names)


def _iter_python_callable_parameters_with_defaults(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[tuple[ast.arg, ast.expr | None]]:
    positional_args = (*node.args.posonlyargs, *node.args.args)
    positional_defaults: tuple[ast.expr | None, ...] = (
        (None,) * (len(positional_args) - len(node.args.defaults))
    ) + tuple(node.args.defaults)
    for argument, default in zip(positional_args, positional_defaults, strict=True):
        yield argument, default
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        yield argument, default


def _python_annotation_mentions_name(
    node: ast.expr | None,
    target_name: str,
    aliases: Mapping[str, str],
) -> bool:
    return any(
        annotation_name.rsplit(".", 1)[-1] == target_name
        for annotation_name in _iter_python_annotation_names(node, aliases)
    )


def _iter_python_annotation_names(
    node: ast.expr | None,
    aliases: Mapping[str, str],
) -> Iterator[str]:
    if node is None:
        return
    if isinstance(node, ast.Name):
        yield aliases.get(node.id, node.id)
        return
    if isinstance(node, ast.Attribute):
        resolved = _resolve_call_name(node, aliases)
        if resolved is not None:
            yield resolved
        return
    if isinstance(node, ast.Subscript):
        yield from _iter_python_annotation_names(node.value, aliases)
        yield from _iter_python_annotation_names(node.slice, aliases)
        return
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        yield from _iter_python_annotation_names(node.left, aliases)
        yield from _iter_python_annotation_names(node.right, aliases)
        return
    if isinstance(node, ast.Tuple):
        for element in node.elts:
            yield from _iter_python_annotation_names(element, aliases)
        return
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        for part in re.split(r"[|,\[\]\(\)\s]+", node.value):
            if part:
                yield part


def _python_default_is_fastapi_file(node: ast.expr | None, aliases: Mapping[str, str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    call_name = _resolve_call_name(node.func, aliases)
    return call_name is not None and call_name.rsplit(".", 1)[-1] == "File"


def _python_upload_size_guard_lines(
    scope_node: ast.AsyncFunctionDef,
    *,
    upload_params: frozenset[str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> dict[str, int]:
    guard_lines: dict[str, int] = {}
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Compare):
            continue
        if _is_python_nested_scope_node(node, scope_node, parent_map):
            continue
        for upload_name in upload_params:
            if not _python_compare_mentions_upload_size(node, upload_name=upload_name):
                continue
            previous_line = guard_lines.get(upload_name)
            if previous_line is None or node.lineno < previous_line:
                guard_lines[upload_name] = node.lineno
    return guard_lines


def _python_compare_mentions_upload_size(node: ast.Compare, *, upload_name: str) -> bool:
    return any(
        isinstance(child, ast.Attribute)
        and child.attr == "size"
        and isinstance(child.value, ast.Name)
        and child.value.id == upload_name
        for child in ast.walk(node)
    )


def _python_upload_read_call_match(
    node: ast.Call,
    *,
    upload_params: frozenset[str],
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> tuple[str, str] | None:
    if node.args or node.keywords:
        return None
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "read":
        return None
    if not isinstance(node.func.value, ast.Name):
        return None
    upload_parameter = node.func.value.id
    if upload_parameter not in upload_params:
        return None
    if not any(
        isinstance(ancestor, ast.Await) for ancestor in _python_ancestor_nodes(node, parent_map)
    ):
        return None
    access_pattern = _resolve_call_name(node.func, aliases) or f"{upload_parameter}.read"
    return upload_parameter, access_pattern


def _collect_python_sync_db_helpers(
    parsed_file: _ParsedPythonFile,
) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
    module_helpers: set[str] = set()
    class_helpers: dict[str, frozenset[str]] = {}
    for node in parsed_file.module.body:
        if isinstance(node, ast.FunctionDef):
            aliases = {
                **parsed_file.import_aliases,
                **_collect_nested_import_aliases(node),
            }
            if _python_scope_has_direct_sync_db_connect(node, aliases):
                module_helpers.add(node.name)
            continue
        if not isinstance(node, ast.ClassDef):
            continue
        helper_names: set[str] = set()
        for class_body_node in node.body:
            if not isinstance(class_body_node, ast.FunctionDef):
                continue
            aliases = {
                **parsed_file.import_aliases,
                **_collect_nested_import_aliases(class_body_node),
            }
            if _python_scope_has_direct_sync_db_connect(class_body_node, aliases):
                helper_names.add(class_body_node.name)
        if helper_names:
            class_helpers[node.name] = frozenset(helper_names)
    return frozenset(module_helpers), class_helpers


def _python_scope_has_direct_sync_db_connect(
    scope_node: ast.FunctionDef,
    aliases: Mapping[str, str],
) -> bool:
    parent_map = _python_parent_map(scope_node)
    for node in ast.walk(scope_node):
        if not isinstance(node, ast.Call):
            continue
        if _is_python_nested_scope_node(node, scope_node, parent_map):
            continue
        if _python_is_sync_db_connect_call(node, aliases):
            return True
    return False


def _python_is_sync_db_connect_call(node: ast.Call, aliases: Mapping[str, str]) -> bool:
    return _resolve_call_name(node.func, aliases) in _SYNC_DB_CONNECT_CALL_NAMES


def _collect_python_sync_db_bindings(
    scope_node: ast.AsyncFunctionDef,
    *,
    aliases: Mapping[str, str],
    parent_map: Mapping[ast.AST, ast.AST],
) -> frozenset[str]:
    bindings = set(_python_sync_db_parameter_names(scope_node, aliases))
    changed = True
    while changed:
        changed = False
        for node in ast.walk(scope_node):
            if _is_python_nested_scope_node(node, scope_node, parent_map):
                continue
            if isinstance(node, ast.Assign):
                if not _python_value_creates_sync_db_binding(node.value, aliases, bindings):
                    continue
                for binding_name in _iter_python_binding_target_names(node.targets, aliases):
                    if binding_name in bindings:
                        continue
                    bindings.add(binding_name)
                    changed = True
                continue
            if isinstance(node, ast.AnnAssign) and _python_value_creates_sync_db_binding(
                node.value, aliases, bindings
            ):
                binding_name = _python_binding_target_name(node.target, aliases)
                if binding_name is None or binding_name in bindings:
                    continue
                bindings.add(binding_name)
                changed = True
    return frozenset(bindings)


def _python_sync_db_parameter_names(
    scope_node: ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
) -> frozenset[str]:
    parameter_names: set[str] = set()
    for argument, _ in _iter_python_callable_parameters_with_defaults(scope_node):
        if _python_annotation_mentions_sync_db_type(argument.annotation, aliases):
            parameter_names.add(argument.arg)
    return frozenset(parameter_names)


def _python_annotation_mentions_sync_db_type(
    node: ast.expr | None, aliases: Mapping[str, str]
) -> bool:
    for annotation_name in _iter_python_annotation_names(node, aliases):
        tail_name = annotation_name.rsplit(".", 1)[-1]
        if tail_name not in _SYNC_DB_TYPE_TAILS:
            continue
        if any(annotation_name.startswith(prefix) for prefix in _SYNC_DB_MODULE_PREFIXES):
            return True
    return False


def _python_value_creates_sync_db_binding(
    node: ast.expr | None,
    aliases: Mapping[str, str],
    bindings: set[str],
) -> bool:
    if node is None:
        return False
    if isinstance(node, (ast.Name, ast.Attribute)):
        binding_name = _resolve_call_name(node, aliases)
        return binding_name in bindings
    if not isinstance(node, ast.Call):
        return False
    if _python_is_sync_db_connect_call(node, aliases):
        return True
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in _SYNC_DB_BINDING_FACTORY_METHODS:
        return False
    receiver_name = _resolve_call_name(node.func.value, aliases)
    if receiver_name in bindings:
        return True
    return isinstance(node.func.value, ast.Call) and _python_is_sync_db_connect_call(
        node.func.value, aliases
    )


def _iter_python_binding_target_names(
    targets: Sequence[ast.expr], aliases: Mapping[str, str]
) -> Iterator[str]:
    for target in targets:
        binding_name = _python_binding_target_name(target, aliases)
        if binding_name is not None:
            yield binding_name


def _python_binding_target_name(target: ast.expr, aliases: Mapping[str, str]) -> str | None:
    if not isinstance(target, (ast.Name, ast.Attribute)):
        return None
    return _resolve_call_name(target, aliases)


def _python_direct_sync_db_call_match(
    node: ast.Call,
    *,
    aliases: Mapping[str, str],
    sync_bindings: frozenset[str],
) -> tuple[str, str] | None:
    call_name = _resolve_call_name(node.func, aliases)
    if call_name in _SYNC_DB_CONNECT_CALL_NAMES:
        return call_name, "sync-db-connect"
    if not _python_is_sync_db_query_call(node, aliases=aliases, sync_bindings=sync_bindings):
        return None
    access_pattern = call_name or _python_attribute_call_pattern(node)
    return access_pattern, "sync-db-query"


def _python_is_sync_db_query_call(
    node: ast.Call,
    *,
    aliases: Mapping[str, str],
    sync_bindings: frozenset[str],
) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in _SYNC_DB_QUERY_METHODS:
        return False
    receiver_name = _resolve_call_name(node.func.value, aliases)
    if receiver_name in sync_bindings:
        return True
    if not isinstance(node.func.value, ast.Call):
        return False
    receiver_call = node.func.value
    if _python_is_sync_db_connect_call(receiver_call, aliases):
        return True
    if not isinstance(receiver_call.func, ast.Attribute):
        return False
    if receiver_call.func.attr not in _SYNC_DB_BINDING_FACTORY_METHODS:
        return False
    receiver_binding_name = _resolve_call_name(receiver_call.func.value, aliases)
    if receiver_binding_name in sync_bindings:
        return True
    return isinstance(receiver_call.func.value, ast.Call) and _python_is_sync_db_connect_call(
        receiver_call.func.value, aliases
    )


def _python_attribute_call_pattern(node: ast.Call) -> str:
    if not isinstance(node.func, ast.Attribute):
        return node.__class__.__name__.lower()
    receiver_name = _root_python_name(node.func)
    if receiver_name is None:
        return node.func.attr
    return f"{receiver_name}.{node.func.attr}"


def _python_same_file_sync_db_helper_call(
    node: ast.Call,
    *,
    module_helpers: frozenset[str],
    class_helpers: frozenset[str],
    aliases: Mapping[str, str],
) -> str | None:
    if isinstance(node.func, ast.Name) and node.func.id in module_helpers:
        return aliases.get(node.func.id, node.func.id)
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"self", "cls"}
        and node.func.attr in class_helpers
    ):
        return _resolve_call_name(node.func, aliases) or f"{node.func.value.id}.{node.func.attr}"
    return None


def _python_route_request_parameter_names(
    route_function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    parameter_names: set[str] = set()
    arguments = (
        *route_function.args.posonlyargs,
        *route_function.args.args,
        *route_function.args.kwonlyargs,
    )
    for argument in arguments:
        annotation_name = _python_annotation_name(argument.annotation)
        if argument.arg == "request" or (
            annotation_name is not None and annotation_name.rsplit(".", 1)[-1] == "Request"
        ):
            parameter_names.add(argument.arg)
    return frozenset(parameter_names)


def _python_annotation_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_annotation_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _python_annotation_name(node.value)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _python_request_json_access_pattern(
    node: ast.Call,
    *,
    request_param_names: frozenset[str],
    aliases: Mapping[str, str],
) -> str | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "json":
        return None
    if not isinstance(node.func.value, ast.Name) or node.func.value.id not in request_param_names:
        return None
    return _resolve_call_name(node.func, aliases) or f"{node.func.value.id}.json"


def _python_request_json_call_has_invalid_json_guard(
    *,
    node: ast.Call,
    scope_node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_map: Mapping[ast.AST, ast.AST],
    aliases: Mapping[str, str],
) -> bool:
    current: ast.AST = node
    while current is not scope_node:
        parent = parent_map.get(current)
        if parent is None:
            return False
        if (
            isinstance(parent, ast.Try)
            and current in parent.body
            and any(
                _python_except_handler_returns_bad_request_response(
                    handler,
                    parent_map=parent_map,
                    aliases=aliases,
                )
                for handler in parent.handlers
            )
        ):
            return True
        current = parent
    return False


def _python_except_handler_returns_bad_request_response(
    handler: ast.ExceptHandler,
    *,
    parent_map: Mapping[ast.AST, ast.AST],
    aliases: Mapping[str, str],
) -> bool:
    for return_node in _iter_python_non_nested_returns(handler, parent_map):
        if _python_response_status_code(return_node.value, aliases) == 400:
            return True
    for node in ast.walk(handler):
        if not isinstance(node, ast.Raise) or node.exc is None:
            continue
        if _python_response_status_code(node.exc, aliases) == 400:
            return True
    return False


def _python_response_status_code(node: ast.expr, aliases: Mapping[str, str]) -> int | None:
    if not isinstance(node, ast.Call):
        return None
    call_name = _resolve_call_name(node.func, aliases)
    status_code = _keyword_argument(node, "status_code")
    if call_name == "HTTPException" and status_code is None and node.args:
        status_code = node.args[0]
    return _python_status_code_value(status_code)


def _python_status_code_value(node: ast.expr | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Attribute) and node.attr in {"BAD_REQUEST", "HTTP_400_BAD_REQUEST"}:
        return 400
    return None


def _python_log_method_name(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in _PYTHON_LOG_METHODS:
        return None
    receiver_name = _resolve_call_name(node.func.value, aliases)
    if receiver_name is None:
        return None
    receiver_tokens = _shared_split_identifier_tokens(receiver_name.split(".")[-1])
    if not any(token in {"log", "logger", "logging"} for token in receiver_tokens):
        return None
    return node.func.attr


def _iter_python_logged_value_nodes(node: ast.Call) -> Iterator[ast.expr]:
    if not node.args:
        return
    first_arg = node.args[0]
    inline_values = tuple(_iter_python_inline_logging_values(first_arg))
    if len(node.args) == 1:
        if inline_values:
            yield from inline_values
        elif not _is_plain_python_string_literal(first_arg):
            yield first_arg
        return
    yield from inline_values
    yield from node.args[1:]


def _iter_python_inline_logging_values(node: ast.expr) -> Iterator[ast.expr]:
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                yield value.value
        return
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        yield from _iter_python_format_operands(node.right)
        return
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        yield from node.args
        for keyword in node.keywords:
            yield keyword.value


def _iter_python_format_operands(node: ast.expr) -> Iterator[ast.expr]:
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        yield from node.elts
        return
    yield node


def _python_sensitive_logging_identity(
    node: ast.expr, aliases: Mapping[str, str]
) -> tuple[str | None, str | None]:
    if _python_expression_is_masked(node, aliases):
        return None, None
    for identifier_name in _iter_python_sensitive_candidate_names(node, aliases):
        sensitivity_kind = _shared_sensitive_logging_name_kind(identifier_name)
        if sensitivity_kind is None:
            continue
        return identifier_name, sensitivity_kind
    return None, None


def _iter_python_sensitive_candidate_names(
    node: ast.expr, aliases: Mapping[str, str]
) -> Iterator[str]:
    seen: set[str] = set()
    for candidate in _iter_python_sensitive_candidate_names_inner(node, aliases):
        normalized = candidate.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        yield normalized


def _iter_python_sensitive_candidate_names_inner(
    node: ast.expr, aliases: Mapping[str, str]
) -> Iterator[str]:
    if isinstance(node, ast.Name):
        yield node.id
        return
    if isinstance(node, ast.Attribute):
        yield node.attr
        return
    if isinstance(node, ast.Call):
        call_name = _resolve_call_name(node.func, aliases)
        if call_name is not None:
            yield call_name.split(".")[-1]
        for argument in node.args:
            constant_value = _constant_string_argument(argument)
            if constant_value is not None:
                yield constant_value
        return
    if isinstance(node, ast.Subscript):
        key_name = _python_subscript_key_name(node.slice)
        if key_name is not None:
            yield key_name
        return
    if isinstance(node, ast.BinOp):
        yield from _iter_python_sensitive_candidate_names_inner(node.left, aliases)
        yield from _iter_python_sensitive_candidate_names_inner(node.right, aliases)
        return
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        for element in node.elts:
            yield from _iter_python_sensitive_candidate_names_inner(element, aliases)
        return
    if isinstance(node, ast.UnaryOp):
        yield from _iter_python_sensitive_candidate_names_inner(node.operand, aliases)


def _python_expression_is_masked(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    if isinstance(node, ast.Name):
        return _shared_is_masked_sensitive_logging_name(node.id)
    if isinstance(node, ast.Attribute):
        return _shared_is_masked_sensitive_logging_name(node.attr)
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Slice) or _python_expression_is_masked(
            node.value, aliases
        )
    if isinstance(node, ast.Call):
        call_name = _resolve_call_name(node.func, aliases)
        if call_name is None:
            return False
        return any(
            _shared_is_masked_sensitive_logging_name(segment) for segment in call_name.split(".")
        )
    if isinstance(node, ast.BinOp):
        return _python_expression_is_masked(node.left, aliases) or _python_expression_is_masked(
            node.right, aliases
        )
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return any(_python_expression_is_masked(element, aliases) for element in node.elts)
    if isinstance(node, ast.UnaryOp):
        return _python_expression_is_masked(node.operand, aliases)
    return False


def _python_subscript_key_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_plain_python_string_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_transport_python_path(relative_path: str) -> bool:
    path = Path(relative_path)
    if any(part in _TRANSPORT_DIRECTORY_NAMES for part in path.parts):
        return True
    stem_tokens = {token for token in path.stem.lower().replace("-", "_").split("_") if token}
    return any(marker in stem_tokens for marker in _TRANSPORT_STEM_MARKERS)


def _oversized_runtime_module_scope(parsed_file: _ParsedPythonFile) -> str | None:
    if not _is_runtime_python_path(parsed_file.relative_path):
        return None
    if (
        _python_path_markers(parsed_file.relative_path)
        & _OVERSIZED_RUNTIME_MODULE_EXCLUDED_PATH_MARKERS
    ):
        return None
    if _is_transport_python_path(parsed_file.relative_path) or any(
        _iter_route_functions(parsed_file)
    ):
        return "request-layer"
    if _is_service_layer_python_path(parsed_file.relative_path):
        return "service-layer"
    return None


def _python_reviewable_runtime_scope(parsed_file: _ParsedPythonFile) -> str | None:
    if not _is_runtime_python_path(parsed_file.relative_path):
        return None
    markers = _python_path_markers(parsed_file.relative_path)
    if markers & _PYTHON_RUNTIME_REVIEW_EXCLUDED_PATH_MARKERS:
        return None
    if _is_transport_python_path(parsed_file.relative_path) or any(
        _iter_route_functions(parsed_file)
    ):
        return "request-layer"
    if _is_service_layer_python_path(parsed_file.relative_path):
        return "service-layer"
    if markers & _PYTHON_RUNTIME_REVIEW_SERVICE_HINT_MARKERS:
        return "service-layer"
    return None


def _is_request_async_python_path(parsed_file: _ParsedPythonFile) -> bool:
    path = Path(parsed_file.relative_path)
    if any(part in _TRANSPORT_DIRECTORY_NAMES for part in path.parts):
        return True
    return any(_iter_route_functions(parsed_file))


def _is_service_layer_python_path(relative_path: str) -> bool:
    if _is_transport_python_path(relative_path) or not _is_runtime_python_path(relative_path):
        return False
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(Path(part).stem.lower() for part in path.parts)
    stem_tokens = set(_shared_split_identifier_tokens(path.stem))
    markers.update(stem_tokens)
    if any(marker in _SERVICE_LAYER_EXCLUDED_MARKERS for marker in markers):
        return False
    return any(marker in _SERVICE_LAYER_PATH_MARKERS for marker in markers)


def _is_state_datetime_python_path(relative_path: str) -> bool:
    if _is_transport_python_path(relative_path) or not _is_runtime_python_path(relative_path):
        return False
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(Path(part).stem.lower() for part in path.parts)
    markers.update(_shared_split_identifier_tokens(path.stem))
    return any(marker in _STATE_DATETIME_PATH_MARKERS for marker in markers)


def _is_atomic_state_write_python_path(relative_path: str) -> bool:
    if not _is_runtime_python_path(relative_path):
        return False
    path = Path(relative_path)
    parts = {part.lower() for part in path.parts}
    if _ATOMIC_STATE_WRITE_WEBHOOK_DIRECTORY in parts:
        return True
    return (
        _ATOMIC_STATE_WRITE_EVENT_DIRECTORY in parts
        and path.stem.lower() in _ATOMIC_STATE_WRITE_EVENT_STEMS
    )


def _is_python_env_literal_review_path(relative_path: str) -> bool:
    if not _is_runtime_python_path(relative_path):
        return False
    return not (_python_path_markers(relative_path) & _ENV_LITERAL_REVIEW_EXCLUDED_PATH_MARKERS)


def _is_runtime_python_path(relative_path: str) -> bool:
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(Path(part).stem.lower() for part in path.parts)
    return not any(marker in _RUNTIME_EXCLUDED_PATH_MARKERS for marker in markers)


def _is_bare_except_cleanup_python_path(relative_path: str) -> bool:
    return _is_runtime_python_path(relative_path) and not (
        _python_path_markers(relative_path) & _BARE_EXCEPT_CLEANUP_EXCLUDED_PATH_MARKERS
    )


def _python_path_markers(relative_path: str) -> set[str]:
    path = Path(relative_path)
    markers: set[str] = set()
    for part in path.parts:
        lowered = part.lower()
        markers.add(lowered)
        stem = Path(part).stem.lower()
        markers.add(stem)
        markers.update(token.lower() for token in _shared_split_identifier_tokens(stem))
    return markers


def _split_python_identifier_tokens(value: str) -> frozenset[str]:
    if not value:
        return frozenset()
    normalized = value.lower().replace("-", "_").replace(".", "_")
    return frozenset(token.lower() for token in _shared_split_identifier_tokens(normalized))


def _python_ast_identifier_tokens(
    node: ast.AST | None,
    *,
    include_string_literals: bool = False,
    skip_nested_scopes: bool = False,
) -> frozenset[str]:
    if node is None:
        return frozenset()
    tokens: set[str] = set()

    def visit(current: ast.AST, *, is_root: bool = False) -> None:
        if (
            skip_nested_scopes
            and not is_root
            and isinstance(
                current,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
            )
        ):
            return
        if isinstance(current, ast.arg):
            tokens.update(_split_python_identifier_tokens(current.arg))
        elif isinstance(current, ast.Name):
            tokens.update(_split_python_identifier_tokens(current.id))
        elif isinstance(current, ast.Attribute):
            tokens.update(_split_python_identifier_tokens(current.attr))
        elif (
            include_string_literals
            and isinstance(current, ast.Constant)
            and isinstance(current.value, str)
        ):
            tokens.update(_split_python_identifier_tokens(current.value))
        for child in ast.iter_child_nodes(current):
            visit(child)

    visit(node, is_root=True)
    return frozenset(tokens)


def _python_scope_identifier_tokens(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    return _split_python_identifier_tokens(node.name) | _python_ast_identifier_tokens(
        node, skip_nested_scopes=True
    )


def _python_runtime_callable_context_tokens(
    relative_path: str, *, callable_name: str, container_name: str | None
) -> frozenset[str]:
    tokens = _python_path_markers(relative_path) | set(
        _split_python_identifier_tokens(callable_name)
    )
    if container_name is not None:
        tokens.update(_split_python_identifier_tokens(container_name))
    return frozenset(tokens)


def _python_first_matching_token(tokens: Iterable[str], candidates: Sequence[str]) -> str | None:
    token_set = set(tokens)
    for candidate in candidates:
        if candidate in token_set:
            return candidate
    return None


def _python_ast_equivalent(left: ast.AST | None, right: ast.AST | None) -> bool:
    if left is None or right is None:
        return False
    left_label = _python_expr_simple_label(left) if isinstance(left, ast.expr) else None
    right_label = _python_expr_simple_label(right) if isinstance(right, ast.expr) else None
    if left_label is not None and right_label is not None:
        return left_label == right_label
    return ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False)


def _looks_like_python_user_scoped_runtime_store_name(name: str) -> bool:
    tokens = _split_python_identifier_tokens(name)
    return bool(
        tokens & _USER_SCOPED_RUNTIME_STORE_CONTAINER_MARKERS
        and tokens & _USER_SCOPED_RUNTIME_STORE_CONTEXT_MARKERS
    )


def _python_user_scoped_store_key_kind(node: ast.expr) -> str | None:
    tokens = _python_ast_identifier_tokens(node)
    if not tokens or tokens & _TENANT_SCOPE_MARKERS:
        return None
    key_marker = _python_first_matching_token(tokens, _USER_SCOPED_RUNTIME_STORE_KEY_MARKERS)
    if key_marker is None:
        return None
    return f"{key_marker}-id"


def _looks_like_secret_env_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_").replace(".", "_")
    return _shared_is_strong_secret_name(normalized)


def _path_file_io_access_pattern(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in _REQUEST_FILE_IO_PATH_METHODS:
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Call):
        return None
    receiver_name = _resolve_call_name(receiver.func, aliases)
    if receiver_name not in {"Path", "pathlib.Path"}:
        return None
    return f"Path.{node.func.attr}"


def _iter_route_functions(
    parsed_file: _ParsedPythonFile,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(
            _is_route_decorator(decorator, parsed_file.import_aliases)
            for decorator in node.decorator_list
        ):
            yield node


def _iter_runtime_python_callables(
    module: ast.Module,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node
            continue
        if not isinstance(node, ast.ClassDef):
            continue
        for class_body_node in node.body:
            if isinstance(class_body_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield class_body_node


def _is_route_decorator(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    call_name = _resolve_call_name(target, aliases)
    if call_name is None:
        return False
    return call_name.rsplit(".", 1)[-1] in _ROUTE_DECORATOR_NAMES


def _python_naive_datetime_call_pattern(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    call_name = _resolve_call_name(node.func, aliases)
    if call_name is None:
        return None
    parts = call_name.split(".")
    if len(parts) < 2 or parts[-2] != "datetime":
        return None
    if parts[-1] == "utcnow":
        return "datetime.utcnow"
    if parts[-1] == "now" and not node.args and not node.keywords:
        return "datetime.now"
    return None


def _python_naive_datetime_default_factory_pattern(
    node: ast.expr, aliases: Mapping[str, str]
) -> str | None:
    if isinstance(node, ast.Attribute):
        call_name = _resolve_call_name(node, aliases)
        if call_name is None:
            return None
        parts = call_name.split(".")
        if len(parts) < 2 or parts[-2] != "datetime":
            return None
        if parts[-1] == "utcnow":
            return "datetime.utcnow"
        if parts[-1] == "now":
            return "datetime.now"
    if isinstance(node, ast.Lambda) and isinstance(node.body, ast.Call):
        return _python_naive_datetime_call_pattern(node.body, aliases)
    return None


def _python_direct_state_write_match(
    node: ast.Call, aliases: Mapping[str, str]
) -> tuple[str, str | None] | None:
    call_name = _resolve_call_name(node.func, aliases)
    if call_name is None or not call_name.endswith(".write_text"):
        return None
    payload = node.args[0] if node.args else _keyword_argument(node, "data")
    if payload is None or not _python_json_dump_expression(payload, aliases):
        return None
    target_name = call_name.removesuffix(".write_text")
    if _python_state_write_target_is_temporary(target_name):
        return None
    return ("Path.write_text", target_name)


def _python_async_with_state_write_matches(
    node: ast.AsyncWith, aliases: Mapping[str, str]
) -> Iterator[tuple[str, str | None]]:
    for item in node.items:
        if not isinstance(item.context_expr, ast.Call):
            continue
        context_name = _resolve_call_name(item.context_expr.func, aliases)
        if context_name != "aiofiles.open":
            continue
        target_expr = item.context_expr.args[0] if item.context_expr.args else None
        if target_expr is None:
            target_expr = _keyword_argument(item.context_expr, "file")
        mode_expr = item.context_expr.args[1] if len(item.context_expr.args) > 1 else None
        if mode_expr is None:
            mode_expr = _keyword_argument(item.context_expr, "mode")
        mode_value = _python_string_literal_value(mode_expr)
        if mode_value is None or not mode_value.startswith("w"):
            continue
        target_name = _resolve_call_name(target_expr, aliases) if target_expr is not None else None
        if _python_state_write_target_is_temporary(target_name):
            continue
        if not _python_async_with_contains_json_dump_write(node, aliases):
            continue
        yield ("aiofiles.open", target_name)


def _python_with_state_write_matches(
    node: ast.With, aliases: Mapping[str, str]
) -> Iterator[tuple[str, str | None]]:
    for item in node.items:
        if not isinstance(item.context_expr, ast.Call) or not isinstance(
            item.optional_vars, ast.Name
        ):
            continue
        write_context = _python_sync_with_state_write_context(item.context_expr, aliases)
        if write_context is None:
            continue
        write_pattern, target_name = write_context
        if _python_state_write_target_is_temporary(target_name):
            continue
        if not _python_with_contains_json_dump(
            node, handle_name=item.optional_vars.id, aliases=aliases
        ):
            continue
        yield write_pattern, target_name


def _python_sync_with_state_write_context(
    node: ast.Call, aliases: Mapping[str, str]
) -> tuple[str, str | None] | None:
    call_name = _resolve_call_name(node.func, aliases)
    if call_name == "open":
        target_expr = node.args[0] if node.args else _keyword_argument(node, "file")
        mode_expr = node.args[1] if len(node.args) > 1 else _keyword_argument(node, "mode")
        write_pattern = "open"
    elif isinstance(node.func, ast.Attribute) and node.func.attr == "open":
        target_expr = node.func.value
        mode_expr = node.args[0] if node.args else _keyword_argument(node, "mode")
        write_pattern = "Path.open"
    else:
        return None
    mode_value = _python_string_literal_value(mode_expr)
    if mode_value is None or not mode_value.startswith("w"):
        return None
    return write_pattern, _python_expr_simple_label(target_expr)


def _python_with_contains_json_dump(
    node: ast.With,
    *,
    handle_name: str,
    aliases: Mapping[str, str],
) -> bool:
    for descendant in ast.walk(node):
        if not isinstance(descendant, ast.Call):
            continue
        if _resolve_call_name(descendant.func, aliases) != "json.dump":
            continue
        target_expr = (
            descendant.args[1] if len(descendant.args) > 1 else _keyword_argument(descendant, "fp")
        )
        if isinstance(target_expr, ast.Name) and target_expr.id == handle_name:
            return True
    return False


def _python_async_with_contains_json_dump_write(
    node: ast.AsyncWith, aliases: Mapping[str, str]
) -> bool:
    for descendant in ast.walk(node):
        if not isinstance(descendant, ast.Call):
            continue
        if not isinstance(descendant.func, ast.Attribute) or descendant.func.attr != "write":
            continue
        payload = descendant.args[0] if descendant.args else _keyword_argument(descendant, "data")
        if payload is not None and _python_json_dump_expression(payload, aliases):
            return True
    return False


def _python_json_dump_expression(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _resolve_call_name(node.func, aliases) == "json.dumps"


def _python_string_literal_value(node: ast.expr | None) -> str | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    return node.value


def _python_state_write_target_is_temporary(target_name: str | None) -> bool:
    if not target_name:
        return False
    tokens = _shared_split_identifier_tokens(target_name.replace(".", "_"))
    return "temp" in tokens or "tmp" in tokens


def _is_python_dependency_boundary_call(call_name: str | None, *, outbound_only: bool) -> bool:
    if call_name is None:
        return False
    return _shared_looks_like_dependency_boundary_name(call_name, outbound_only=outbound_only)


def _python_global_resolution_call_match(
    *,
    call_name: str | None,
    root_name: str | None,
    aliases: Mapping[str, str],
    module_singletons: frozenset[str],
) -> tuple[str, str] | None:
    if call_name is None:
        return None
    if "._instance." in call_name:
        access_pattern = _python_registry_instance_access_pattern(call_name)
        if access_pattern is not None:
            return access_pattern, "registry-instance"
    holder_name = _python_locator_holder_name(
        call_name=call_name,
        root_name=root_name,
        aliases=aliases,
        module_singletons=module_singletons,
    )
    if holder_name is None:
        return None
    method_name = call_name.rsplit(".", 1)[-1]
    is_context_holder = _looks_like_python_context_holder_name(holder_name)
    is_locator_holder = _looks_like_python_locator_holder_name(holder_name)
    if is_context_holder and method_name == "get":
        return f"{holder_name}.get", "context-get"
    if is_locator_holder:
        return holder_name, "global-singleton"
    return None


def _python_registry_instance_assignment_match(
    value: ast.expr | None, aliases: Mapping[str, str]
) -> tuple[str, str] | None:
    access_pattern = _python_registry_instance_access_pattern(_resolve_call_name(value, aliases))
    if access_pattern is None:
        return None
    return access_pattern, "registry-instance"


def _python_registry_instance_access_pattern(call_name: str | None) -> str | None:
    if call_name is None or "._instance" not in call_name:
        return None
    owner_name = call_name.split("._instance", 1)[0].rsplit(".", 1)[-1]
    if not _looks_like_python_registry_owner_name(owner_name):
        return None
    return f"{owner_name}._instance"


def _python_locator_holder_name(
    *,
    call_name: str,
    root_name: str | None,
    aliases: Mapping[str, str],
    module_singletons: frozenset[str],
) -> str | None:
    if root_name is None:
        return None
    if root_name in module_singletons:
        return root_name
    imported_name = aliases.get(root_name)
    if imported_name is None:
        return None
    if call_name in (imported_name, root_name):
        return None
    imported_tail = imported_name.rsplit(".", 1)[-1]
    if imported_tail[:1].isupper():
        return None
    if _looks_like_python_context_holder_name(
        imported_tail
    ) or _looks_like_python_locator_holder_name(imported_tail):
        return imported_tail
    return None


def _looks_like_python_locator_holder_name(name: str) -> bool:
    tail_name = name.rsplit(".", 1)[-1]
    normalized = tail_name.lower()
    tokens = {token.lower() for token in _shared_split_identifier_tokens(tail_name)}
    return bool(tokens & _GLOBAL_LOCATOR_HOLDER_MARKERS) or (
        normalized in _GLOBAL_LOCATOR_EXACT_NAMES
    )


def _looks_like_python_context_holder_name(name: str) -> bool:
    tail_name = name.rsplit(".", 1)[-1]
    tokens = {token.lower() for token in _shared_split_identifier_tokens(tail_name)}
    return bool(tokens & _GLOBAL_CONTEXT_HOLDER_MARKERS)


def _looks_like_python_registry_owner_name(name: str) -> bool:
    tail_name = name.rsplit(".", 1)[-1]
    tokens = {token.lower() for token in _shared_split_identifier_tokens(tail_name)}
    return "registry" in tokens


def _enclosing_python_symbol(module: ast.Module, node: ast.AST) -> str | None:
    line_number = getattr(node, "lineno", None)
    end_line_number = getattr(node, "end_lineno", line_number)
    if line_number is None or end_line_number is None:
        return None
    candidates: list[tuple[int, str]] = []
    for candidate in ast.walk(module):
        if not isinstance(candidate, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        candidate_start = getattr(candidate, "lineno", None)
        candidate_end = getattr(candidate, "end_lineno", candidate_start)
        if candidate_start is None or candidate_end is None:
            continue
        if candidate_start <= line_number and end_line_number <= candidate_end:
            span = candidate_end - candidate_start
            candidates.append((span, candidate.name))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def _python_external_literal_kind(node: ast.expr | None, context_name: str | None) -> str | None:
    if node is None or context_name is None:
        return None
    literal_value = _literal_constant_value(node)
    if literal_value is None:
        return None
    normalized_context = _normalize_external_context_name(context_name)
    if isinstance(literal_value, str):
        if _EXTERNAL_URL_PATTERN.fullmatch(literal_value) and _context_matches_any_marker(
            normalized_context, _URL_CONTEXT_MARKERS
        ):
            return "service-url"
        if _EXTERNAL_DOMAIN_PATTERN.fullmatch(literal_value) and _context_matches_any_marker(
            normalized_context, _DOMAIN_CONTEXT_MARKERS
        ):
            return "public-domain"
        if _looks_like_database_name_context(
            normalized_context
        ) and _DATABASE_NAME_PATTERN.fullmatch(literal_value):
            return "database-default"
        if _looks_like_tenant_context(normalized_context) and literal_value.isdigit():
            return "tenant-default"
        return _external_identifier_kind(normalized_context, literal_value)
    if isinstance(literal_value, int) and _looks_like_tenant_context(normalized_context):
        return "tenant-default"
    return None


def _literal_constant_value(node: ast.expr | None) -> str | int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    ):
        return node.value
    return None


def _python_literal_value_for_metadata(node: ast.expr | None) -> str | None:
    literal_value = _literal_constant_value(node)
    if literal_value is None:
        return None
    return str(literal_value)


def _normalize_external_context_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _context_matches_any_marker(context_name: str, markers: frozenset[str]) -> bool:
    tokens = {token for token in context_name.replace("__", "_").split("_") if token}
    return any(marker in tokens or marker in context_name for marker in markers)


def _looks_like_tenant_context(context_name: str) -> bool:
    tokens = {token for token in context_name.replace("__", "_").split("_") if token}
    return "tenant" in tokens and ("id" in tokens or "code" in tokens)


def _looks_like_database_name_context(context_name: str) -> bool:
    if context_name in _DATABASE_CONTEXT_MARKERS:
        return True
    return context_name.endswith(("_database", "_database_name", "_db_name", "_dbname"))


def _external_identifier_kind(context_name: str, literal_value: str) -> str | None:
    if not _EXTERNAL_IDENTIFIER_PATTERN.fullmatch(literal_value):
        return None
    if "channel" in context_name:
        return "channel-identifier"
    if "provider" in context_name:
        return "provider-identifier"
    if "integration" in context_name:
        return "integration-identifier"
    if "owner" in context_name and "role" in context_name:
        return "owner-role-identifier"
    return None


def _iter_assignment_target_names(targets: Sequence[ast.expr]) -> Iterator[str]:
    for target in targets:
        target_name = _assignment_target_name(target)
        if target_name is not None:
            yield target_name


def _assignment_target_name(target: ast.expr | None) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _collect_python_module_singletons(parsed_file: _ParsedPythonFile) -> frozenset[str]:
    singleton_names: set[str] = set()
    for node in parsed_file.module.body:
        if isinstance(node, ast.Assign):
            target_names = tuple(_iter_assignment_target_names(node.targets))
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target_name = _assignment_target_name(node.target)
            target_names = (target_name,) if target_name is not None else ()
            value = node.value
        else:
            continue
        if not isinstance(value, ast.Call) or not target_names:
            continue
        constructor_name = _resolve_call_name(value.func, parsed_file.import_aliases)
        if constructor_name is None:
            continue
        for target_name in target_names:
            if _looks_like_python_locator_holder_name(target_name):
                singleton_names.add(target_name)
    return frozenset(singleton_names)


def _root_python_name(node: ast.expr) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _iter_function_default_external_literal_matches(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[_ExternalLiteralMatch]:
    positional_args = (*node.args.posonlyargs, *node.args.args)
    if node.args.defaults:
        default_args = positional_args[-len(node.args.defaults) :]
        for arg, default in zip(default_args, node.args.defaults, strict=True):
            literal_kind = _python_external_literal_kind(default, arg.arg)
            literal_value = _python_literal_value_for_metadata(default)
            if literal_kind is None or literal_value is None:
                continue
            yield _ExternalLiteralMatch(
                node=default,
                context_name=arg.arg,
                literal_kind=literal_kind,
                literal_value=literal_value,
            )
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        literal_kind = _python_external_literal_kind(default, arg.arg)
        literal_value = _python_literal_value_for_metadata(default)
        if literal_kind is None or literal_value is None:
            continue
        yield _ExternalLiteralMatch(
            node=default,
            context_name=arg.arg,
            literal_kind=literal_kind,
            literal_value=literal_value,
        )


def _looks_like_python_sql_execution_call(call_name: str | None) -> bool:
    if call_name is None:
        return False
    return call_name in {"execute", "executemany"} or call_name.endswith(
        (".execute", ".executemany")
    )


def _looks_like_python_sql_binding_name(name: str) -> bool:
    return bool(set(_shared_split_identifier_tokens(name)) & _SQL_LOCAL_NAME_MARKERS)


def _sql_expression_from_execution_call(
    node: ast.Call, aliases: Mapping[str, str]
) -> ast.expr | None:
    sql_expression = node.args[0] if node.args else None
    if sql_expression is None:
        for keyword_name in _SQL_EXECUTION_KEYWORDS:
            sql_expression = _keyword_argument(node, keyword_name)
            if sql_expression is not None:
                break
    if sql_expression is None:
        return None
    return _unwrap_python_sql_builder_call(sql_expression, aliases)


def _unwrap_python_sql_builder_call(node: ast.expr, aliases: Mapping[str, str]) -> ast.expr:
    if not isinstance(node, ast.Call):
        return node
    call_name = _resolve_call_name(node.func, aliases)
    if call_name not in _SQL_BUILDER_CALL_NAMES:
        return node
    if node.args:
        return node.args[0]
    return _keyword_argument(node, "text") or node


def _dynamic_python_sql_construction_kind(node: ast.expr) -> str | None:
    template = _python_sql_template(node)
    if (
        template is None
        or _SQL_KEYWORD_PATTERN.search(template) is None
        or _python_expression_is_static(node)
        or _python_sql_is_safe_identifier_interpolation(node)
    ):
        return None
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "string concatenation"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "percent formatting"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return "str.format"
    return None


def _python_sql_is_safe_identifier_interpolation(node: ast.expr) -> bool:
    if not isinstance(node, ast.JoinedStr):
        return False
    formatted_nodes = [value for value in node.values if isinstance(value, ast.FormattedValue)]
    if not formatted_nodes:
        return False
    if not all(_python_sql_identifier_expression(value.value) for value in formatted_nodes):
        return False
    template = _python_joined_str_template(node, "__sql_slot__")
    normalized = " ".join(template.lower().split()).rstrip(";")
    if normalized == "create schema if not exists __sql_slot__":
        return True
    for index, value in enumerate(node.values):
        if not isinstance(value, ast.FormattedValue):
            continue
        next_value = node.values[index + 1] if index + 1 < len(node.values) else None
        next_text = _python_joined_str_constant_text(next_value)
        if not next_text.lstrip().startswith("."):
            return False
    return True


def _python_joined_str_template(node: ast.JoinedStr, placeholder: str) -> str:
    fragments: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            fragments.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            fragments.append(placeholder)
        else:
            return ""
    return "".join(fragments)


def _python_joined_str_constant_text(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _python_sql_identifier_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return _python_sql_identifier_expression(node.value)
    return False


def _python_sql_template(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        fragments: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                fragments.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                fragments.append("{}")
            else:
                return None
        return "".join(fragments)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_sql_template(node.left)
        right = _python_sql_template(node.right)
        if left is None and right is None:
            return None
        return f"{left or '{}'}{right or '{}'}"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _python_sql_template(node.left)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _python_sql_template(node.func.value)
    return None


def _python_expression_is_static(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(_python_expression_is_static(value) for value in node.values)
    if isinstance(node, ast.FormattedValue):
        return _python_expression_is_static(node.value) and (
            node.format_spec is None or _python_expression_is_static(node.format_spec)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _python_expression_is_static(node.left) and _python_expression_is_static(node.right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return (
            _python_expression_is_static(node.func.value)
            and all(_python_expression_is_static(argument) for argument in node.args)
            and all(_python_expression_is_static(keyword.value) for keyword in node.keywords)
        )
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_python_expression_is_static(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            _python_expression_is_static(key) and _python_expression_is_static(value)
            for key, value in zip(node.keys, node.values, strict=False)
            if key is not None
        )
    return False


def _normalize_blocking_call_name(call_name: str | None) -> str | None:
    if call_name is None:
        return None
    if call_name == "time.sleep":
        return call_name
    if call_name in {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }:
        return call_name
    if call_name == "open":
        return call_name
    if any(call_name == f"requests.{method}" for method in _REQUESTS_METHODS):
        return call_name
    if call_name == "urllib.request.urlopen":
        return call_name
    return None


def _blocking_call_suggestion(call_name: str) -> str:
    if call_name in _BLOCKING_CALL_SUGGESTIONS:
        return _BLOCKING_CALL_SUGGESTIONS[call_name]
    if call_name.startswith("requests."):
        return (
            "Use an async HTTP client such as httpx.AsyncClient or move the call "
            "to asyncio.to_thread(...)."
        )
    return (
        "Move the blocking work to asyncio.to_thread(...) or replace it with an async-native API."
    )


def _line_in_scope(changed_lines: frozenset[int] | None, line: int) -> bool:
    return changed_lines is None or line in changed_lines


def _lines_intersect(changed_lines: frozenset[int] | None, line_range: range) -> bool:
    return changed_lines is None or any(line in changed_lines for line in line_range)


def _python_file_has_changed_behavior_lines(parsed_file: _ParsedPythonFile) -> bool:
    if parsed_file.changed_lines is None:
        return True
    for line_number in parsed_file.changed_lines:
        if line_number < 1 or line_number > len(parsed_file.source_lines):
            continue
        line = parsed_file.source_lines[line_number - 1]
        if line.strip() and not line.lstrip().startswith("#"):
            return True
    return False


def _effective_python_module_line_count(source_lines: Sequence[str]) -> int:
    return sum(1 for line in source_lines if line.strip() and not line.lstrip().startswith("#"))


def _effective_python_line_count(
    source_lines: Sequence[str], node: ast.FunctionDef | ast.AsyncFunctionDef
) -> int:
    line_range = _node_line_range(node)
    if line_range.start <= 0:
        return 0
    return sum(
        1
        for line in source_lines[line_range.start - 1 : line_range.stop - 1]
        if line.strip() and not line.lstrip().startswith("#")
    )


def _python_branch_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    visitor = _PythonBranchComplexityVisitor(node)
    visitor.visit(node)
    return visitor.complexity


def _python_max_control_nesting(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    return _python_statement_max_control_nesting(node.body, depth=0)


def _python_statement_max_control_nesting(statements: Sequence[ast.stmt], *, depth: int) -> int:
    max_depth = depth
    for statement in statements:
        max_depth = max(max_depth, _python_node_max_control_nesting(statement, depth=depth))
    return max_depth


def _python_node_max_control_nesting(node: ast.AST, *, depth: int) -> int:
    if isinstance(node, ast.If):
        current_depth = depth + 1
        max_depth = max(
            current_depth,
            _python_statement_max_control_nesting(node.body, depth=current_depth),
        )
        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            return max(max_depth, _python_node_max_control_nesting(node.orelse[0], depth=depth))
        return max(
            max_depth,
            _python_statement_max_control_nesting(node.orelse, depth=current_depth),
        )
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        current_depth = depth + 1
        return max(
            current_depth,
            _python_statement_max_control_nesting(node.body, depth=current_depth),
            _python_statement_max_control_nesting(node.orelse, depth=current_depth),
        )
    if isinstance(node, ast.Try):
        current_depth = depth + 1
        max_depth = max(
            current_depth,
            _python_statement_max_control_nesting(node.body, depth=current_depth),
            _python_statement_max_control_nesting(node.orelse, depth=current_depth),
            _python_statement_max_control_nesting(node.finalbody, depth=current_depth),
        )
        for handler in node.handlers:
            max_depth = max(
                max_depth,
                _python_statement_max_control_nesting(handler.body, depth=current_depth),
            )
        return max_depth
    if isinstance(node, ast.Match):
        current_depth = depth + 1
        max_depth = current_depth
        for case in node.cases:
            max_depth = max(
                max_depth,
                _python_statement_max_control_nesting(case.body, depth=current_depth),
            )
        return max_depth
    return depth


def _changed_python_test_paths(changed_files: Sequence[str]) -> frozenset[str]:
    normalized_paths: set[str] = set()
    for changed_file in changed_files:
        normalized = changed_file.replace("\\", "/")
        if not normalized.endswith(".py"):
            continue
        file_name = Path(normalized).name
        if (
            normalized.startswith("tests/")
            or "/tests/" in normalized
            or file_name.startswith("test_")
            or file_name.endswith("_test.py")
        ):
            normalized_paths.add(normalized)
    return frozenset(normalized_paths)


def _first_changed_python_line(parsed_file: _ParsedPythonFile) -> int:
    if parsed_file.changed_lines is not None:
        for line_number in sorted(parsed_file.changed_lines):
            if 1 <= line_number <= len(parsed_file.source_lines):
                line = parsed_file.source_lines[line_number - 1]
                if line.strip() and not line.lstrip().startswith("#"):
                    return line_number
    return 1


def _python_name_tokens(value: str) -> frozenset[str]:
    return frozenset(token for token in re.split(r"[^a-z0-9]+", value.lower()) if token)


def _python_path_tokens(relative_path: str) -> frozenset[str]:
    path = Path(relative_path.replace("\\", "/"))
    tokens: set[str] = set()
    for part in path.parts:
        tokens.update(_python_name_tokens(Path(part).stem))
    return frozenset(tokens)


def _is_ingress_python_path(relative_path: str) -> bool:
    path = Path(relative_path.replace("\\", "/"))
    if path.suffix.lower() != ".py" or "tests" in path.parts:
        return False
    return _is_transport_python_path(relative_path) and any(
        part in _INGRESS_NORMALIZATION_DIRECTORY_NAMES for part in path.parts
    )


def _is_contract_surface_python_path(relative_path: str) -> bool:
    path = Path(relative_path.replace("\\", "/"))
    if path.suffix.lower() != ".py" or "tests" in path.parts:
        return False
    stem = path.stem.lower()
    return (
        any(part in _CONTRACT_SURFACE_DIRECTORY_MARKERS for part in path.parts)
        or bool(_python_path_tokens(relative_path) & _CONTRACT_SURFACE_STEM_MARKERS)
        or stem in _CONTRACT_SURFACE_EXACT_STEMS
    )


def _is_deploy_env_surface_python_path(relative_path: str) -> bool:
    path = Path(relative_path.replace("\\", "/"))
    if path.suffix.lower() != ".py" or "tests" in path.parts:
        return False
    return any(part in _DEPLOY_ENV_DIRECTORY_MARKERS for part in path.parts) or bool(
        _python_path_tokens(relative_path) & _DEPLOY_ENV_STEM_MARKERS
    )


def _matching_contract_canary_test_paths(
    relative_path: str, *, test_paths: frozenset[str]
) -> tuple[str, ...]:
    source_tokens = _python_path_tokens(relative_path) - {"src", "test", "tests"}
    matches = [
        test_path
        for test_path in sorted(test_paths)
        if _python_path_tokens(test_path) & _CONTRACT_TEST_MARKERS
        and _python_path_tokens(test_path) & source_tokens
    ]
    return tuple(matches)


def _matching_deploy_env_test_paths(
    relative_path: str, *, test_paths: frozenset[str]
) -> tuple[str, ...]:
    source_tokens = _python_path_tokens(relative_path)
    expected_markers = set(source_tokens & _DEPLOY_ENV_TEST_MARKERS)
    if "config" in Path(relative_path.replace("\\", "/")).parts:
        expected_markers.add("config")
    if not expected_markers:
        expected_markers.add("config")
    matches = [
        test_path
        for test_path in sorted(test_paths)
        if _python_path_tokens(test_path) & frozenset(expected_markers)
    ]
    return tuple(matches)


def _suggest_contract_canary_paths(relative_path: str) -> tuple[str, ...]:
    tokens = _python_path_tokens(relative_path)
    candidates: list[str] = []
    if {"platform", "contracts"} <= tokens:
        candidates.append("tests/test_platform_sidecar_contracts.py")
    if {"booking", "contract"} & tokens:
        candidates.append("tests/test_external_booking_contract.py")
    if {"sidecar", "eval", "gates"} <= tokens:
        candidates.append("tests/test_sidecar_eval_gates.py")
    flattened = _python_runtime_test_flattened_name(relative_path)
    if flattened:
        candidates.append(Path("tests", f"test_{flattened}_contracts.py").as_posix())
    return _unique_preserving_order(candidates)


def _suggest_deploy_env_test_paths(relative_path: str) -> tuple[str, ...]:
    tokens = _python_path_tokens(relative_path)
    candidates: list[str] = []
    if "config" in tokens:
        candidates.append("tests/test_config.py")
    if {"sidecar", "config"} <= tokens:
        candidates.append("tests/test_sidecar_config.py")
    if {"tenant", "readiness"} <= tokens or "readiness" in tokens:
        candidates.append("tests/test_tenant_readiness.py")
    if {"tenant", "snapshot"} <= tokens or "snapshot" in tokens:
        candidates.append("tests/test_tenant_config_snapshot.py")
    if "health" in tokens:
        candidates.append("tests/test_health_detailed.py")
    return _unique_preserving_order(candidates)


def _unique_preserving_order(values: Sequence[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _iter_webhook_payload_without_normalization_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_IngressNormalizationMatch]:
    if not _is_ingress_python_path(parsed_file.relative_path):
        return

    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        if _python_name_tokens(callable_node.name) & _INGRESS_NORMALIZATION_HELPER_MARKERS:
            continue
        if _callable_uses_ingress_normalizer(callable_node, parsed_file.import_aliases):
            continue

        seen_patterns: set[tuple[int, str]] = set()
        for node in ast.walk(callable_node):
            chain = _python_mapping_access_chain(node)
            if chain is None:
                continue
            root_name, keys = chain
            if root_name not in _INGRESS_NORMALIZATION_RAW_ROOT_NAMES or len(keys) < 2:
                continue
            payload_key = next(
                (key for key in keys if key in _INGRESS_NORMALIZATION_CONTEXT_KEYS),
                None,
            )
            if payload_key is None:
                continue
            access_pattern = root_name + "".join(f"[{key}]" for key in keys)
            dedupe_key = (getattr(node, "lineno", 0), access_pattern)
            if dedupe_key in seen_patterns:
                continue
            seen_patterns.add(dedupe_key)
            yield _IngressNormalizationMatch(
                node=node,
                access_pattern=access_pattern,
                payload_key=payload_key,
                symbol=callable_node.name,
            )


def _callable_uses_ingress_normalizer(
    node: ast.FunctionDef | ast.AsyncFunctionDef, aliases: Mapping[str, str]
) -> bool:
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        call_name = _resolve_call_name(candidate.func, aliases) or _python_access_path(
            candidate.func
        )
        if call_name is None:
            continue
        if _python_name_tokens(call_name) & _INGRESS_NORMALIZATION_HELPER_MARKERS:
            return True
    return False


def _python_mapping_access_chain(node: ast.AST) -> tuple[str, tuple[str, ...]] | None:
    if isinstance(node, ast.Subscript):
        key_name = _python_subscript_key_name(node.slice)
        if key_name is None:
            return None
        base_chain = _python_mapping_access_chain(node.value)
        if base_chain is None:
            root_name = _root_python_name(node.value) if isinstance(node.value, ast.expr) else None
            if root_name is None:
                return None
            return root_name, (key_name,)
        root_name, keys = base_chain
        return root_name, (*keys, key_name)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        key_name = _literal_constant_value(node.args[0])
        if not isinstance(key_name, str):
            return None
        base_chain = _python_mapping_access_chain(node.func.value)
        if base_chain is None:
            root_name = _root_python_name(node.func.value)
            if root_name is None:
                return None
            return root_name, (key_name,)
        root_name, keys = base_chain
        return root_name, (*keys, key_name)
    if isinstance(node, ast.Name):
        return node.id, ()
    if isinstance(node, ast.Attribute):
        access_path = _python_access_path(node)
        if access_path is None:
            return None
        return access_path, ()
    return None


def _find_nearby_python_test_path(
    relative_path: str, *, discovered_python_test_paths: frozenset[str]
) -> str | None:
    for candidate in _python_runtime_test_candidate_paths(relative_path):
        if candidate in discovered_python_test_paths:
            return candidate
    return None


def _preferred_python_runtime_test_patterns(relative_path: str) -> tuple[str, ...]:
    candidates = _python_runtime_test_candidate_paths(relative_path)
    preferred = tuple(candidate for candidate in candidates if candidate.startswith("tests/"))
    if preferred:
        return preferred[:4]
    return candidates[:4]


def _python_runtime_test_candidate_paths(relative_path: str) -> tuple[str, ...]:
    path = Path(relative_path.replace("\\", "/"))
    if path.suffix.lower() != ".py":
        return ()

    file_name_variants = (f"test_{path.stem}.py", f"{path.stem}_test.py")
    candidates: list[str] = []

    parts = path.parts
    if "src" in parts:
        src_index = parts.index("src")
        mirrored_parent = Path(*parts[:src_index], "tests", *parts[src_index + 1 : -1])
    else:
        mirrored_parent = Path("tests", *parts[:-1])
    for file_name in file_name_variants:
        candidates.append((mirrored_parent / file_name).as_posix())

    flattened_name = _python_runtime_test_flattened_name(relative_path)
    if flattened_name:
        candidates.extend(
            (
                Path("tests", f"test_{flattened_name}.py").as_posix(),
                Path("tests", f"{flattened_name}_test.py").as_posix(),
            )
        )

    for file_name in file_name_variants:
        candidates.extend(
            (
                Path("tests", file_name).as_posix(),
                (path.parent / "tests" / file_name).as_posix(),
                (path.parent / "__tests__" / file_name).as_posix(),
                (path.parent / file_name).as_posix(),
            )
        )

    unique_candidates: list[str] = []
    seen_candidates: set[str] = set()
    for candidate in candidates:
        if candidate in seen_candidates:
            continue
        seen_candidates.add(candidate)
        unique_candidates.append(candidate)
    return tuple(unique_candidates)


def _python_runtime_test_flattened_name(relative_path: str) -> str:
    path = Path(relative_path.replace("\\", "/"))
    parts = path.parts
    relevant_parts = parts[:-1]
    if "src" in parts:
        relevant_parts = parts[parts.index("src") + 1 : -1]
    flattened_parts = [
        Path(part).stem for part in relevant_parts if part not in {"tests", "__tests__"}
    ]
    flattened_parts.append(path.stem)
    return "_".join(part for part in flattened_parts if part)


def _changed_lines_for_path(
    *, repo_root: Path, relative_path: str, mode: ExecutionMode, total_lines: int
) -> frozenset[int] | None:
    if mode is not ExecutionMode.DIFF:
        return None

    git_changed_lines = _git_changed_lines(repo_root=repo_root, relative_path=relative_path)
    if git_changed_lines is not None:
        return git_changed_lines
    return frozenset(range(1, total_lines + 1))


def _git_changed_lines(*, repo_root: Path, relative_path: str) -> frozenset[int] | None:
    diff_command = [
        "git",
        "-C",
        str(repo_root),
        "--no-pager",
        "diff",
        "--no-color",
        "--unified=0",
        "HEAD",
        "--",
        relative_path,
    ]
    try:
        completed = subprocess.run(
            diff_command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    changed_lines = _parse_unified_diff_changed_lines(completed.stdout)
    if changed_lines:
        return changed_lines

    untracked_command = [
        "git",
        "-C",
        str(repo_root),
        "--no-pager",
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        relative_path,
    ]
    try:
        untracked = subprocess.run(
            untracked_command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    if untracked.stdout.strip():
        return None
    return None


def _parse_unified_diff_changed_lines(diff_output: str) -> frozenset[int]:
    changed_lines: set[int] = set()
    for line in diff_output.splitlines():
        if not line.startswith("@@"):
            continue
        _, _, new_section, *_ = line.split(" ")
        start_text, _, length_text = new_section[1:].partition(",")
        start_line = int(start_text)
        length = int(length_text) if length_text else 1
        for line_number in range(start_line, start_line + length):
            changed_lines.add(line_number)
    return frozenset(changed_lines)


def _normalized_end_column(node: ast.Call) -> int | None:
    end_col_offset = getattr(node, "end_col_offset", None)
    if isinstance(end_col_offset, int):
        return end_col_offset + 1
    return None


def _normalized_node_end_column(node: ast.AST) -> int | None:
    end_col_offset = getattr(node, "end_col_offset", None)
    if isinstance(end_col_offset, int):
        return end_col_offset + 1
    return None


def _node_line_range(node: ast.AST) -> range:
    start_line = getattr(node, "lineno", None)
    if not isinstance(start_line, int):
        return range(0, 0)
    end_line = getattr(node, "end_lineno", start_line)
    if not isinstance(end_line, int):
        end_line = start_line
    return range(start_line, end_line + 1)


def _iter_unvalidated_llm_output_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_LlmOutputMatch]:
    for route_function in _iter_route_functions(parsed_file):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(route_function)}
        parent_map = _python_parent_map(route_function)
        llm_names: set[str] = set()
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases)
            if call_name is not None and any(
                call_name.endswith(tail) for tail in _LLM_OUTPUT_CALL_NAMES
            ):
                parent = parent_map.get(node)
                if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
                    if isinstance(parent.targets[0], ast.Name):
                        llm_names.add(parent.targets[0].id)
                elif isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
                    llm_names.add(parent.target.id)
                elif isinstance(parent, ast.Return):
                    llm_names.add("<direct-return>")
        if not llm_names:
            continue
        validated: set[str] = set()
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if "validate" in call_name or "gate" in call_name:
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        validated.add(arg.id)
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if not any(marker in call_name for marker in _CUSTOMER_CHANNEL_SEND_NAMES):
                continue
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                if isinstance(arg, ast.Name) and arg.id in llm_names and arg.id not in validated:
                    yield _LlmOutputMatch(
                        node=node, access_pattern=call_name, symbol=route_function.name
                    )
                    break


def _iter_raw_tool_response_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ToolResponseMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(callable_node)}
        parent_map = _python_parent_map(callable_node)
        tool_names: set[str] = set()
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if any(marker in call_name for marker in _TOOL_CALL_NAMES):
                parent = parent_map.get(node)
                if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
                    if isinstance(parent.targets[0], ast.Name):
                        tool_names.add(parent.targets[0].id)
                elif isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
                    tool_names.add(parent.target.id)
        if not tool_names:
            continue
        stripped: set[str] = set()
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if "_strip_fields" in call_name or "redact" in call_name:
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        stripped.add(arg.id)
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if not any(marker in call_name for marker in _LLM_OUTPUT_CALL_NAMES):
                continue
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                if isinstance(arg, ast.Name) and arg.id in tool_names and arg.id not in stripped:
                    yield _ToolResponseMatch(
                        node=node,
                        access_pattern=call_name,
                        symbol=callable_node.name,
                    )
                    break


def _iter_generic_session_identity_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_SessionIdentityMatch]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or "session" not in target.id.lower():
            continue
        value = _literal_constant_value(node.value)
        if not isinstance(value, str) or value.lower() not in _GENERIC_SESSION_IDS:
            continue
        yield _SessionIdentityMatch(node=node, session_name=target.id, literal_value=value)


def _iter_mcp_process_leak_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_McpProcessLeakMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(callable_node)}
        has_cleanup = any(
            isinstance(child, ast.Try) and bool(child.finalbody)
            for child in ast.walk(callable_node)
        )
        if not has_cleanup:
            has_cleanup = any(
                isinstance(node, ast.Call)
                and _resolve_call_name(node.func, aliases) in {"atexit.register", "atexit"}
                for node in ast.walk(callable_node)
            )
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases)
            if call_name is not None and any(
                call_name.endswith(tail) for tail in _MCP_CONSTRUCTOR_NAMES
            ):
                if not has_cleanup:
                    yield _McpProcessLeakMatch(
                        node=node,
                        constructor_name=call_name,
                        symbol=callable_node.name,
                    )


def _iter_timeout_kwarg_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_TimeoutKwargsMatch]:
    for async_node, container_name in _iter_async_callables(parsed_file.module):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(async_node)}
        symbol = _python_scoped_symbol_name(async_node.name, container_name)
        for node in ast.walk(async_node):
            if not isinstance(node, ast.Call):
                continue
            if not any(kw.arg == "timeout" for kw in node.keywords):
                continue
            call_name = _resolve_call_name(node.func, aliases)
            if call_name in {"asyncio.wait_for", "wait_for"}:
                continue
            yield _TimeoutKwargsMatch(
                node=node,
                call_name=call_name or "<dynamic>",
                symbol=symbol,
            )


def _iter_webhook_replay_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_WebhookReplayMatch]:
    if not _is_webhook_python_path(parsed_file.relative_path):
        return
    for route_function in _iter_route_functions(parsed_file):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(route_function)}
        has_verify = False
        has_origin_check = False
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if any(marker in call_name for marker in _WEBHOOK_VERIFY_MARKERS):
                has_verify = True
            if any(marker in call_name for marker in _ORIGIN_VALIDATE_MARKERS):
                has_origin_check = True
        if has_verify and not has_origin_check:
            yield _WebhookReplayMatch(
                node=route_function,
                access_pattern="missing-origin-validation",
                symbol=route_function.name,
            )


def _iter_db_sslmode_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_DbSslmodeMatch]:
    for node in ast.walk(parsed_file.module):
        text: str | None = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = _python_joined_str_template(node, "{}")
        if text is None:
            continue
        lowered = text.lower()
        if "sslmode=require" not in lowered:
            continue
        if "ssl=require" in lowered or "verify-full" in lowered:
            yield _DbSslmodeMatch(node=node, literal_value=text)


def _iter_chain_confirmation_external_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ChainConfirmationMatch]:
    path_markers = _python_path_markers(parsed_file.relative_path)
    if not path_markers & _EXTERNAL_CHANNEL_NAMES:
        return
    for route_function in _iter_route_functions(parsed_file):
        func_tokens = _split_python_identifier_tokens(route_function.name)
        if not func_tokens & _CHAIN_CONFIRMATION_MARKERS:
            continue
        yield _ChainConfirmationMatch(
            node=route_function,
            access_pattern=route_function.name,
            symbol=route_function.name,
        )


def _iter_context_manager_exit_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_ContextManagerExitMatch]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, ast.FunctionDef) or node.name != "__exit__":
            continue
        has_return_false = False
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                if child.value is None or isinstance(child.value, ast.Constant) and child.value.value is False:
                    has_return_false = True
        if not has_return_false:
            yield _ContextManagerExitMatch(
                node=node,
                symbol=_enclosing_python_symbol(parsed_file.module, node),
            )


def _iter_commerce_price_leak_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_CommercePriceLeakMatch]:
    if not _is_transport_python_path(parsed_file.relative_path):
        return
    for node in ast.walk(parsed_file.module):
        text: str | None = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = _python_joined_str_template(node, "{}")
        if text is None:
            continue
        lowered = text.lower()
        if any(marker in lowered for marker in _COMMERCE_PRICE_MARKERS):
            yield _CommercePriceLeakMatch(
                node=node,
                literal_value=text,
                symbol=_enclosing_python_symbol(parsed_file.module, node),
            )


def _iter_employee_payroll_leak_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_PayrollLeakMatch]:
    if not _is_transport_python_path(parsed_file.relative_path):
        return
    for node in ast.walk(parsed_file.module):
        text: str | None = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = _python_joined_str_template(node, "{}")
        if text is None:
            continue
        lowered = text.lower()
        if any(marker in lowered for marker in _PAYROLL_MARKERS):
            yield _PayrollLeakMatch(
                node=node,
                literal_value=text,
                symbol=_enclosing_python_symbol(parsed_file.module, node),
            )


def _iter_tenant_shared_webhook_secret_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_TenantWebhookSecretMatch]:
    if not _is_webhook_python_path(parsed_file.relative_path):
        return
    module_globals: set[str] = set()
    for node in parsed_file.module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if any(marker in target.id for marker in _WEBHOOK_SECRET_GLOBAL_MARKERS):
                        module_globals.add(target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                if any(marker in node.target.id for marker in _WEBHOOK_SECRET_GLOBAL_MARKERS):
                    module_globals.add(node.target.id)
    for route_function in _iter_route_functions(parsed_file):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(route_function)}
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if not any(marker in call_name for marker in _WEBHOOK_VERIFY_MARKERS):
                continue
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                if isinstance(arg, ast.Name) and arg.id in module_globals:
                    yield _TenantWebhookSecretMatch(
                        node=node,
                        access_pattern=arg.id,
                        symbol=route_function.name,
                    )
                    break


def _iter_lifespan_cleanup_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_LifespanCleanupMatch]:
    for node in ast.walk(parsed_file.module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_lifespan = node.name == "lifespan"
        if not is_lifespan:
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                call_name = _resolve_call_name(target, parsed_file.import_aliases)
                if call_name is not None and any(
                    call_name.endswith(tail) for tail in _LIFESPAN_DECORATOR_NAMES
                ):
                    is_lifespan = True
                    break
        if not is_lifespan:
            continue
        has_try = any(isinstance(child, ast.Try) for child in ast.walk(node) if child is not node)
        if not has_try:
            yield _LifespanCleanupMatch(node=node, symbol=node.name)


def _iter_orphaned_async_task_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_OrphanedAsyncTaskMatch]:
    for route_function in _iter_route_functions(parsed_file):
        aliases = {**parsed_file.import_aliases, **_collect_nested_import_aliases(route_function)}
        if not any(
            decorator_name in (route_function.name.lower() + " ")
            for decorator_name in _WEBSOCKET_ROUTE_MARKERS
        ):
            has_ws_decorator = any(
                (
                    _resolve_call_name(d.func if isinstance(d, ast.Call) else d, aliases) or ""
                ).rsplit(".", 1)[-1]
                in _WEBSOCKET_ROUTE_MARKERS
                for d in route_function.decorator_list
            )
            if not has_ws_decorator:
                continue
        has_cancel = False
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases) or ""
            if ".cancel" in call_name or "cancel" in call_name:
                has_cancel = True
                break
        for node in ast.walk(route_function):
            if not isinstance(node, ast.Call):
                continue
            call_name = _resolve_call_name(node.func, aliases)
            if call_name not in _ASYNC_TASK_LAUNCH_CALL_NAMES:
                continue
            if not has_cancel:
                yield _OrphanedAsyncTaskMatch(
                    node=node,
                    access_pattern=call_name,
                    symbol=route_function.name,
                )


def _iter_retry_counter_matches(
    parsed_file: _ParsedPythonFile,
) -> Iterator[_RetryCounterMatch]:
    for callable_node in _iter_runtime_python_callables(parsed_file.module):
        tokens = _split_python_identifier_tokens(callable_node.name)
        if not tokens & _RETRY_LOOP_MARKERS:
            continue
        has_aggregation = any(
            isinstance(node, ast.Call)
            and _resolve_call_name(node.func, parsed_file.import_aliases) in {"max", "aggregate"}
            for node in ast.walk(callable_node)
        )
        if has_aggregation:
            continue
        for node in ast.walk(callable_node):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr == "reference":
                parent = _python_access_path(node.value)
                if parent is not None and "issue" in parent.lower():
                    yield _RetryCounterMatch(
                        node=node,
                        access_pattern=f"{parent}.reference",
                        symbol=callable_node.name,
                    )
                    break


def _is_webhook_python_path(relative_path: str) -> bool:
    path = Path(relative_path.replace("\\", "/"))
    return any(part in _WEBHOOK_HANDLER_PATH_MARKERS for part in path.parts)


DEFAULT_ADAPTERS = (PythonAdapter(),)
