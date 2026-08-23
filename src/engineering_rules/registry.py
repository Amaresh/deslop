"""Rule registry and taxonomy for cross-language engineering rules."""

from __future__ import annotations

from collections.abc import Iterable

from .models import (
    FindingConfidence,
    FindingSeverity,
    RepoLanguage,
    RuleCategory,
    RuleDefinition,
)
from .framework_compat import enrich_rule_frameworks

_ALL_LANGUAGES = tuple(language for language in RepoLanguage)
_ACTIVE_BACKEND_RULE_IDS = frozenset(
    {
        "go.architecture.no-handler-concrete-dependency",
        "go.architecture.no-handler-detached-goroutine",
        "go.architecture.no-handler-direct-outbound-http",
        "go.architecture.no-handler-direct-sql-execution",
        "go.architecture.no-handler-log-only-background-outcome",
        "go.architecture.no-handler-rooted-background-context",
        "go.architecture.no-handler-service-locator-access",
        "go.architecture.no-handler-terminal-response-fallthrough",
        "go.architecture.no-service-layer-detached-goroutine",
        "go.architecture.no-service-layer-log-only-background-outcome",
        "go.architecture.no-service-layer-outbound-client-construction",
        "go.architecture.no-service-layer-rooted-background-context",
        "go.architecture.no-service-layer-service-locator-access",
        "go.config.no-handler-env-read",
        "go.reliability.no-handler-request-json-decode-without-strict-decoder",
        "go.reliability.no-hardcoded-external-literals",
        "go.security.no-dynamic-sql-execution",
        "go.security.no-handler-error-detail-response",
        "go.security.no-raw-credential-logging",
        "go.security.no-raw-pii-logging",
        "go.security.no-secret-fallback-literal",
        "java.architecture.event-listener-needs-transaction-phase-boundary",
        "java.architecture.no-controller-direct-repository-access",
        "java.architecture.no-entity-crossing-async-or-requires-new-boundary",
        "java.architecture.no-service-layer-detached-async-launch",
        "java.architecture.no-service-layer-log-only-async-outcome",
        "java.architecture.no-service-layer-objectprovider-circular-self-reference",
        "java.architecture.no-service-layer-outbound-client-construction",
        "java.architecture.no-service-layer-rest-template-without-timeout-shaping",
        "java.architecture.no-service-layer-service-locator-access",
        "java.architecture.no-service-layer-transactional-external-io",
        "java.architecture.no-web-layer-concrete-dependency",
        "java.architecture.no-web-layer-detached-async-launch",
        "java.architecture.no-web-layer-local-file-io",
        "java.architecture.no-web-layer-log-only-async-outcome",
        "java.architecture.no-web-layer-service-locator-access",
        "java.architecture.no-web-layer-terminal-response-fallthrough",
        "java.concurrency.no-concurrentmap-scheduled-unsafe-removal",
        "java.concurrency.no-static-lock-pool-without-eviction",
        "java.config.no-web-layer-value-injection",
        "java.maintainability.no-cyclomatic-hotspot-method",
        "java.maintainability.no-exception-swallowing-in-critical-paths",
        "java.maintainability.no-oversized-service-class",
        "java.maintainability.no-oversized-service-method",
        "java.reliability.no-batch-saveall-without-partial-failure-guard",
        "java.reliability.no-hardcoded-external-literals",
        "java.reliability.no-nonadditive-flyway-migration",
        "java.reliability.no-unbounded-findall-without-pagination",
        "java.security.no-auth-filter-broad-exception-fallthrough",
        "java.security.no-dynamic-sql-execution",
        "java.security.no-raw-credential-logging",
        "java.security.no-raw-pii-logging",
        "java.security.no-secret-fallback-literal",
        "java.testing.no-scheduled-service-without-scheduler-test",
        "java.testing.no-controller-without-test-class",
        "python.error-handling.no-bare-except-cleanup",
        "python.architecture.no-daemon-task-without-failure-sink",
        "python.architecture.no-public-fastapi-model-without-field-aliases",
        "python.architecture.no-request-layer-concrete-dependency",
        "python.architecture.no-request-layer-detached-async-task",
        "python.architecture.no-request-layer-global-collaborator-resolution",
        "python.architecture.no-request-layer-local-file-io",
        "python.architecture.no-request-layer-log-only-task-exception-sink",
        "python.architecture.no-request-layer-thread-hop-without-context-copy",
        "python.architecture.no-service-layer-detached-async-task",
        "python.architecture.no-service-layer-global-collaborator-resolution",
        "python.architecture.no-service-layer-httpx-client-without-timeout-shaping",
        "python.architecture.no-service-layer-log-only-task-exception-sink",
        "python.architecture.no-service-layer-outbound-client-construction",
        "python.architecture.no-service-layer-thread-hop-without-context-copy",
        "python.architecture.no-webhook-payload-without-normalization",
        "python.concurrency.no-racy-lock-pool-creation",
        "python.concurrency.no-unbounded-async-lock-pool",
        "python.config.no-request-layer-env-read",
        "python.correctness.no-sync-db-client-on-async-path",
        "python.maintainability.no-cyclomatic-hotspot-method",
        "python.maintainability.no-oversized-runtime-module",
        "python.maintainability.no-oversized-runtime-function",
        "python.reliability.no-durable-state-overwrite-without-atomic-replace",
        "python.reliability.no-hardcoded-external-literals",
        "python.reliability.no-public-fastapi-model-without-cross-field-invariants",
        "python.reliability.no-route-request-json-without-invalid-json-guard",
        "python.reliability.no-state-layer-naive-datetime",
        "python.resource.no-unbounded-upload-read",
        "python.security.no-dynamic-sql-execution",
        "python.security.no-outbound-html-or-url-without-sanitization",
        "python.security.no-raw-credential-logging",
        "python.security.no-raw-exception-detail-response",
        "python.security.no-raw-pii-logging",
        "python.security.no-secret-fallback-literal",
        "python.testing.no-large-runtime-module-without-test-file",
        "python.typing.no-untyped-template-catalog",
        "java.performance.no-n-plus-one-without-entity-graph",
        "java.correctness.no-lazy-collection-touch-in-dto-mapping",
        "java.reliability.no-cascade-redundant-save",
        "java.correctness.no-requery-uncommitted-state-across-transaction-boundary",
        "java.reliability.no-rollback-only-poisoning-in-concurrent-workload",
        "java.correctness.no-async-self-invocation",
        "java.reliability.no-payload-build-after-async-boundary",
        "java.correctness.no-async-read-before-owning-transaction-commit",
        "java.reliability.no-state-transition-without-pessimistic-lock",
        "java.security.no-auth-fallback-to-privileged-user",
        "java.correctness.no-retry-without-re-execution",
        "java.reliability.no-duplicate-flyway-migration-version",
        "java.correctness.no-file-upload-without-validation",
        "python.ai.no-unvalidated-llm-output-on-customer-channel",
        "python.ai.no-raw-tool-response-to-llm",
        "python.ai.no-generic-session-identity-collapse",
        "python.ai.no-mcp-process-leak",
        "python.correctness.no-timeout-kwarg-to-async-callable-without-signature",
        "python.security.no-webhook-replay-without-origin-validation",
        "python.reliability.no-db-sslmode-require-with-verification",
        "python.correctness.no-context-manager-exit-suppressing-exceptions",
        "python.security.no-tenant-shared-webhook-secret",
        "python.reliability.no-lifespan-without-cleanup-guard",
        "python.reliability.no-orphaned-async-task-on-disconnect",
        "go.correctness.no-squared-vector-magnitude-without-sqrt",
        "go.reliability.no-hardcoded-sql-schema-reference-without-migration-check",
        "go.reliability.no-json-numeric-field-without-flexible-decoder",
        "go.security.no-plaintext-http-error-for-unconfigured-service",
        "go.security.authoritative-server-must-validate-client-input",
        "go.security.no-oauth-callback-without-csrf-state",
        "go.reliability.no-in-memory-store-without-expiry-pruning",
        "go.security.no-unvalidated-enumerated-input",
        "go.architecture.no-implicit-cross-module-session-fields",
        "android.correctness.gson-nonnull-field-needs-nullable-type",
        "android.reliability.api-response-type-must-match-contract",
        "android.lifecycle.viewmodel-cleared-must-be-singular",
        "android.lifecycle.geofence-transition-needs-debounce",
        "android.security.no-hardcoded-credentials-in-buildconfig",
        "android.security.no-sensitive-token-in-url-query",
        "android.correctness.fcm-default-notification-channel-required",
        "android.compose.dialog-state-must-be-hoisted-above-conditional",
        "android.compose.unsupported-parameter-must-not-be-used",
        "android.compose.dark-theme-textfield-needs-explicit-text-color",
        "android.reliability.proguard-r8-must-keep-generic-type-signatures",
        "android.correctness.custom-flow-first-extension-is-unsafe",
        "android.reliability.okhttp-legacy-mediatype-needs-extension",
        "android.architecture.deep-link-routing-must-use-shared-target-parser",
        "android.correctness.keyboard-input-needs-ime-padding",
        "android.reliability.notification-deep-link-must-fetch-by-id",
        "android.reliability.no-async-paginated-fetch-without-generation-guard",
        "java.reliability.no-jpql-null-or-lower-on-optional-filter",
        "java.reliability.no-readonly-transactional-on-composite-read-service",
        "java.reliability.transactional-event-listener-requires-phase",
        "java.reliability.no-requires-new-self-invocation",
        "python.reliability.no-long-poll-read-timeout-mismatch",
        "python.reliability.no-unhandled-idempotent-duplicate-api-response",
        "typescript.accessibility.no-number-input-without-wheel-blur",
        "typescript.web.no-client-api-url-in-server-backend-fetch",
        "typescript.react.mutation-requires-cache-invalidation",
        "typescript.react.polled-query-requires-placeholder-data",
        "unity.reliability.no-network-singleton-after-ui-bootstrap",
    }
)

_DEFAULT_RULES = (
    RuleDefinition(
        rule_id="shared.security.no-secrets-in-diff",
        name="No secrets in changed code",
        summary="Block committed secrets and credentials in changed files.",
        category=RuleCategory.SECURITY,
        languages=_ALL_LANGUAGES,
        adapter_key="shared",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("diff-first", "high-confidence"),
    ),
    RuleDefinition(
        rule_id="shared.testing.changed-code-has-tests",
        name="Changed behavior has test coverage",
        summary="Require changed behavior to keep or add nearby tests where confidence is high.",
        category=RuleCategory.TESTING,
        languages=_ALL_LANGUAGES,
        adapter_key="shared",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("diff-first", "advisory"),
    ),
    RuleDefinition(
        rule_id="shared.testing.no-unconditional-skip",
        name="Do not land unconditional skipped tests",
        summary=(
            "Block changed test files that add explicit skip or disable markers instead of "
            "tracking the gap through targeted follow-up work."
        ),
        category=RuleCategory.TESTING,
        languages=_ALL_LANGUAGES,
        adapter_key="shared",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("shared", "testing", "diff-first", "skip", "high-confidence"),
    ),
    RuleDefinition(
        rule_id="shared.testing.test-with-change-ratchet",
        name="Large app diffs should include test updates",
        summary=(
            "Advise when a diff changes substantial application code without any accompanying "
            "test file updates."
        ),
        category=RuleCategory.TESTING,
        languages=_ALL_LANGUAGES,
        adapter_key="shared",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("shared", "testing", "diff-first", "advisory", "coverage"),
    ),
    RuleDefinition(
        rule_id="python.typing.explicit-public-api",
        name="Python public APIs stay typed",
        summary="Flag changed Python public APIs that lose explicit type coverage.",
        category=RuleCategory.TYPING,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "typing"),
    ),
    RuleDefinition(
        rule_id="python.typing.no-untyped-template-catalog",
        name="Keep Python template catalogs explicitly typed",
        summary=(
            "Warn when changed Python service/workflow template catalogs are introduced without "
            "an explicit value type contract."
        ),
        category=RuleCategory.TYPING,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "template", "catalog", "typing"),
    ),
    RuleDefinition(
        rule_id="python.maintainability.no-oversized-runtime-function",
        name="Keep Python request and service functions small",
        summary=(
            "Warn when changed Python route handlers or service/workflow callables grow large "
            "enough to become hard to review, test, or safely extend."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "maintainability", "complexity"),
    ),
    RuleDefinition(
        rule_id="python.maintainability.no-oversized-runtime-module",
        name="Keep Python runtime modules reviewable",
        summary=(
            "Warn when changed Python runtime modules grow large enough to hide routing, "
            "orchestration, and helper concerns in one file."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "maintainability", "runtime", "complexity"),
    ),
    RuleDefinition(
        rule_id="python.maintainability.no-cyclomatic-hotspot-method",
        name="Keep Python hotspot callables reviewable",
        summary=(
            "Warn when changed Python runtime callables accumulate branch-heavy hotspots "
            "that become hard to review and test."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "maintainability", "runtime", "cyclomatic", "complexity"),
    ),
    RuleDefinition(
        rule_id="python.testing.no-large-runtime-module-without-test-file",
        name="Keep large Python runtime modules paired with tests",
        summary=(
            "Warn when changed Python runtime modules grow large without a nearby dedicated "
            "test file."
        ),
        category=RuleCategory.TESTING,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "testing", "runtime", "module", "coverage"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-webhook-payload-without-normalization",
        name="Normalize webhook and media payloads before branching on them",
        summary=(
            "Warn when changed Python webhook/media handlers read nested raw payload metadata "
            "without routing it through a normalization helper first."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "architecture", "webhook", "media", "normalization"),
    ),
    RuleDefinition(
        rule_id="python.error-handling.no-bare-except-cleanup",
        name="Keep bare except out of Python cleanup paths",
        summary=(
            "Warn when changed Python cleanup or teardown paths use bare except blocks that can "
            "swallow the real failure, cancellation, or timeout signal."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "error-handling", "cleanup", "exceptions"),
    ),
    RuleDefinition(
        rule_id="python.concurrency.no-unbounded-async-lock-pool",
        name="Bound Python async lock pools",
        summary=(
            "Warn when changed Python runtime code grows dict-backed asyncio lock pools without "
            "a visible eviction or capacity strategy."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "concurrency", "locks", "resource-safety"),
    ),
    RuleDefinition(
        rule_id="python.concurrency.no-racy-lock-pool-creation",
        name="Create Python lock pools atomically",
        summary=(
            "Warn when changed Python code lazily creates per-key asyncio locks without "
            "protecting lock-pool creation behind an outer guard."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "concurrency", "locks", "race-condition"),
    ),
    RuleDefinition(
        rule_id="python.resource.no-unbounded-upload-read",
        name="Bound Python upload reads",
        summary=(
            "Warn when changed Python request paths read full upload or request-body content into "
            "memory without a visible size guard or chunking strategy."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "backend", "uploads", "memory", "resource-safety"),
    ),
    RuleDefinition(
        rule_id="python.correctness.no-sync-db-client-on-async-path",
        name="Keep sync DB clients off async Python paths",
        summary=(
            "Block changed async Python paths that reach synchronous database client connect or "
            "query helpers without an explicit worker-boundary handoff."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "async", "database", "blocking"),
    ),
    RuleDefinition(
        rule_id="python.correctness.async-blocking-call",
        name="Avoid blocking calls in async paths",
        summary="Catch high-confidence blocking calls introduced inside async Python code.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "async"),
    ),
    RuleDefinition(
        rule_id="python.config.no-request-layer-env-read",
        name="Keep request-layer env reads behind config boundaries",
        summary=(
            "Warn when Python request/webhook surfaces read environment variables directly "
            "instead of flowing them through shared config or secret helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "config", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-request-layer-local-file-io",
        name="Keep Python request-layer file I/O behind boundaries",
        summary=(
            "Warn when Python request-entry surfaces open or read/write local files directly "
            "instead of delegating that work to a storage/helper boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "transport", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-public-fastapi-model-without-field-aliases",
        name="Keep public FastAPI DTO aliases explicit",
        summary=(
            "Warn when changed public Python FastAPI/Pydantic DTOs expose snake_case field names "
            "without explicit alias coverage for the transport contract."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "fastapi", "transport", "alias"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-request-layer-concrete-dependency",
        name="Keep Python request-layer concrete dependency construction behind boundaries",
        summary=(
            "Warn when Python route/webhook handlers construct concrete collaborators inline "
            "instead of receiving them from a dedicated boundary or composition root."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "dip", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-service-layer-outbound-client-construction",
        name="Keep Python outbound client construction out of service/workflow code",
        summary=(
            "Warn when Python service/workflow code constructs concrete outbound clients "
            "directly instead of delegating that wiring to a boundary, factory, or bootstrap."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "dip", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-service-layer-httpx-client-without-timeout-shaping",
        name="Keep Python service/workflow httpx clients on explicit timeout boundaries",
        summary=(
            "Warn when Python service/workflow code constructs httpx clients without timeout= on "
            "the client itself or per-request timeout shaping on direct calls inside the client "
            "context."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "http", "timeout", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-request-layer-global-collaborator-resolution",
        name="Keep Python request-layer runtime singleton resolution behind boundaries",
        summary=(
            "Warn when Python route/webhook handlers resolve collaborators from module globals, "
            "context holders, or registry singletons at runtime instead of receiving them "
            "explicitly."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-service-layer-global-collaborator-resolution",
        name="Keep Python service/workflow singleton resolution behind boundaries",
        summary=(
            "Warn when Python service/workflow code resolves collaborators from module globals, "
            "context holders, or registry singletons at runtime instead of using explicit "
            "injection or wiring."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-request-layer-detached-async-task",
        name="Keep Python request-layer async launches behind explicit lifecycle boundaries",
        summary=(
            "Warn when Python request/webhook code launches detached asyncio tasks without "
            "awaiting them or handing them to an explicit cancellation/lifecycle boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "async", "cancellation", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-service-layer-detached-async-task",
        name="Keep Python service/workflow async launches behind explicit lifecycle boundaries",
        summary=(
            "Warn when Python service/workflow code launches detached asyncio tasks without "
            "awaiting them or handing them to an explicit cancellation/lifecycle boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "async", "cancellation", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-request-layer-thread-hop-without-context-copy",
        name="Keep Python request-layer thread hops behind explicit context propagation",
        summary=(
            "Warn when Python request/webhook code dispatches work through run_in_executor "
            "without wrapping the callable in contextvars.copy_context().run."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "async", "context", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-service-layer-thread-hop-without-context-copy",
        name="Keep Python service/workflow thread hops behind explicit context propagation",
        summary=(
            "Warn when Python service/workflow code dispatches work through run_in_executor "
            "without wrapping the callable in contextvars.copy_context().run."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "async", "context", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-request-layer-log-only-task-exception-sink",
        name="Keep Python request-layer task failures on durable observability paths",
        summary=(
            "Warn when Python request/webhook background-task callbacks only consume "
            "task.exception() without surfacing durable failure/status telemetry."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "async", "observability", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-service-layer-log-only-task-exception-sink",
        name="Keep Python service/workflow task failures on durable observability paths",
        summary=(
            "Warn when Python service/workflow background-task callbacks only consume "
            "task.exception() without surfacing durable failure/status telemetry."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "async", "observability", "boundary"),
    ),
    RuleDefinition(
        rule_id="python.architecture.no-daemon-task-without-failure-sink",
        name="Supervise daemon-like Python background tasks",
        summary=(
            "Warn when long-lived Python background tasks launch without a done-callback, "
            "owning helper, or other durable failure sink."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "backend", "async", "daemon", "observability"),
    ),
    RuleDefinition(
        rule_id="python.security.no-secret-fallback-literal",
        name="Avoid literal secret defaults in Python env lookups",
        summary=(
            "Block Python env lookups that embed non-placeholder secret defaults directly in code."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "backend", "secrets", "config"),
    ),
    RuleDefinition(
        rule_id="python.security.no-dynamic-sql-execution",
        name="Avoid dynamic SQL construction at Python execution sites",
        summary=(
            "Block Python SQL execution surfaces that interpolate or concatenate SQL text "
            "dynamically instead of using bound parameters or approved allowlisted fragments."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "backend", "sql", "security"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-hardcoded-external-literals",
        name="Avoid hardcoded external/config literals in Python backends",
        summary=(
            "Block high-confidence Python service URLs, host/domain defaults, tenant/database "
            "defaults, and selected provider/channel literals embedded directly in config/default "
            "positions."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "backend", "config", "literals"),
    ),
    RuleDefinition(
        rule_id="python.security.no-raw-exception-detail-response",
        name="Avoid raw exception detail in Python error responses",
        summary=(
            "Warn when Python route or webhook responses serialize raw exception detail back to "
            "the caller instead of returning a stable client-facing error message."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "http", "response", "security"),
    ),
    RuleDefinition(
        rule_id="python.security.no-outbound-html-or-url-without-sanitization",
        name="Sanitize outbound Python HTML and CTA URLs",
        summary=(
            "Warn when changed Python email or messaging HTML/URL builders interpolate raw values "
            "without escaping or URL validation."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "security", "html", "sanitization"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-route-request-json-without-invalid-json-guard",
        name="Guard Python request.json() calls with invalid-body handling",
        summary=(
            "Warn when Python route or webhook code parses request JSON directly without an "
            "explicit malformed-body guard that returns a stable 400 response."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "http", "json", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-public-fastapi-model-without-cross-field-invariants",
        name="Keep public FastAPI DTO cross-field invariants explicit",
        summary=(
            "Warn when changed public Python FastAPI/Pydantic DTOs rely on discriminator-style "
            "field combinations without a model or field validator."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "fastapi", "validation", "invariant"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-state-layer-naive-datetime",
        name="Keep Python durable state timestamps on explicit UTC-aware datetimes",
        summary=(
            "Warn when Python persistence, event, or scheduler state code uses "
            "datetime.utcnow() or bare datetime.now() instead of timezone-aware UTC values."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "datetime", "utc", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-durable-state-overwrite-without-atomic-replace",
        name="Keep Python durable state overwrites on atomic temp-file replace",
        summary=(
            "Warn when Python webhook or event state code overwrites durable JSON state files "
            "directly instead of writing a temp file and atomically replacing the target."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "state", "atomic", "file", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.security.no-raw-credential-logging",
        name="Avoid raw credential logging in Python backends",
        summary=(
            "Block Python runtime log statements that emit raw credential-bearing values such as "
            "tokens, secrets, API keys, or cookies."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "backend", "logging", "security"),
    ),
    RuleDefinition(
        rule_id="python.security.no-raw-pii-logging",
        name="Avoid raw PII logging in Python backends",
        summary=(
            "Warn when Python runtime log statements emit raw phone, email, or registration "
            "identifiers instead of redacted forms."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "backend", "logging", "privacy"),
    ),
    RuleDefinition(
        rule_id="java.config.no-web-layer-value-injection",
        name="Keep Java web-layer config injection behind boundaries",
        summary=(
            "Warn when Java controller/filter surfaces inject config directly with @Value or "
            "read env variables instead of consuming typed configuration collaborators."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "config", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-web-layer-local-file-io",
        name="Keep Java web-layer file I/O behind boundaries",
        summary=(
            "Warn when Java controller/filter surfaces touch the local filesystem directly "
            "instead of delegating file access to storage or service collaborators."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "transport", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-web-layer-concrete-dependency",
        name="Keep Java web-layer concrete dependency construction behind boundaries",
        summary=(
            "Warn when Java controller/filter/listener surfaces construct concrete collaborators "
            "inline instead of consuming injected beans or dedicated boundaries."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "dip", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-outbound-client-construction",
        name="Keep Java outbound client construction out of service/workflow code",
        summary=(
            "Warn when Java service/workflow components construct concrete outbound clients "
            "directly instead of wiring them through configuration or injected collaborators."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "dip", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-rest-template-without-timeout-shaping",
        name="Keep Java service/workflow RestTemplate wiring on explicit timeout boundaries",
        summary=(
            "Warn when Java service/workflow code constructs RestTemplate without request-factory "
            "timeout shaping instead of injecting a timeout-configured client."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "http", "timeout", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-objectprovider-circular-self-reference",
        name="Avoid lazy self-provider wiring in Java service orchestration",
        summary=(
            "Warn when Java service/workflow beans inject ObjectProvider/ObjectFactory/Provider "
            "of their own service type to hide circular self-invocation wiring."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "spring", "objectprovider", "circular-dependency"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-entity-crossing-async-or-requires-new-boundary",
        name="Keep JPA entities out of Java async and REQUIRES_NEW boundaries",
        summary=(
            "Warn when Java @Async or REQUIRES_NEW method signatures pass JPA entities across "
            "thread or transaction boundaries instead of reloading inside the new boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "entity", "async", "transaction"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-transactional-external-io",
        name="Keep Java transactional service/workflow code off direct external I/O paths",
        summary=(
            "Warn when Java @Transactional service/workflow methods call outbound client, sender, "
            "or storage collaborators directly instead of handing that work to an after-commit or "
            "non-transactional boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "transaction", "external-io", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-web-layer-service-locator-access",
        name="Keep Java web-layer service-locator access behind boundaries",
        summary=(
            "Warn when Java controller/filter surfaces resolve collaborators through runtime "
            "application-context or singleton access instead of explicit injection."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-service-locator-access",
        name="Keep Java service/workflow service-locator access behind boundaries",
        summary=(
            "Warn when Java service/workflow code resolves collaborators through runtime "
            "application-context or singleton access instead of explicit wiring."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-web-layer-detached-async-launch",
        name="Keep Java web-layer async launches behind explicit lifecycle boundaries",
        summary=(
            "Warn when Java controller/filter surfaces fire off detached async work via "
            "@Async, CompletableFuture.runAsync, or executor.execute without a caller-visible "
            "lifecycle boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "async", "cancellation", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-detached-async-launch",
        name="Keep Java service/workflow async launches behind explicit lifecycle boundaries",
        summary=(
            "Warn when Java service/workflow code fires off detached async work via @Async, "
            "CompletableFuture.runAsync, or executor.execute without a caller-visible lifecycle "
            "boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "async", "cancellation", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-web-layer-log-only-async-outcome",
        name="Keep Java web-layer async outcomes on durable observability paths",
        summary=(
            "Warn when Java controller/filter async work only logs success/failure instead of "
            "surfacing a durable failure/status signal."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "async", "observability", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-service-layer-log-only-async-outcome",
        name="Keep Java service/workflow async outcomes on durable observability paths",
        summary=(
            "Warn when Java service/workflow async work only logs success/failure instead of "
            "surfacing a durable failure/status signal."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "async", "observability", "boundary"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-web-layer-terminal-response-fallthrough",
        name="Keep Java terminal response writes on terminating request paths",
        summary=(
            "Warn when Java filter/controller request paths write a terminal HTTP response but "
            "can still continue later request processing."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "http", "response", "lifecycle"),
    ),
    RuleDefinition(
        rule_id="java.security.no-auth-filter-broad-exception-fallthrough",
        name="Keep Java auth filters fail-closed on broad auth exceptions",
        summary=(
            "Warn when Java auth filters catch broad Exception paths and still continue the "
            "request filter chain instead of failing closed."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "auth", "filter", "security"),
    ),
    RuleDefinition(
        rule_id="java.security.no-secret-fallback-literal",
        name="Avoid literal secret defaults in Java property injection",
        summary=(
            "Block Java @Value placeholders that embed non-placeholder secret defaults in code."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "secrets", "config"),
    ),
    RuleDefinition(
        rule_id="java.security.no-dynamic-sql-execution",
        name="Avoid dynamic SQL construction at Java execution sites",
        summary=(
            "Block Java JdbcTemplate or EntityManager execution surfaces that build SQL "
            "dynamically instead of relying on parameter binding or tightly allowlisted fragments."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "sql", "security"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-hardcoded-external-literals",
        name="Avoid hardcoded external/config literals in Java backends",
        summary=(
            "Block high-confidence Java service URLs, host/domain defaults, and selected "
            "provider/channel/integration literals embedded directly in config/default positions."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "config", "literals"),
    ),
    RuleDefinition(
        rule_id="java.security.no-raw-credential-logging",
        name="Avoid raw credential logging in Java backends",
        summary=(
            "Block Java runtime log statements that emit raw credential-bearing values such as "
            "tokens, secrets, API keys, or cookies."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "logging", "security"),
    ),
    RuleDefinition(
        rule_id="java.security.no-raw-pii-logging",
        name="Avoid raw PII logging in Java backends",
        summary=(
            "Warn when Java runtime log statements emit raw phone, email, or registration "
            "identifiers instead of redacted forms."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "logging", "privacy"),
    ),
    RuleDefinition(
        rule_id="java.maintainability.no-oversized-service-class",
        name="Keep Java service classes within reviewable size",
        summary=(
            "Warn when changed Java service/workflow classes exceed a 500-line size "
            "guardrail and become hard to review and test."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "maintainability", "complexity"),
    ),
    RuleDefinition(
        rule_id="java.maintainability.no-oversized-service-method",
        name="Keep Java service methods within reviewable size",
        summary=(
            "Warn when changed Java service/workflow methods exceed a 50-line size "
            "guardrail and become hard to review and test."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "maintainability", "complexity"),
    ),
    RuleDefinition(
        rule_id="java.concurrency.no-static-lock-pool-without-eviction",
        name="Bound static Java lock pools with eviction",
        summary=(
            "Warn when changed Java code holds per-key locks in static maps without a visible "
            "eviction or lifecycle strategy."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "concurrency", "locks", "eviction"),
    ),
    RuleDefinition(
        rule_id="java.testing.no-controller-without-test-class",
        name="Keep Java controllers paired with controller tests",
        summary=(
            "Warn when changed Java controller surfaces land without a nearby test class "
            "covering the controller entrypoints."
        ),
        category=RuleCategory.TESTING,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "testing", "controller", "coverage"),
    ),
    RuleDefinition(
        rule_id="java.testing.no-scheduled-service-without-scheduler-test",
        name="Keep scheduled Java services paired with scheduler tests",
        summary=(
            "Warn when changed Java scheduled services land without nearby tests that exercise "
            "the scheduler entrypoints."
        ),
        category=RuleCategory.TESTING,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "testing", "scheduler", "coverage"),
    ),
    RuleDefinition(
        rule_id="java.maintainability.no-cyclomatic-hotspot-method",
        name="Keep Java hotspot methods reviewable",
        summary=(
            "Warn when changed Java methods accumulate branching hotspots beyond the cyclomatic "
            "complexity guardrails used for service and controller code."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "maintainability", "cyclomatic", "complexity"),
    ),
    RuleDefinition(
        rule_id="java.maintainability.no-exception-swallowing-in-critical-paths",
        name="Surface Java critical-path failures durably",
        summary=(
            "Warn when changed Java scheduler, dispatch, or outbox paths catch broad "
            "exceptions and only log or suppress the failure."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "exceptions", "critical-paths", "maintainability"),
    ),
    RuleDefinition(
        rule_id="java.architecture.no-controller-direct-repository-access",
        name="Keep Java controllers off repositories",
        summary=(
            "Warn when changed Spring MVC controller code injects or calls repositories "
            "directly instead of delegating persistence work to services."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "mvc", "controller", "repository"),
    ),
    RuleDefinition(
        rule_id="java.concurrency.no-concurrentmap-scheduled-unsafe-removal",
        name="Avoid fragile scheduled ConcurrentMap removal",
        summary=(
            "Warn when changed scheduled Java code iterates ConcurrentMap state and removes "
            "entries inline without a clearer atomic or snapshot-based cleanup path."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "concurrency", "scheduler", "maps"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-batch-saveall-without-partial-failure-guard",
        name="Guard Java batch saveAll mutations",
        summary=(
            "Warn when changed Java batch-processing code mutates collections and persists them "
            "with saveAll() without a visible partial-failure or retry strategy."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "batch", "saveall", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-nonadditive-flyway-migration",
        name="Keep Java Flyway migrations additive",
        summary=(
            "Warn when changed Flyway versioned migrations perform non-additive destructive "
            "schema work instead of additive repair migrations."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "flyway", "migration", "schema"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-unbounded-findall-without-pagination",
        name="Page or scope Java repository findAll access",
        summary=(
            "Warn when changed Java service or workflow code calls repository findAll() "
            "without visible pagination or scoping."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "repository", "findall", "pagination"),
    ),
    RuleDefinition(
        rule_id="java.architecture.event-listener-needs-transaction-phase-boundary",
        name="Bound Java event listener transaction coupling",
        summary=(
            "Warn when changed Java event listeners perform write-sensitive work without an "
            "explicit transaction-phase or isolated-transaction boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "events", "transactions"),
    ),
    RuleDefinition(
        rule_id="go.config.no-handler-env-read",
        name="Keep Go handler env reads behind config boundaries",
        summary=(
            "Warn when Go handler surfaces read environment variables directly instead of "
            "using injected configuration."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "config", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-direct-outbound-http",
        name="Keep Go handler outbound HTTP behind boundaries",
        summary=(
            "Warn when Go handler surfaces construct outbound HTTP requests or clients directly "
            "instead of delegating that work to a dedicated client/helper boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "transport", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-concrete-dependency",
        name="Keep Go handler concrete dependency construction behind boundaries",
        summary=(
            "Warn when Go handler surfaces construct concrete repositories, services, or "
            "integration clients inline instead of receiving them from bootstrap wiring."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "dip", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-direct-sql-execution",
        name="Keep Go handler persistence behind repository or service boundaries",
        summary=(
            "Warn when Go HTTP handlers execute SQL or start transactions directly instead of "
            "delegating persistence work to a repository or service boundary."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "sql", "persistence", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-service-layer-outbound-client-construction",
        name="Keep Go outbound client construction out of service/workflow code",
        summary=(
            "Warn when Go service/workflow code constructs concrete outbound clients or "
            "transports directly instead of delegating that wiring to bootstrap or factories."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "dip", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-service-locator-access",
        name="Keep Go handler service-locator access behind boundaries",
        summary=(
            "Warn when Go handler surfaces resolve collaborators from package-global holders or "
            "singleton-getter helpers instead of receiving them explicitly."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-service-layer-service-locator-access",
        name="Keep Go service/workflow service-locator access behind boundaries",
        summary=(
            "Warn when Go service/workflow code resolves collaborators from package-global "
            "holders or singleton-getter helpers instead of explicit injection."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-detached-goroutine",
        name="Keep Go handler goroutines behind explicit lifecycle boundaries",
        summary=(
            "Warn when Go handler or websocket-entry code launches detached goroutines without "
            "passing caller-owned context/done signaling into the work."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "async", "cancellation", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-service-layer-detached-goroutine",
        name="Keep Go service/workflow goroutines behind explicit lifecycle boundaries",
        summary=(
            "Warn when Go service/workflow code launches detached goroutines without passing "
            "caller-owned context/done signaling into the work."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "async", "cancellation", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-rooted-background-context",
        name="Keep Go handler contexts rooted in caller-owned request context",
        summary=(
            "Warn when Go handler or websocket-entry code starts async/request work from "
            "context.Background() or context.TODO() instead of propagating caller context."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "async", "context", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-service-layer-rooted-background-context",
        name="Keep Go service/workflow contexts rooted in caller-owned context",
        summary=(
            "Warn when Go service/workflow code starts async or outbound work from "
            "context.Background() or context.TODO() instead of propagating caller context."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "async", "context", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-log-only-background-outcome",
        name="Keep Go handler background outcomes on durable observability paths",
        summary=(
            "Warn when Go handler or websocket-entry background work only logs failures instead of "
            "surfacing a durable failure/status signal."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "async", "observability", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-service-layer-log-only-background-outcome",
        name="Keep Go service/workflow background outcomes on durable observability paths",
        summary=(
            "Warn when Go service/workflow background work only logs failures instead of "
            "surfacing a durable failure/status signal."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "async", "observability", "boundary"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-handler-terminal-response-fallthrough",
        name="Keep Go terminal response writes on terminating handler paths",
        summary=(
            "Warn when Go HTTP handlers write a terminal response through error helpers but can "
            "still continue later handler logic."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "http", "response", "lifecycle"),
    ),
    RuleDefinition(
        rule_id="go.security.no-secret-fallback-literal",
        name="Avoid literal secret defaults in Go env helpers",
        summary=(
            "Block Go env helper calls that embed non-placeholder secret defaults directly in code."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "secrets", "config"),
    ),
    RuleDefinition(
        rule_id="go.security.no-dynamic-sql-execution",
        name="Avoid dynamic SQL construction at Go execution sites",
        summary=(
            "Block Go database execution surfaces that interpolate or concatenate SQL text "
            "dynamically instead of relying on query parameters or tightly allowlisted fragments."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "sql", "security"),
    ),
    RuleDefinition(
        rule_id="go.reliability.no-hardcoded-external-literals",
        name="Avoid hardcoded external/config literals in Go backends",
        summary=(
            "Block high-confidence Go service URLs, host/domain defaults, and selected "
            "provider/channel/integration literals embedded directly in config/default positions."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "config", "literals"),
    ),
    RuleDefinition(
        rule_id="go.security.no-handler-error-detail-response",
        name="Avoid raw error detail in Go HTTP responses",
        summary=(
            "Warn when Go HTTP handlers or inline HandlerFunc boundaries write raw error detail "
            "back to clients through http.Error instead of using a stable client-facing message."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "http", "response", "security"),
    ),
    RuleDefinition(
        rule_id="go.reliability.no-handler-request-json-decode-without-strict-decoder",
        name="Use strict request JSON decoding in Go HTTP handlers",
        summary=(
            "Warn when Go HTTP handlers decode request JSON through a bare json.NewDecoder(...)."
            "Decode(...) path instead of configuring a strict decoder that rejects unknown fields."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "http", "json", "reliability"),
    ),
    RuleDefinition(
        rule_id="go.security.no-raw-credential-logging",
        name="Avoid raw credential logging in Go backends",
        summary=(
            "Block Go runtime log statements that emit raw credential-bearing values such as "
            "tokens, secrets, API keys, or cookies."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "logging", "security"),
    ),
    RuleDefinition(
        rule_id="go.security.no-raw-pii-logging",
        name="Avoid raw PII logging in Go backends",
        summary=(
            "Warn when Go runtime log statements emit raw phone, email, or registration "
            "identifiers instead of redacted forms."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "logging", "privacy"),
    ),
    RuleDefinition(
        rule_id="typescript.correctness.no-unsafe-any-boundary",
        name="Avoid unsafe any at boundaries",
        summary="Detect new unsafe any usage across TS component and API boundaries.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "safety"),
    ),
    RuleDefinition(
        rule_id="typescript.foundation.typecheck-clean",
        name="TypeScript typecheck stays clean",
        summary=(
            "Run the repo-native TypeScript typecheck surface and surface reported diagnostics."
        ),
        category=RuleCategory.TYPING,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript-typecheck",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "tooling", "foundation", "typecheck"),
    ),
    RuleDefinition(
        rule_id="typescript.foundation.eslint-clean",
        name="ESLint stays clean",
        summary="Run the repo-native ESLint surface and surface reported lint diagnostics.",
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript-eslint",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "tooling", "foundation", "eslint"),
    ),
    RuleDefinition(
        rule_id="unity.reliability.no-runtime-unityeditor-usage",
        name="Keep UnityEditor APIs out of runtime code",
        summary=(
            "Block UnityEditor namespace usage in runtime/player C# surfaces unless the file "
            "lives in an Editor-only folder or editor-only assembly."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("unity", "runtime", "editor", "build-safety"),
    ),
    RuleDefinition(
        rule_id="unity.ui.no-direct-imgui-dpi-scaling",
        name="Avoid raw IMGUI DPI scaling",
        summary=(
            "Flag direct `Screen.dpi / 160f` scaling in runtime IMGUI code, which tends to "
            "oversize layouts on dense Android devices."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("unity", "ui", "imgui", "android", "scaling"),
    ),
    RuleDefinition(
        rule_id="android.foundation.android-lint-clean",
        name="Android Lint stays clean",
        summary="Run the repo-native Android Lint surface and surface reported diagnostics.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android-lint",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "tooling", "foundation", "lint"),
    ),
    RuleDefinition(
        rule_id="android.foundation.detekt-clean",
        name="Detekt stays clean",
        summary="Run the repo-native Detekt surface and surface reported lint diagnostics.",
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android-detekt",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "tooling", "foundation", "detekt"),
    ),
    RuleDefinition(
        rule_id="android.foundation.api-contract-surface-needs-doc-refresh",
        name="Refresh Android API contract artifacts with transport changes",
        summary=(
            "Warn when Android Retrofit or DTO contract surfaces drift without a matching "
            "checked-in API contract artifact refresh."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "foundation", "contract", "api"),
    ),
    RuleDefinition(
        rule_id="android.foundation.variant-owned-release-config",
        name="Keep Android release config owned by variants",
        summary=(
            "Warn when Android Gradle files declare release- or tenant-owned BuildConfig values "
            "in defaultConfig instead of buildTypes or productFlavors."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "foundation", "gradle", "release", "flavors"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-ui-direct-api-client",
        name="Keep ApiClient access out of Android UI code",
        summary=(
            "Block direct ApiClient transport-service access in Android UI surfaces when the "
            "repo already exposes repository/data helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "ui", "boundary", "transport"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-ui-direct-buildconfig-transport",
        name="Keep transport BuildConfig access out of Android UI code",
        summary=(
            "Warn when Android UI surfaces read transport or tenant routing BuildConfig values "
            "directly instead of flowing them through repository/client helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "ui", "boundary", "buildconfig"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-fragmented-deeplink-intent-parsing",
        name="Keep Android deep-link parsing in coordinator helpers",
        summary=(
            "Warn when Android lifecycle or UI code parses Intent extras and deep-link params "
            "directly instead of routing through shared navigation helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "ui", "navigation", "deeplink", "boundary"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-ui-direct-preferences-manager",
        name="Route UI persistence through approved boundaries",
        summary=(
            "Warn when Android UI code reaches into ApiClient.preferencesManager directly "
            "instead of repository or session helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "ui", "boundary", "storage"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-service-or-receiver-direct-service-locator-access",
        name="Keep Android services and receivers off service locators",
        summary=(
            "Warn when Android services or receivers instantiate repositories or preferences "
            "managers directly, or reach into ApiClient.* instead of injected boundaries."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "service", "receiver", "service-locator", "boundary"),
    ),
    RuleDefinition(
        rule_id="android.ui.no-raw-color-literals",
        name="Use Android theme colors instead of raw literals",
        summary="Block new raw Compose color literals in Android UI surfaces.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "ui", "design-system", "colors"),
    ),
    RuleDefinition(
        rule_id="android.ui.avoid-fixed-tokenless-layout-values",
        name="Avoid tokenless fixed Android layout values",
        summary="Warn on raw dp/sp layout literals in Android UI surfaces.",
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "ui", "layout", "design-system"),
    ),
    RuleDefinition(
        rule_id="android.ui.avoid-tiny-readability-text",
        name="Avoid tiny readability text in Android UI",
        summary=(
            "Warn on explicit sub-12sp text sizes in Android UI surfaces when compact labels and "
            "badges become hard to read."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "ui", "accessibility", "readability", "text-size"),
    ),
    RuleDefinition(
        rule_id="android.ui.no-local-status-color-map",
        name="Keep semantic status color maps in shared Android theme helpers",
        summary=(
            "Block local status->color maps in Android UI code when badge/tone styling should "
            "live in the shared theme/design-system layer."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "ui", "semantic-tokens", "status"),
    ),
    RuleDefinition(
        rule_id="android.ui.no-semantic-status-color-literals",
        name="Prefer shared Android semantic tokens over raw status colors",
        summary=(
            "Warn on raw status/badge/chip color literals in Android UI code instead of shared "
            "theme tokens."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "ui", "semantic-tokens", "status", "colors"),
    ),
    RuleDefinition(
        rule_id="typescript.maintainability.unused-exported-surface",
        name="Avoid dead exported surface",
        summary="Find changed exported TS symbols that are unused or stale.",
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "maintainability"),
    ),
    RuleDefinition(
        rule_id="typescript.maintainability.no-oversized-ui-module",
        name="Keep UI modules reviewable",
        summary=(
            "Warn when changed TSX page/component modules grow large enough to hide rendering, "
            "state, and data-fetch concerns in one file."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "maintainability", "ui", "complexity"),
    ),
    RuleDefinition(
        rule_id="typescript.maintainability.no-oversized-support-module",
        name="Keep TypeScript support modules reviewable",
        summary=(
            "Warn when changed TypeScript support modules such as hooks, helpers, and cache "
            "surfaces grow large enough to hide multiple responsibilities."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "maintainability", "support", "complexity"),
    ),
    RuleDefinition(
        rule_id="typescript.maintainability.no-hook-heavy-page-module",
        name="Keep hook-heavy pages reviewable",
        summary=(
            "Warn when changed TypeScript page modules accumulate unusually high hook "
            "orchestration pressure."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "maintainability", "page", "hooks"),
    ),
    RuleDefinition(
        rule_id="typescript.architecture.no-page-direct-api-import-sprawl",
        name="Keep pages off direct API import sprawl",
        summary=(
            "Warn when changed TypeScript page modules directly wire too many API modules "
            "instead of leaning on domain hooks or helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "architecture", "page", "api"),
    ),
    RuleDefinition(
        rule_id="typescript.react.no-use-effect",
        name="Keep React runtime state flows off useEffect",
        summary=(
            "Block new React useEffect usage in runtime code so state transitions stay behind "
            "explicit events, derived state, query boundaries, or dedicated helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        implementation_state="active",
        tags=("typescript", "react", "state", "effects", "boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.react.no-unstable-sync-external-store-snapshot",
        name="Keep useSyncExternalStore snapshots stable",
        summary=(
            "Block React useSyncExternalStore snapshot readers that rebuild object or array "
            "references during reads instead of reusing cached snapshot values."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        implementation_state="active",
        tags=("typescript", "react", "external-store", "snapshot", "state"),
    ),
    RuleDefinition(
        rule_id="typescript.testing.no-interactive-page-without-tests",
        name="Keep interactive pages covered by tests",
        summary=(
            "Warn when changed interactive TypeScript page surfaces land without nearby tests "
            "that exercise the page behavior."
        ),
        category=RuleCategory.TESTING,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "testing", "pages", "interaction"),
    ),
    RuleDefinition(
        rule_id="typescript.accessibility.no-icon-only-button-without-accessible-name",
        name="Give icon-only buttons an accessible name",
        summary=(
            "Block changed icon-only button surfaces in TypeScript web UI when they do not "
            "expose a visible label or accessible name."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "accessibility", "buttons", "aria"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-query-cache-mutation-outside-cache-module",
        name="Keep query cache mutation behind dedicated modules",
        summary=(
            "Warn when changed TypeScript web UI code mutates shared query caches outside "
            "dedicated cache helper modules."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "query-cache", "state", "boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-unguarded-async-mutation-ui",
        name="Guard async mutation UI with pending state",
        summary=(
            "Warn when changed TypeScript UI surfaces trigger async mutations without exposing "
            "a pending-state guard that prevents duplicate interaction."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "mutation", "pending", "ui"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-inconsistent-query-key-mutation",
        name="Keep query keys aligned across query and mutation paths",
        summary=(
            "Warn when changed TypeScript files query one key family but mutation-side "
            "cache updates or invalidations target another."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "query-cache", "state", "consistency"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-raw-transport-calls",
        name="Keep raw transport inside approved clients",
        summary=(
            "Block raw fetch and axios calls in web UI surfaces when the repo already "
            "exposes dedicated transport clients."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "transport", "boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-direct-response-casting",
        name="Normalize backend payloads in client or schema layers",
        summary=(
            "Warn when web UI code casts response.json() directly instead of using "
            "client or schema normalization layers."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "response-normalization", "boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.web.route-manifest-centralization",
        name="Keep route manifests centralized",
        summary=(
            "Block scattered web route manifest families when the repo already exposes a "
            "shared route or navigation manifest."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "routing", "manifest"),
    ),
    RuleDefinition(
        rule_id="typescript.web.route-access-policy-centralization",
        name="Keep route access policy centralized",
        summary=(
            "Block inline public-path and route-access checks when the repo already "
            "exposes a shared access policy surface."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "routing", "access-policy"),
    ),
    RuleDefinition(
        rule_id="typescript.web.route-family-literal-consistency",
        name="Keep route family literals consistent",
        summary=(
            "Warn when changed web route literals drift from repo-approved singular/plural "
            "route families."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "routing", "consistency"),
    ),
    RuleDefinition(
        rule_id="typescript.web.route-query-codec-centralization",
        name="Keep route/query decoding behind shared codecs",
        summary=(
            "Warn when changed TypeScript route surfaces read raw route params or search params "
            "instead of routing that decoding through shared codec helpers."
        ),
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "routing", "codec"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-window-confirm",
        name="Route confirms through dialog boundaries",
        summary=(
            "Block browser confirm dialogs in web UI surfaces when the repo already exposes "
            "approved dialog infrastructure."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "browser", "dialog"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-hard-browser-navigation",
        name="Keep hard browser navigation inside approved boundaries",
        summary=(
            "Block reload/replace/assign and direct location mutation in web UI surfaces "
            "when the repo already exposes router-aware redirect helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "browser", "navigation"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-direct-browser-storage",
        name="Route browser storage through approved boundaries",
        summary=(
            "Warn on direct localStorage/sessionStorage access in web UI surfaces when the "
            "repo already exposes dedicated storage or auth helpers."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "browser", "storage"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-modal-controller-bypass",
        name="Keep modal keyboard and scroll-lock wiring in controllers",
        summary=(
            "Warn when changed TypeScript UI surfaces wire modal document listeners or body "
            "scroll-lock directly instead of leaning on shared controller boundaries."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "modal", "scroll-lock", "boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-server-api-tenant-isolation-bypass",
        name="Cross-check server-route tenant resolution against auth context",
        summary=(
            "Warn when TypeScript server routes resolve tenants from headers, params, or "
            "tenant-id helpers without validating the authenticated tenant context."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "server", "tenant", "auth", "security"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-local-status-variant-map",
        name="Keep semantic status mappings inside approved helpers",
        summary=(
            "Block local status/badge variant and tone maps in TS web repos once a shared "
            "semantic helper boundary already exists."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "semantic-tokens", "status", "boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-raw-semantic-tailwind-status-classes",
        name="Prefer shared semantic status helpers over raw Tailwind palettes",
        summary=(
            "Warn on raw semantic Tailwind status classes in badge/alert/status contexts "
            "instead of shared helpers or token layers."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "semantic-tokens", "status", "tailwind"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-semantic-status-hex-literals",
        name="Prefer shared semantic tokens over raw status color literals",
        summary=(
            "Warn on raw hex/rgb semantic status literals in badge/alert/status contexts "
            "instead of shared token layers."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "semantic-tokens", "status", "colors"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.no-raw-color-literals",
        name="Use theme colors instead of raw literals",
        summary="Block new raw color literals in React Native style surfaces.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "ui", "react-native", "design-system"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.avoid-fixed-tokenless-layout-values",
        name="Avoid tokenless fixed layout values",
        summary="Warn on new fixed layout literals in React Native style surfaces.",
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "ui", "react-native", "layout"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.no-orphaned-effect-intervals",
        name="Lifecycle intervals must be cleaned up",
        summary="Block repeating timers created in React lifecycle code without visible cleanup.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "ui", "react-native", "lifecycle", "timers"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.no-orphaned-effect-timeouts",
        name="Lifecycle timeouts should be cleaned up",
        summary="Warn on timeouts created in React lifecycle code without visible cleanup.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "ui", "react-native", "lifecycle", "timers"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.avoid-raw-readability-colors",
        name="Avoid raw readability colors",
        summary="Warn on non-theme readability colors in React Native text and icon surfaces.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "ui", "react-native", "accessibility", "contrast"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.no-low-contrast-readability-pairings",
        name="Block obvious low-contrast readability pairings",
        summary="Block high-confidence low-contrast text and icon pairings in React Native styles.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "ui", "react-native", "accessibility", "contrast"),
    ),
    RuleDefinition(
        rule_id="typescript.ui.risky-status-badge-contrast",
        name="Avoid risky status badge contrast",
        summary="Warn on low-confidence status badge color pairings that often under-contrast.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "ui", "react-native", "accessibility", "status"),
    ),
    RuleDefinition(
        rule_id="android.performance.no-main-thread-io",
        name="Avoid main-thread I/O",
        summary=(
            "Catch changed Android code paths that perform disk or network I/O on the main thread."
        ),
        category=RuleCategory.PERFORMANCE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "performance"),
    ),
    RuleDefinition(
        rule_id="android.reliability.no-runblocking-hotpath",
        name="Avoid runBlocking on Android hot paths",
        summary=(
            "Block changed Android UI or request-path code that uses runBlocking and risks "
            "freezing the main thread or stalling request execution."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "coroutines", "runblocking", "hotpath", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.reliability.dto-nullability-default-discipline",
        name="Guard Android response DTOs with nullability or defaults",
        summary=(
            "Warn when Android response DTO fields remain non-null without defaults, making "
            "backend contract drift harder to absorb safely."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "dto", "nullability", "defaults", "contract"),
    ),
    RuleDefinition(
        rule_id="android.reliability.no-stringly-typed-state-machine",
        name="Avoid stringly typed Android state machines",
        summary=(
            "Warn when Android flows coordinate screens or modes through raw string constants "
            "instead of explicit enum or sealed state types."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "state-machine", "reliability", "navigation"),
    ),
    RuleDefinition(
        rule_id="android.reliability.no-unscoped-boundary-coroutine",
        name="Scope Android boundary coroutines explicitly",
        summary=(
            "Block changed Android receiver, service, or callback boundaries that launch "
            "CoroutineScope(...).launch work without a lifecycle-aware or goAsync-style owner."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "coroutines", "receivers", "services", "lifecycle"),
    ),
    RuleDefinition(
        rule_id="android.reliability.no-blocking-sync-wrapper",
        name="Avoid blocking sync wrappers on Android boundaries",
        summary=(
            "Block changed Android code that wraps async DataStore or network work behind "
            "runBlocking-style sync helpers on UI, receiver, or request boundaries."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "coroutines", "runblocking", "datastore", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-viewmodel-direct-repository-instantiation",
        name="Construct Android ViewModel dependencies outside the ViewModel",
        summary=(
            "Warn when changed Android ViewModels instantiate repositories or managers directly "
            "instead of receiving them through construction boundaries."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "viewmodel", "repository", "testability", "architecture"),
    ),
    RuleDefinition(
        rule_id="android.architecture.no-default-viewmodel-parameter-in-composable",
        name="Construct ViewModels outside composable defaults",
        summary=(
            "Warn when changed Android composables create default ViewModel parameters inline "
            "instead of receiving them through call-site or preview-safe boundaries."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "compose", "viewmodel", "architecture", "testability"),
    ),
    RuleDefinition(
        rule_id="android.maintainability.no-oversized-screen-composable",
        name="Keep Compose screen entrypoints reviewable",
        summary=(
            "Warn when changed Android screen composables accumulate large, deeply nested "
            "UI/state flow in one entrypoint."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "compose", "screen", "maintainability", "complexity"),
    ),
    RuleDefinition(
        rule_id="android.maintainability.no-ui-detekt-suppression",
        name="Avoid UI-layer Detekt suppressions",
        summary=(
            "Warn when changed Android UI code suppresses Detekt rules inline instead of "
            "tightening the implementation or centralizing the exception."
        ),
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "ui", "detekt", "suppressions", "maintainability"),
    ),
    RuleDefinition(
        rule_id="android.testing.no-boundary-callback-without-test",
        name="Keep Android boundary callbacks paired with tests",
        summary=(
            "Warn when changed Android boundary entry classes carry meaningful callback logic "
            "without nearby tests."
        ),
        category=RuleCategory.TESTING,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "testing", "boundary", "callbacks", "coverage"),
    ),
    RuleDefinition(
        rule_id="android.testing.no-viewmodel-without-tests",
        name="Keep Android ViewModels paired with tests",
        summary=(
            "Warn when changed Android ViewModels land without nearby tests covering their state "
            "and event handling."
        ),
        category=RuleCategory.TESTING,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "testing", "viewmodel", "coverage"),
    ),
    RuleDefinition(
        rule_id="android.reliability.lifecycle-safe-ui-updates",
        name="Lifecycle-safe UI updates",
        summary="Detect changed Android UI updates that ignore lifecycle safety.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "lifecycle"),
    ),
    RuleDefinition(
        rule_id="android.reliability.scrollable-compose-inputs-need-ime-awareness",
        name="Keep scrollable Compose inputs IME-aware",
        summary=(
            "Warn when changed Android Compose form screens use scrollable text-input surfaces "
            "without visible IME inset or bring-into-view handling."
        ),
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "compose", "keyboard", "ime", "forms", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.security.no-hardcoded-secret-literals",
        name="Avoid hardcoded Android secret literals",
        summary=(
            "Block hardcoded credentials and secret-bearing config literals in Android "
            "source or build surfaces."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "security", "secrets", "config"),
    ),
    RuleDefinition(
        rule_id="android.security.no-secret-fallback-literals",
        name="Avoid inline secret fallback literals",
        summary=(
            "Warn when Android build or runtime config falls back to checked-in secret "
            "literals instead of secure environment or Gradle inputs."
        ),
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "security", "fallback", "config"),
    ),
    RuleDefinition(
        rule_id="java.performance.no-n-plus-one-without-entity-graph",
        name="Paginated JPA queries with lazy associations need explicit fetch strategy",
        summary="Warn when paginated repository methods fetch entities with lazy associations"
            "without @EntityGraph or JOIN FETCH, which causes N+1 queries.",
        category=RuleCategory.PERFORMANCE,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "jpa", "pagination", "n-plus-one", "performance"),
    ),
    RuleDefinition(
        rule_id="java.correctness.no-lazy-collection-touch-in-dto-mapping",
        name="DTO mappers must not touch lazy-loaded associations",
        summary="Block DTO/fromEntity mappers from accessing lazy-loaded collections (e.g.,"
            ".size(), .stream()) unless explicitly requested.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "jpa", "dto", "lazy-loading", "correctness"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-cascade-redundant-save",
        name="Do not redundantly save cascade-managed entities",
        summary="Warn when code calls repository.save() on child entities already managed by"
            "CascadeType.ALL from the owning side.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "jpa", "cascade", "save", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.correctness.no-requery-uncommitted-state-across-transaction-boundary",
        name="Do not re-query uncommitted state across transaction boundaries",
        summary="Block re-querying entities inside REQUIRES_NEW or async listeners expecting to"
            "see uncommitted state from the outer transaction.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "transaction", "async", "correctness"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-rollback-only-poisoning-in-concurrent-workload",
        name="Isolate concurrent sub-transactions to avoid rollback-only poisoning",
        summary="Block concurrent sub-transactions that can mark the outer transaction"
            "rollback-only without isolation via REQUIRES_NEW.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "transaction", "concurrency", "rollback"),
    ),
    RuleDefinition(
        rule_id="java.correctness.no-async-self-invocation",
        name="Avoid @Async self-invocation proxy bypass",
        summary="Warn when @Async methods are called from within the same Spring bean, bypassing"
            "the AOP proxy and running synchronously.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "spring", "async", "proxy", "correctness"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-payload-build-after-async-boundary",
        name="Hydrate JPA-dependent payloads before crossing async boundaries",
        summary="Block building JPA-entity-dependent payloads inside @Async or runAsync callbacks"
            "without hydrating data before the boundary.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "jpa", "async", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.correctness.no-async-read-before-owning-transaction-commit",
        name="Defer async reads until after transaction commit",
        summary="Block fire-and-forget async work that reads DB state modified by the current"
            "transaction before it commits.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "transaction", "async", "correctness"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-state-transition-without-pessimistic-lock",
        name="State transitions must acquire pessimistic locks",
        summary="Warn when state machine transitions on shared aggregates do not use SELECT FOR"
            "UPDATE or equivalent pessimistic locking.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "state-machine", "locking", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.security.no-auth-fallback-to-privileged-user",
        name="Avoid silent auth fallback to privileged users",
        summary="Warn when authentication fallback defaults to a privileged/system user without"
            "explicit scoping and auditing.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("java", "backend", "auth", "security", "fallback"),
    ),
    RuleDefinition(
        rule_id="java.correctness.no-retry-without-re-execution",
        name="Retry must re-execute the target operation",
        summary="Block retry logic that only resets status fields without actually re-executing"
            "the external or internal operation.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "retry", "correctness"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-duplicate-flyway-migration-version",
        name="Flyway Java and SQL migrations must not share version numbers",
        summary="Block Flyway migration version collisions between Java and SQL migrations.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("java", "backend", "flyway", "migration", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.correctness.no-file-upload-without-validation",
        name="Public file uploads must validate size and MIME type",
        summary="Warn when public multipart file upload endpoints do not validate size, MIME"
            "type, or extension before persisting.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "backend", "upload", "validation", "correctness"),
    ),
    RuleDefinition(
        rule_id="typescript.correctness.no-falsy-default-for-numeric-zero",
        name="Use nullish coalescing for numeric defaults",
        summary="Block logical OR (||) used to default numeric values where explicit zero should"
            "be preserved; require nullish coalescing (??).",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "frontend", "numeric", "correctness"),
    ),
    RuleDefinition(
        rule_id="typescript.react.no-mixed-controlled-uncontrolled",
        name="Do not mix controlled and uncontrolled APIs",
        summary="Detect simultaneous use of uncontrolled init props (defaultEdges, defaultValue)"
            "and controlled update APIs (setEdges, value, onChange).",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "react", "controlled", "uncontrolled", "correctness"),
    ),
    RuleDefinition(
        rule_id="typescript.react.query-key-registry",
        name="Centralize React Query keys in registry modules",
        summary=(
            "Advise against inline string or array query keys in React Query hooks and cache "
            "operations outside dedicated query-key registry modules."
        ),
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "react", "query-cache", "registry", "advisory"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-manual-multipart-headers",
        name="Do not manually set Content-Type on FormData uploads",
        summary="Block manual Content-Type header assignment when the request payload is"
            "FormData; require deletion of the header so the browser sets the boundary.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "upload", "multipart", "correctness"),
    ),
    RuleDefinition(
        rule_id="typescript.accessibility.modal-focus-trap",
        name="Modals must implement focus trap and restoration",
        summary="Require modal/dialog components to implement focus trap, initial focus, and"
            "focus restoration on close.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "accessibility", "modal", "focus"),
    ),
    RuleDefinition(
        rule_id="typescript.security.no-raw-error-in-error-boundary",
        name="Avoid raw error details in error boundaries",
        summary="Block rendering of raw Error.message or Error.stack inside React error"
            "boundaries or global-error surfaces exposed to end users.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "react", "security", "error-boundary"),
    ),
    RuleDefinition(
        rule_id="typescript.security.no-unvalidated-external-href",
        name="Validate external href schemes",
        summary="Flag href attributes interpolated from external/user data without scheme"
            "validation (http/https whitelist).",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "security", "href", "xss"),
    ),
    RuleDefinition(
        rule_id="typescript.reliability.no-concurrent-token-refresh",
        name="Deduplicate concurrent token refresh calls",
        summary="Detect auth store or interceptor patterns that initiate token refresh without a"
            "mutex or in-flight deduplication guard.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "auth", "reliability", "race-condition"),
    ),
    RuleDefinition(
        rule_id="typescript.performance.no-eager-heavy-dependency-import",
        name="Lazy-load heavy dependencies",
        summary="Warn when heavy third-party dependencies are imported statically instead of via"
            "dynamic import or next/dynamic.",
        category=RuleCategory.PERFORMANCE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "performance", "lazy-loading"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-ephemeral-ids-for-deep-linking",
        name="Use stable IDs for deep-linking",
        summary="Detect deep-link logic relying on IDs regenerated on every render instead of"
            "stable map keys.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "deep-link", "correctness"),
    ),
    RuleDefinition(
        rule_id="typescript.maintainability.no-console-in-production-browser-code",
        name="Remove console statements from production browser code",
        summary="Warn on console.log, console.warn, or console.error left in browser-facing"
            "TypeScript/React code.",
        category=RuleCategory.MAINTAINABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "maintainability", "console"),
    ),
    RuleDefinition(
        rule_id="typescript.correctness.no-unvalidated-numeric-precision",
        name="Validate numeric input precision",
        summary="Require explicit precision validation for numeric inputs mapping to backend"
            "decimal columns.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "correctness", "numeric", "precision"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-unauthenticated-image-blob-urls",
        name="Authenticate image blob URLs in multi-tenant apps",
        summary="Warn when image URLs are constructed from raw filenames without authenticated"
            "context or tenant-scoped query parameters.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "security", "images", "authentication"),
    ),
    RuleDefinition(
        rule_id="typescript.architecture.no-inline-filter-logic-in-components",
        name="Extract non-trivial filter logic from components",
        summary="Advisory: extract non-trivial filter/sort/map logic from inside React.useMemo in"
            "components into named support modules with tests.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "web", "architecture", "filter", "component"),
    ),
    RuleDefinition(
        rule_id="typescript.correctness.no-unvalidated-url-tab-param",
        name="Validate URL-driven tab parameters against allowlist",
        summary="Require URL-driven tab parameters to be validated against an explicit allowlist"
            "before being used as component state.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "correctness", "url", "tabs"),
    ),
    RuleDefinition(
        rule_id="typescript.reliability.no-module-level-throwing-side-effect",
        name="Defer throwing side effects from module level",
        summary="Flag module-level statements that can throw (API client construction, config"
            "loading) and require deferral into component scope with try/catch.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "react-native", "reliability", "module-level", "side-effects"),
    ),
    RuleDefinition(
        rule_id="typescript.reliability.no-formdata-for-raw-binary-upload",
        name="Use direct Blob upload for raw binary endpoints",
        summary="Flag FormData usage as the body of S3 pre-signed PUT or raw-binary upload"
            "endpoints; require direct Blob/ArrayBuffer upload.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "react-native", "reliability", "upload", "binary"),
    ),
    RuleDefinition(
        rule_id="typescript.reliability.no-unbounded-buffer-without-chunking",
        name="Chunk unbounded in-memory buffers before upload",
        summary="Flag unbounded in-memory buffers flushed in a single network request without"
            "size-based chunking or retention limits.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "react-native", "reliability", "buffer", "chunking"),
    ),
    RuleDefinition(
        rule_id="typescript.react.no-websocket-reconnect-after-unmount",
        name="Prevent WebSocket reconnect after unmount",
        summary="Flag WebSocket onclose handlers that schedule reconnect timers without checking"
            "a mountedRef or cleanup flag.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "react", "websocket", "correctness", "unmount"),
    ),
    RuleDefinition(
        rule_id="android.correctness.gson-nonnull-field-needs-nullable-type",
        name="Gson-deserialized Kotlin fields must be nullable or have defaults",
        summary="Block Kotlin data classes used with Gson from having non-null fields without"
            "defaults, because Gson silently injects nulls.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "kotlin", "gson", "null-safety", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.reliability.api-response-type-must-match-contract",
        name="Retrofit response types must match backend contract",
        summary="Warn when Retrofit service methods use response wrapper types that do not match"
            "the actual backend contract.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "retrofit", "api", "contract", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.lifecycle.viewmodel-cleared-must-be-singular",
        name="ViewModel onCleared must be overridden at most once",
        summary="Block duplicate onCleared() overrides in a ViewModel, which cause build errors"
            "or leaked resources.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "lifecycle", "viewmodel", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.lifecycle.geofence-transition-needs-debounce",
        name="Debounce geofence EXIT transitions",
        summary="Warn when geofence EXIT transitions trigger side effects immediately instead of"
            "being debounced or delayed.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "geofence", "lifecycle", "reliability", "debounce"),
    ),
    RuleDefinition(
        rule_id="android.security.no-hardcoded-credentials-in-buildconfig",
        name="Avoid hardcoded credentials in BuildConfig",
        summary="Block hardcoded email/password or API keys in BuildConfig fields, even in debug"
            "builds.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "security", "buildconfig", "credentials"),
    ),
    RuleDefinition(
        rule_id="android.security.no-sensitive-token-in-url-query",
        name="Send sensitive tokens in request body",
        summary="Block refresh tokens and sensitive credentials sent as URL query parameters;"
            "require request body.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "security", "token", "query", "retrofit"),
    ),
    RuleDefinition(
        rule_id="android.correctness.fcm-default-notification-channel-required",
        name="Declare FCM default notification channel",
        summary="Warn when apps using FCM do not declare"
            "com.google.firebase.messaging.default_notification_channel_id in"
            "AndroidManifest.xml.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "fcm", "notifications", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.compose.dialog-state-must-be-hoisted-above-conditional",
        name="Hoist dialog state above conditional blocks",
        summary="Block remembered dialog or bottom-sheet state inside a when branch or"
            "conditional block, which is destroyed on recomposition.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "compose", "state", "hoisting", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.compose.unsupported-parameter-must-not-be-used",
        name="Do not use unsupported Compose parameters",
        summary="Warn when Compose Material parameters not supported by the current dependency"
            "version are used.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "compose", "correctness", "version"),
    ),
    RuleDefinition(
        rule_id="android.compose.dark-theme-textfield-needs-explicit-text-color",
        name="Explicit text color for dark theme TextFields",
        summary="Warn when OutlinedTextField or BasicTextField in dark-themed Compose UIs lack"
            "explicit focused/unfocused text colors.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "compose", "dark-theme", "textfield", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.reliability.proguard-r8-must-keep-generic-type-signatures",
        name="ProGuard/R8 must keep generic type signatures for Gson",
        summary="Warn when ProGuard/R8 rules for Gson/Retrofit omit -keepattributes Signature or"
            "TypeToken subclasses.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "proguard", "r8", "gson", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.correctness.custom-flow-first-extension-is-unsafe",
        name="Avoid custom Flow.first() extensions using collect",
        summary="Block custom Flow.first() extensions implemented with collect without a terminal"
            "operator; require kotlinx.coroutines.flow.first.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("android", "kotlin", "flow", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.reliability.okhttp-legacy-mediatype-needs-extension",
        name="Use OkHttp 4.x extension functions for media types",
        summary="Warn when deprecated MediaType.parse or RequestBody.create are used instead of"
            "OkHttp 4.x extensions.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "okhttp", "retrofit", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.architecture.deep-link-routing-must-use-shared-target-parser",
        name="Centralize deep-link parsing in shared navigation helpers",
        summary="Warn when Intent extras and deep-link params are parsed directly in FCMService"
            "or MainActivity instead of shared navigation helpers.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "architecture", "deeplink", "navigation"),
    ),
    RuleDefinition(
        rule_id="android.correctness.keyboard-input-needs-ime-padding",
        name="Apply IME padding for bottom text input",
        summary="Warn when Compose screens with bottom text input lack Modifier.imePadding().",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "compose", "keyboard", "ime", "correctness"),
    ),
    RuleDefinition(
        rule_id="android.reliability.notification-deep-link-must-fetch-by-id",
        name="Fetch fresh entity details by ID from notification deep links",
        summary="Warn when deep links from notifications rely on stale list snapshots instead of"
            "loading fresh details by ID.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("android", "notifications", "deeplink", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.ai.no-unvalidated-llm-output-on-customer-channel",
        name="Validate LLM output before sending to customer channels",
        summary="Block customer-facing code paths that forward raw LLM responses without"
            "validation or sanitization.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "ai", "llm", "security", "customer-channel"),
    ),
    RuleDefinition(
        rule_id="python.ai.no-raw-tool-response-to-llm",
        name="Strip internal fields from tool responses before LLM",
        summary="Warn when tool or MCP responses are passed to the LLM without stripping"
            "internal-only fields.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "ai", "llm", "security", "tools"),
    ),
    RuleDefinition(
        rule_id="python.ai.no-generic-session-identity-collapse",
        name="Avoid generic placeholder session IDs",
        summary="Block code that uses generic placeholder user IDs as stable session keys without"
            "a unique per-request seed.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "ai", "session", "reliability", "identity"),
    ),
    RuleDefinition(
        rule_id="python.ai.no-mcp-process-leak",
        name="Prevent MCP process leaks",
        summary="Warn when MCP sessions are created without async double-checked locking, session"
            "reaping, or shared-client recycling.",
        category=RuleCategory.PERFORMANCE,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "ai", "mcp", "performance", "resources"),
    ),
    RuleDefinition(
        rule_id="python.correctness.no-timeout-kwarg-to-async-callable-without-signature",
        name="Use asyncio.wait_for instead of timeout kwarg",
        summary="Block passing a timeout keyword argument to an async callable unless its"
            "signature explicitly accepts it; require asyncio.wait_for.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "async", "timeout", "correctness"),
    ),
    RuleDefinition(
        rule_id="python.security.no-webhook-replay-without-origin-validation",
        name="Validate webhook origin against replay attacks",
        summary="Block webhook handlers that verify signatures but do not enforce public-origin"
            "IP checks.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "webhook", "security", "replay", "origin"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-db-sslmode-require-with-verification",
        name="Map sslmode=require correctly for async drivers",
        summary="Warn when sslmode=require is incorrectly mapped to a verifying TLS context"
            "(CERT_REQUIRED) instead of TLS without CA validation.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "database", "ssl", "asyncpg", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.security.no-credential-shaped-placeholder-in-tests",
        name="Avoid credential-shaped placeholders in tests",
        summary="Warn when test fixtures contain DSN-shaped URLs with fake credentials that"
            "trigger secret scanners.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "testing", "security", "secrets", "placeholders"),
    ),
    RuleDefinition(
        rule_id="python.ai.no-unhandled-failed-generation-pattern",
        name="Handle malformed LLM generations gracefully",
        summary="Warn when LLM response parsers lack explicit handling for malformed, fenced, or"
            "no-tool failed generations.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "ai", "llm", "correctness", "parsing"),
    ),
    RuleDefinition(
        rule_id="python.ai.no-missing-llm-timeout-in-retryable-pattern",
        name="Include LLM timeout exceptions in retry patterns",
        summary="Warn when fallback/retry logic for LLM providers does not include timeout"
            "exceptions in retryable error patterns.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "ai", "llm", "reliability", "retry", "timeout"),
    ),
    RuleDefinition(
        rule_id="python.correctness.no-context-manager-exit-suppressing-exceptions",
        name="Context manager __exit__ must not suppress exceptions",
        summary="Block __exit__ methods that return None or omit explicit return False, which"
            "silently suppresses exceptions.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "correctness", "context-manager", "exceptions"),
    ),
    RuleDefinition(
        rule_id="python.security.no-tenant-shared-webhook-secret",
        name="Use tenant-scoped webhook secrets",
        summary="Warn when webhook verification uses a single global secret across tenants"
            "instead of tenant-scoped secrets.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "webhook", "security", "tenant", "secrets"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-lifespan-without-cleanup-guard",
        name="FastAPI lifespan must have cleanup guards",
        summary="Warn when FastAPI/ASGI lifespan blocks initialize resources without try/finally"
            "or equivalent cleanup.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "fastapi", "lifespan", "cleanup", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-orphaned-async-task-on-disconnect",
        name="Cancel async tasks on WebSocket disconnect",
        summary="Block WebSocket or streaming handlers that spawn async tasks without cancelling"
            "them on disconnect or exception.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("python", "websocket", "async", "cleanup", "reliability"),
    ),
    RuleDefinition(
        rule_id="go.correctness.no-squared-vector-magnitude-without-sqrt",
        name="Apply math.Sqrt to vector magnitudes",
        summary="Flag Pythagorean sum expressions used for magnitude comparison or storage when"
            "math.Sqrt is missing.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "math", "vector", "correctness"),
    ),
    RuleDefinition(
        rule_id="go.reliability.no-hardcoded-sql-schema-reference-without-migration-check",
        name="Align hardcoded SQL with migration schema",
        summary="Warn when hardcoded table/column names in SQL strings do not match known"
            "migrations or schema definitions.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "sql", "schema", "reliability"),
    ),
    RuleDefinition(
        rule_id="go.reliability.no-json-numeric-field-without-flexible-decoder",
        name="Use flexible decoders for external numeric JSON fields",
        summary="Warn when JSON struct fields decode from external APIs without handling"
            "empty-string or string-numeric variants.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "json", "decoder", "reliability"),
    ),
    RuleDefinition(
        rule_id="go.security.no-plaintext-http-error-for-unconfigured-service",
        name="Return structured JSON errors for service unavailability",
        summary="Flag http.Error with plain text for configuration/dependency failures; require"
            "structured JSON with semantically correct status codes (e.g., 503).",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("go", "backend", "http", "error", "security"),
    ),
    RuleDefinition(
        rule_id="go.security.authoritative-server-must-validate-client-input",
        name="Authoritative servers must validate all client input",
        summary="Block authoritative game/session handlers that apply client input without"
            "server-side validation of bounds, speed, action rates, and state drift.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "game", "security", "validation", "authoritative"),
    ),
    RuleDefinition(
        rule_id="go.security.no-oauth-callback-without-csrf-state",
        name="OAuth callbacks require CSRF state verification",
        summary="Block OAuth callback handlers that do not generate, verify, and consume a"
            "per-request state token.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "oauth", "csrf", "security"),
    ),
    RuleDefinition(
        rule_id="go.reliability.no-in-memory-store-without-expiry-pruning",
        name="In-memory state stores need expiry and pruning",
        summary="Warn when in-memory maps used for state storage lack time-bounded expiry and"
            "periodic pruning.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("go", "backend", "memory", "store", "expiry", "reliability"),
    ),
    RuleDefinition(
        rule_id="go.security.no-unvalidated-enumerated-input",
        name="Validate enumerated string inputs against allowlist",
        summary="Block handlers that accept enumerated string values without validating against"
            "an explicit allowlist.",
        category=RuleCategory.SECURITY,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("go", "backend", "validation", "enum", "security"),
    ),
    RuleDefinition(
        rule_id="go.architecture.no-implicit-cross-module-session-fields",
        name="Use explicit shared DTOs for cross-module session data",
        summary="Warn when session-related data is passed between subsystems via inferred or"
            "partial structs instead of an explicit shared DTO.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.GO,),
        adapter_key="go",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("go", "backend", "architecture", "dto", "session"),
    ),
    RuleDefinition(
        rule_id="unity.reliability.no-renderer-creation-in-batchmode",
        name="Avoid renderer creation in batchmode",
        summary="Block creation of TrailRenderer, LineRenderer, or ParticleSystem in runtime code"
            "without guarding against Application.isBatchMode.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("unity", "batchmode", "renderer", "reliability"),
    ),
    RuleDefinition(
        rule_id="unity.reliability.no-destroyimmediate-on-resources-assets",
        name="Avoid DestroyImmediate on Resources assets",
        summary="Block DestroyImmediate on textures or materials loaded from Resources.Load;"
            "clear cache references instead.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("unity", "resources", "destroy", "reliability"),
    ),
    RuleDefinition(
        rule_id="unity.performance.no-per-frame-allocation-in-hot-path",
        name="Avoid per-frame allocations in hot paths",
        summary="Warn when Update, FixedUpdate, or interpolation loops allocate new arrays or"
            "structs per frame instead of reusing pre-allocated buffers.",
        category=RuleCategory.PERFORMANCE,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("unity", "performance", "allocation", "gc"),
    ),
    RuleDefinition(
        rule_id="unity.physics.no-gravity-stacking",
        name="Disable built-in gravity when applying custom gravity",
        summary="Flag Rigidbody.useGravity = true in custom character controllers that also apply"
            "manual gravity via MovePosition or velocity changes.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("unity", "physics", "gravity", "correctness"),
    ),
    RuleDefinition(
        rule_id="unity.performance.no-alloc-physics-overlap",
        name="Use NonAlloc physics overlap methods",
        summary="Prefer Physics.OverlapSphereNonAlloc, OverlapCapsuleNonAlloc, or"
            "SphereCastNonAlloc with reusable buffers over allocating variants.",
        category=RuleCategory.PERFORMANCE,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("unity", "physics", "performance", "allocation"),
    ),
    RuleDefinition(
        rule_id="unity.reliability.no-singleton-access-before-instantiation",
        name="Do not access singletons before instantiation",
        summary="Block access to MonoBehaviour singleton Instance properties before the hosting"
            "script has initialized the instance.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("unity", "singleton", "lifecycle", "reliability"),
    ),
    RuleDefinition(
        rule_id="unity.correctness.no-input-zeroed-before-lateupdate",
        name="Cache input vectors before clearing in Update",
        summary="Warn when input vectors are consumed in Update and cleared before LateUpdate has"
            "a chance to read them.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("unity", "input", "lateupdate", "correctness"),
    ),
    RuleDefinition(
        rule_id="unity.physics.no-moverotation-canceled-by-fixedupdate",
        name="Use direct rotation assignment when FixedUpdate zeros angular velocity",
        summary="Flag rb.MoveRotation() in LateUpdate when FixedUpdate simultaneously zeroes"
            "angularVelocity, which cancels the rotation.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("unity", "physics", "rotation", "correctness"),
    ),
    RuleDefinition(
        rule_id="unity.physics.no-ignorecollision-without-query-guard",
        name="Filter ignored colliders from manual physics queries",
        summary="Warn when custom movement resolvers rely on Physics.IgnoreCollision without also"
            "filtering those colliders out of manual CapsuleCast/Overlap queries.",
        category=RuleCategory.CORRECTNESS,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("unity", "physics", "collision", "correctness"),
    ),
    RuleDefinition(
        rule_id="typescript.accessibility.no-number-input-without-wheel-blur",
        name="Blur number inputs on mouse wheel",
        summary="Warn when a shared Input component renders type=\"number\" without a wheel-blur"
            "guard (`onWheel` with blur or `shouldBlurNumberInputOnWheel`).",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "web", "accessibility", "input", "number"),
    ),
    RuleDefinition(
        rule_id="typescript.web.no-client-api-url-in-server-backend-fetch",
        name="Use server backend URL helpers in server-api routes",
        summary="Block server-api modules from using client-facing API URL helpers or"
            "NEXT_PUBLIC_API_URL for backend fetch base URLs.",
        category=RuleCategory.ARCHITECTURE,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.ERROR,
        default_confidence=FindingConfidence.HIGH,
        default_blocking=True,
        tags=("typescript", "web", "server-api", "architecture", "fetch"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-jpql-null-or-lower-on-optional-filter",
        name="Avoid JPQL IS NULL OR with LOWER on optional filters",
        summary="Warn on @Query JPQL using `:param IS NULL OR` combined with LOWER on optional"
            "filters; prefer empty-string sentinels (`:param = ''`).",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "jpa", "jpql", "query", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-long-poll-read-timeout-mismatch",
        name="Configure Telegram long-poll read timeout above poll timeout",
        summary="Warn when Telegram/httpx long polling uses start_polling or getUpdates without"
            "get_updates_read_timeout exceeding the poll timeout.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("python", "telegram", "httpx", "polling", "reliability"),
    ),
    RuleDefinition(
        rule_id="python.reliability.no-unhandled-idempotent-duplicate-api-response",
        name="Handle idempotent duplicate API responses before raise_for_status",
        summary="Warn when HTTP client code calls raise_for_status on POST/PUT responses without"
            "handling idempotent duplicate error codes in 400 responses first.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.PYTHON,),
        adapter_key="python",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("python", "http", "idempotency", "duplicate", "reliability"),
    ),
    RuleDefinition(
        rule_id="android.reliability.no-async-paginated-fetch-without-generation-guard",
        name="Guard paginated ViewModel fetches with generation tokens",
        summary="Warn when ViewModels mutate paginated list state after await/getOrElse without a"
            "generation or fetchGeneration guard.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.ANDROID,),
        adapter_key="android",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("android", "viewmodel", "pagination", "coroutines", "reliability"),
    ),
    RuleDefinition(
        rule_id="unity.reliability.no-network-singleton-after-ui-bootstrap",
        name="Bootstrap networking singletons before UI screens",
        summary="Warn when bootstrap Awake/Start adds UI screen components before networking"
            "singletons such as NetworkClient or AuthManager.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.UNITY,),
        adapter_key="unity",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("unity", "bootstrap", "network", "singleton", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-readonly-transactional-on-composite-read-service",
        name="Avoid read-only transactions on mixed read/write services",
        summary="Warn when a service class uses @Transactional(readOnly=true) while also calling"
            "repository save/delete/update methods in the same file.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "transaction", "readonly", "repository", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.reliability.transactional-event-listener-requires-phase",
        name="Transactional event listeners need explicit phase",
        summary="Warn on @TransactionalEventListener without an explicit phase= attribute.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "events", "transaction", "listener", "reliability"),
    ),
    RuleDefinition(
        rule_id="java.reliability.no-requires-new-self-invocation",
        name="Avoid REQUIRES_NEW self-invocation in transactional services",
        summary="Warn when a class with multiple @Transactional methods uses"
            "Propagation.REQUIRES_NEW and self-invokes transactional methods via this.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.JAVA,),
        adapter_key="java",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("java", "transaction", "requires-new", "proxy", "reliability"),
    ),
    RuleDefinition(
        rule_id="typescript.react.mutation-requires-cache-invalidation",
        name="Mutations should invalidate or update query cache",
        summary="Warn when useMutation callbacks in a function lack invalidateQueries,"
            "setQueryData, or queryClient cache updates in the same function scope.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.MEDIUM,
        tags=("typescript", "react", "react-query", "mutation", "cache"),
    ),
    RuleDefinition(
        rule_id="typescript.react.polled-query-requires-placeholder-data",
        name="Polled queries should keep previous data visible",
        summary="Warn when useQuery uses refetchInterval without placeholderData or"
            "keepPreviousData to avoid UI flicker between polls.",
        category=RuleCategory.RELIABILITY,
        languages=(RepoLanguage.TYPESCRIPT,),
        adapter_key="typescript",
        default_severity=FindingSeverity.WARNING,
        default_confidence=FindingConfidence.HIGH,
        tags=("typescript", "react", "react-query", "polling", "reliability"),
    ),
)


class RulesRegistry:
    """In-memory registry of rule metadata."""

    def __init__(self, rules: Iterable[RuleDefinition] | None = None):
        self._rules: dict[str, RuleDefinition] = {}
        for rule in rules or ():
            self.register(rule)

    def register(self, rule: RuleDefinition) -> None:
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> RuleDefinition | None:
        return self._rules.get(rule_id)

    def list_rules(
        self,
        *,
        languages: Iterable[RepoLanguage] | None = None,
        category: RuleCategory | None = None,
    ) -> list[RuleDefinition]:
        requested_languages = set(languages) if languages is not None else None
        results: list[RuleDefinition] = []
        for rule in self._rules.values():
            if category is not None and rule.category is not category:
                continue
            if requested_languages is not None and not requested_languages.intersection(
                rule.languages
            ):
                continue
            results.append(rule)
        return sorted(results, key=lambda rule: rule.rule_id)

    def rule_ids_for_languages(self, languages: Iterable[RepoLanguage]) -> tuple[str, ...]:
        return tuple(rule.rule_id for rule in self.list_rules(languages=languages))


def _with_active_backend_rule_metadata(
    rules: Iterable[RuleDefinition],
) -> tuple[RuleDefinition, ...]:
    return tuple(
        rule.model_copy(update={"implementation_state": "active"})
        if rule.rule_id in _ACTIVE_BACKEND_RULE_IDS
        else rule
        for rule in rules
    )


def create_default_registry() -> RulesRegistry:
    """Return the default cross-language taxonomy registry."""

    enriched_rules = tuple(
        enrich_rule_frameworks(rule) for rule in _with_active_backend_rule_metadata(_DEFAULT_RULES)
    )
    return RulesRegistry(enriched_rules)
