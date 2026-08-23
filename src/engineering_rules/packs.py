"""Curated rule packs for targeted engineering-rules workflows."""

from __future__ import annotations

from collections.abc import Iterable

from .models import RulePack
from .registry import RulesRegistry, create_default_registry

_DEFAULT_PACKS = (
    RulePack(
        pack_id="blocking-v1",
        name="High-confidence blocking rules v1",
        summary="Curated blocking rules safe for first-pass CI enforcement.",
        rule_ids=(
            "android.performance.no-main-thread-io",
            "python.correctness.async-blocking-call",
            "shared.security.no-secrets-in-diff",
            "unity.ui.no-direct-imgui-dpi-scaling",
            "unity.reliability.no-runtime-unityeditor-usage",
        ),
    ),
    RulePack(
        pack_id="unity-foundation-v1",
        name="Unity foundation guardrails v1",
        summary="High-confidence build-safety guardrails for Unity/C# game repos.",
        rule_ids=(
            "unity.reliability.no-runtime-unityeditor-usage",
            "unity.ui.no-direct-imgui-dpi-scaling",
        ),
    ),
    RulePack(
        pack_id="ui-static-v1",
        name="React Native UI static guardrails v1",
        summary="Design-token and layout guardrails for React Native TypeScript surfaces.",
        rule_ids=(
            "typescript.ui.no-raw-color-literals",
            "typescript.ui.avoid-fixed-tokenless-layout-values",
        ),
    ),
    RulePack(
        pack_id="frontend-foundation-v1",
        name="Frontend foundation tooling guardrails v1",
        summary="Repo-native typecheck and ESLint surfaces for TypeScript frontend repos.",
        rule_ids=(
            "typescript.foundation.typecheck-clean",
            "typescript.foundation.eslint-clean",
        ),
    ),
    RulePack(
        pack_id="frontend-maintainability-v1",
        name="Frontend maintainability guardrails v1",
        summary="Dead-surface and oversized-module guardrails for TypeScript UI repos.",
        rule_ids=(
            "typescript.maintainability.unused-exported-surface",
            "typescript.maintainability.no-oversized-ui-module",
        ),
    ),
    RulePack(
        pack_id="web-structure-accessibility-v1",
        name="Web structure and accessibility guardrails v1",
        summary=(
            "Support-module, interactive-page coverage, and icon-button accessibility guardrails "
            "for TypeScript web/admin repos."
        ),
        rule_ids=(
            "typescript.maintainability.no-oversized-support-module",
            "typescript.testing.no-interactive-page-without-tests",
            "typescript.accessibility.no-icon-only-button-without-accessible-name",
        ),
    ),
    RulePack(
        pack_id="web-state-safety-v1",
        name="Web state safety guardrails v1",
        summary="Shared query-cache mutation and async mutation guardrails for TypeScript web"
            "repos.",
        rule_ids=(
            "typescript.web.no-query-cache-mutation-outside-cache-module",
            "typescript.web.no-unguarded-async-mutation-ui",
        ),
    ),
    RulePack(
        pack_id="android-foundation-v1",
        name="Android foundation tooling guardrails v1",
        summary="Tooling, contract, and release-ownership guardrails for Android native repos.",
        rule_ids=(
            "android.foundation.android-lint-clean",
            "android.foundation.detekt-clean",
            "android.foundation.api-contract-surface-needs-doc-refresh",
            "android.foundation.variant-owned-release-config",
        ),
    ),
    RulePack(
        pack_id="android-reliability-v1",
        name="Android lifecycle and runtime reliability guardrails v1",
        summary="Lifecycle, DTO, and explicit-state guardrails for Android repos.",
        rule_ids=(
            "android.performance.no-main-thread-io",
            "android.reliability.lifecycle-safe-ui-updates",
            "android.reliability.scrollable-compose-inputs-need-ime-awareness",
            "android.reliability.dto-nullability-default-discipline",
            "android.reliability.no-stringly-typed-state-machine",
        ),
    ),
    RulePack(
        pack_id="android-coroutine-hotpath-v1",
        name="Android coroutine hot-path guardrails v1",
        summary="Block runBlocking on Android UI and network request hot paths.",
        rule_ids=("android.reliability.no-runblocking-hotpath",),
    ),
    RulePack(
        pack_id="android-coroutine-boundary-v1",
        name="Android coroutine boundary guardrails v1",
        summary="Boundary coroutine and sync-wrapper guardrails for Android native repos.",
        rule_ids=(
            "android.reliability.no-unscoped-boundary-coroutine",
            "android.reliability.no-blocking-sync-wrapper",
            "android.architecture.no-viewmodel-direct-repository-instantiation",
        ),
    ),
    RulePack(
        pack_id="android-compose-testability-v1",
        name="Android Compose testability guardrails v1",
        summary=(
            "Compose ViewModel-construction, UI-suppression, and ViewModel-test guardrails for "
            "Android repos."
        ),
        rule_ids=(
            "android.architecture.no-default-viewmodel-parameter-in-composable",
            "android.maintainability.no-ui-detekt-suppression",
            "android.testing.no-viewmodel-without-tests",
        ),
    ),
    RulePack(
        pack_id="android-ui-boundary-v1",
        name="Android UI boundary guardrails v1",
        summary="UI-only transport and deep-link boundary guardrails for Android native repos.",
        rule_ids=(
            "android.architecture.no-ui-direct-api-client",
            "android.architecture.no-ui-direct-buildconfig-transport",
            "android.architecture.no-fragmented-deeplink-intent-parsing",
        ),
    ),
    RulePack(
        pack_id="android-storage-boundary-v1",
        name="Android storage boundary guardrails v1",
        summary="UI/session persistence boundary guardrails for Android native repos.",
        rule_ids=("android.architecture.no-ui-direct-preferences-manager",),
    ),
    RulePack(
        pack_id="android-ui-static-v1",
        name="Android UI static token guardrails v1",
        summary="Theme-color and layout-token guardrails for Android UI surfaces.",
        rule_ids=(
            "android.ui.no-raw-color-literals",
            "android.ui.avoid-fixed-tokenless-layout-values",
        ),
    ),
    RulePack(
        pack_id="android-accessibility-v1",
        name="Android readability accessibility guardrails v1",
        summary="Readability-focused text-size guardrails for Android UI surfaces.",
        rule_ids=("android.ui.avoid-tiny-readability-text",),
    ),
    RulePack(
        pack_id="android-semantic-token-v1",
        name="Android semantic token guardrails v1",
        summary="Status/badge semantic color guardrails for Android UI surfaces.",
        rule_ids=(
            "android.ui.no-local-status-color-map",
            "android.ui.no-semantic-status-color-literals",
        ),
    ),
    RulePack(
        pack_id="android-secrets-config-v1",
        name="Android secrets and config guardrails v1",
        summary=(
            "High-signal hardcoded secret and insecure fallback checks for Android native repos."
        ),
        rule_ids=(
            "android.security.no-hardcoded-secret-literals",
            "android.security.no-secret-fallback-literals",
        ),
    ),
    RulePack(
        pack_id="backend-config-boundary-v1",
        name="Backend config-boundary guardrails v1",
        summary=(
            "Advisory request/transport-layer config access guardrails for Python, Java, and Go "
            "backend repos."
        ),
        rule_ids=(
            "python.config.no-request-layer-env-read",
            "java.config.no-web-layer-value-injection",
            "go.config.no-handler-env-read",
        ),
    ),
    RulePack(
        pack_id="backend-transport-boundary-v1",
        name="Backend transport side-effect boundary guardrails v1",
        summary=(
            "Advisory request-entry boundary guardrails for direct file I/O or outbound HTTP "
            "inside Python, Java, and Go backend transport surfaces."
        ),
        rule_ids=(
            "python.architecture.no-request-layer-local-file-io",
            "python.architecture.no-public-fastapi-model-without-field-aliases",
            "java.architecture.no-web-layer-local-file-io",
            "go.architecture.no-handler-direct-outbound-http",
        ),
    ),
    RulePack(
        pack_id="backend-dependency-inversion-v1",
        name="Backend dependency-inversion boundary guardrails v1",
        summary=(
            "Advisory concrete dependency construction guardrails for request-entry and "
            "service/workflow backend code across Python, Java, and Go repos."
        ),
        rule_ids=(
            "python.architecture.no-request-layer-concrete-dependency",
            "python.architecture.no-service-layer-outbound-client-construction",
            "java.architecture.no-web-layer-concrete-dependency",
            "java.architecture.no-service-layer-outbound-client-construction",
            "go.architecture.no-handler-concrete-dependency",
            "go.architecture.no-service-layer-outbound-client-construction",
        ),
    ),
    RulePack(
        pack_id="backend-service-locator-boundary-v1",
        name="Backend service-locator boundary guardrails v1",
        summary=(
            "Advisory runtime singleton and service-locator resolution guardrails for "
            "request-entry and service/workflow backend code across Python, Java, and Go repos."
        ),
        rule_ids=(
            "python.architecture.no-request-layer-global-collaborator-resolution",
            "python.architecture.no-service-layer-global-collaborator-resolution",
            "java.architecture.no-web-layer-service-locator-access",
            "java.architecture.no-service-layer-service-locator-access",
            "go.architecture.no-handler-service-locator-access",
            "go.architecture.no-service-layer-service-locator-access",
        ),
    ),
    RulePack(
        pack_id="backend-async-cancellation-boundary-v1",
        name="Backend async cancellation boundary guardrails v1",
        summary=(
            "Advisory detached async launch guardrails for Python, Java, and Go backend repos "
            "where request or service code starts background work without an explicit "
            "cancellation/lifecycle boundary."
        ),
        rule_ids=(
            "python.architecture.no-request-layer-detached-async-task",
            "python.architecture.no-service-layer-detached-async-task",
            "java.architecture.no-web-layer-detached-async-launch",
            "java.architecture.no-service-layer-detached-async-launch",
            "go.architecture.no-handler-detached-goroutine",
            "go.architecture.no-service-layer-detached-goroutine",
        ),
    ),
    RulePack(
        pack_id="backend-async-context-propagation-v1",
        name="Backend async context propagation guardrails v1",
        summary=(
            "Advisory async context-propagation guardrails for Python, Java, and Go backend "
            "repos where thread hops or rooted background contexts sever tenant/request state."
        ),
        rule_ids=(
            "python.architecture.no-request-layer-thread-hop-without-context-copy",
            "python.architecture.no-service-layer-thread-hop-without-context-copy",
            "go.architecture.no-handler-rooted-background-context",
            "go.architecture.no-service-layer-rooted-background-context",
        ),
    ),
    RulePack(
        pack_id="backend-background-work-observability-v1",
        name="Backend background-work observability guardrails v1",
        summary=(
            "Advisory async/background observability guardrails for Python, Java, and Go backend "
            "repos where background failures disappear into local logs or task sinks."
        ),
        rule_ids=(
            "python.architecture.no-request-layer-log-only-task-exception-sink",
            "python.architecture.no-service-layer-log-only-task-exception-sink",
            "java.architecture.no-web-layer-log-only-async-outcome",
            "java.architecture.no-service-layer-log-only-async-outcome",
            "go.architecture.no-handler-log-only-background-outcome",
            "go.architecture.no-service-layer-log-only-background-outcome",
        ),
    ),
    RulePack(
        pack_id="backend-http-response-lifecycle-v1",
        name="Backend HTTP response lifecycle guardrails v1",
        summary=(
            "Advisory request-boundary response termination guardrails for Java and Go backend "
            "repos where terminal response writes must stop later request flow."
        ),
        rule_ids=(
            "java.architecture.no-web-layer-terminal-response-fallthrough",
            "go.architecture.no-handler-terminal-response-fallthrough",
        ),
    ),
    RulePack(
        pack_id="backend-outbound-timeout-deadline-v1",
        name="Backend outbound timeout/deadline guardrails v1",
        summary=(
            "Advisory outbound client timeout-shaping guardrails for Python and Java backend "
            "repos where service/workflow code constructs HTTP clients without explicit timeout "
            "boundaries."
        ),
        rule_ids=(
            "java.architecture.no-service-layer-rest-template-without-timeout-shaping",
            "python.architecture.no-service-layer-httpx-client-without-timeout-shaping",
        ),
    ),
    RulePack(
        pack_id="backend-http-error-response-safety-v1",
        name="Backend HTTP error response safety guardrails v1",
        summary=(
            "Advisory request-boundary error-response and outbound content-safety guardrails for "
            "Python and Go backend repos."
        ),
        rule_ids=(
            "go.security.no-handler-error-detail-response",
            "python.security.no-outbound-html-or-url-without-sanitization",
            "python.security.no-raw-exception-detail-response",
        ),
    ),
    RulePack(
        pack_id="backend-strict-json-body-v1",
        name="Backend strict JSON body guardrails v1",
        summary=(
            "Advisory request-body JSON guardrails for Python and Go backend repos where request "
            "parsing should fail closed on malformed or unexpected input."
        ),
        rule_ids=(
            "go.reliability.no-handler-request-json-decode-without-strict-decoder",
            "python.reliability.no-public-fastapi-model-without-cross-field-invariants",
            "python.reliability.no-route-request-json-without-invalid-json-guard",
        ),
    ),
    RulePack(
        pack_id="backend-persistence-boundary-v1",
        name="Backend persistence-boundary guardrails v1",
        summary=(
            "Advisory request-entry persistence-boundary guardrails for Go backend repos where "
            "HTTP handlers should delegate SQL execution and transaction orchestration."
        ),
        rule_ids=("go.architecture.no-handler-direct-sql-execution",),
    ),
    RulePack(
        pack_id="backend-transactional-external-io-v1",
        name="Backend transactional external-I/O guardrails v1",
        summary=(
            "Advisory transactional boundary guardrails for Java backend repos where "
            "@Transactional service/workflow methods should not call outbound collaborators "
            "directly."
        ),
        rule_ids=("java.architecture.no-service-layer-transactional-external-io",),
    ),
    RulePack(
        pack_id="backend-datetime-utc-discipline-v1",
        name="Backend datetime UTC discipline guardrails v1",
        summary=(
            "Advisory UTC timestamp guardrails for Python backend repos where persistence, event, "
            "and scheduler state should avoid naive datetime creation."
        ),
        rule_ids=("python.reliability.no-state-layer-naive-datetime",),
    ),
    RulePack(
        pack_id="backend-atomic-state-write-v1",
        name="Backend atomic state-write guardrails v1",
        summary=(
            "Advisory durable-state write guardrails for Python backend repos where webhook and "
            "event state stores should use atomic temp-file replacement."
        ),
        rule_ids=("python.reliability.no-durable-state-overwrite-without-atomic-replace",),
    ),
    RulePack(
        pack_id="backend-auth-boundary-fail-open-v1",
        name="Backend auth fail-open boundary guardrails v1",
        summary=(
            "Advisory auth-boundary guardrails for Java backend repos where auth filters should "
            "fail closed on broad authentication exceptions."
        ),
        rule_ids=("java.security.no-auth-filter-broad-exception-fallthrough",),
    ),
    RulePack(
        pack_id="backend-secret-safety-v1",
        name="Backend secret-safety guardrails v1",
        summary=(
            "High-confidence blocking checks for embedded secret fallback literals in "
            "backend repos."
        ),
        rule_ids=(
            "python.security.no-secret-fallback-literal",
            "java.security.no-secret-fallback-literal",
            "go.security.no-secret-fallback-literal",
        ),
    ),
    RulePack(
        pack_id="backend-unsafe-sql-v1",
        name="Backend unsafe SQL guardrails v1",
        summary=(
            "High-confidence blocking checks for dynamically constructed SQL at Python, Java, "
            "and Go backend execution surfaces."
        ),
        rule_ids=(
            "python.security.no-dynamic-sql-execution",
            "java.security.no-dynamic-sql-execution",
            "go.security.no-dynamic-sql-execution",
        ),
    ),
    RulePack(
        pack_id="backend-external-literals-v1",
        name="Backend external/config literal guardrails v1",
        summary=(
            "High-confidence blocking checks for hardcoded service URLs, host/domain defaults, "
            "tenant/database defaults, and selected external identifiers in backend repos."
        ),
        rule_ids=(
            "python.reliability.no-hardcoded-external-literals",
            "java.reliability.no-hardcoded-external-literals",
            "go.reliability.no-hardcoded-external-literals",
        ),
    ),
    RulePack(
        pack_id="backend-sensitive-logging-v1",
        name="Backend sensitive logging hygiene guardrails v1",
        summary=(
            "Runtime-only logging guardrails for raw credentials plus advisory PII exposure in "
            "Python, Java, and Go backend repos."
        ),
        rule_ids=(
            "python.security.no-raw-credential-logging",
            "python.security.no-raw-pii-logging",
            "java.security.no-raw-credential-logging",
            "java.security.no-raw-pii-logging",
            "go.security.no-raw-credential-logging",
            "go.security.no-raw-pii-logging",
        ),
    ),
    RulePack(
        pack_id="backend-maintainability-v1",
        name="Backend maintainability guardrails v1",
        summary=(
            "Oversized Python and Java runtime surface guardrails based on the dominant backend "
            "service patterns in production backend codebases."
        ),
        rule_ids=(
            "python.maintainability.no-oversized-runtime-function",
            "java.maintainability.no-oversized-service-class",
            "java.maintainability.no-oversized-service-method",
        ),
    ),
    RulePack(
        pack_id="python-runtime-structure-v1",
        name="Python runtime structure guardrails v1",
        summary=(
            "Python runtime module-size, template-catalog typing, ingress-normalization, and "
            "cleanup-path guardrails for request and service code."
        ),
        rule_ids=(
            "python.architecture.no-webhook-payload-without-normalization",
            "python.maintainability.no-oversized-runtime-module",
            "python.error-handling.no-bare-except-cleanup",
            "python.typing.no-untyped-template-catalog",
        ),
    ),
    RulePack(
        pack_id="java-structure-testing-v1",
        name="Java structure and testing guardrails v1",
        summary=(
            "Java controller-test, cyclomatic-hotspot, and static lock-pool guardrails for "
            "backend repos."
        ),
        rule_ids=(
            "java.testing.no-controller-without-test-class",
            "java.maintainability.no-cyclomatic-hotspot-method",
            "java.concurrency.no-static-lock-pool-without-eviction",
        ),
    ),
    RulePack(
        pack_id="python-concurrency-resource-v1",
        name="Python concurrency and resource guardrails v1",
        summary=(
            "Async lock-pool, upload-read, and sync-database-on-async-path guardrails for "
            "Python backend repos."
        ),
        rule_ids=(
            "python.concurrency.no-unbounded-async-lock-pool",
            "python.concurrency.no-racy-lock-pool-creation",
            "python.resource.no-unbounded-upload-read",
            "python.correctness.no-sync-db-client-on-async-path",
        ),
    ),
    RulePack(
        pack_id="java-boundary-reliability-v1",
        name="Java boundary and reliability guardrails v1",
        summary=(
            "Controller-boundary, scheduler-concurrency, batch-save, and event-listener "
            "guardrails for Java backend repos."
        ),
        rule_ids=(
            "java.architecture.no-controller-direct-repository-access",
            "java.architecture.no-entity-crossing-async-or-requires-new-boundary",
            "java.concurrency.no-concurrentmap-scheduled-unsafe-removal",
            "java.reliability.no-batch-saveall-without-partial-failure-guard",
            "java.architecture.event-listener-needs-transaction-phase-boundary",
        ),
    ),
    RulePack(
        pack_id="python-complexity-testing-v1",
        name="Python complexity and testing guardrails v1",
        summary=(
            "Cyclomatic-hotspot and large-runtime-module test-coverage guardrails for "
            "Python backend repos."
        ),
        rule_ids=(
            "python.maintainability.no-cyclomatic-hotspot-method",
            "python.testing.no-large-runtime-module-without-test-file",
        ),
    ),
    RulePack(
        pack_id="java-reliability-testing-v1",
        name="Java reliability and testing guardrails v1",
        summary=(
            "Repository pagination, critical-path exception surfacing, and scheduler-test "
            "guardrails for Java backend repos."
        ),
        rule_ids=(
            "java.reliability.no-nonadditive-flyway-migration",
            "java.reliability.no-unbounded-findall-without-pagination",
            "java.maintainability.no-exception-swallowing-in-critical-paths",
            "java.testing.no-scheduled-service-without-scheduler-test",
        ),
    ),
    RulePack(
        pack_id="web-state-composition-v1",
        name="Web state and page composition guardrails v1",
        summary=(
            "Query-key consistency, hook-heavy page, and direct API import-sprawl guardrails "
            "for TypeScript web/admin repos."
        ),
        rule_ids=(
            "typescript.web.no-inconsistent-query-key-mutation",
            "typescript.maintainability.no-hook-heavy-page-module",
            "typescript.architecture.no-page-direct-api-import-sprawl",
        ),
    ),
    RulePack(
        pack_id="react-state-discipline-v1",
        name="React state discipline guardrails v1",
        summary=(
            "Ban new useEffect-driven runtime state flows and unstable useSyncExternalStore "
            "snapshots in TypeScript React stacks while teams burn down temporary repo waivers."
        ),
        rule_ids=(
            "typescript.react.no-use-effect",
            "typescript.react.no-unstable-sync-external-store-snapshot",
        ),
    ),
    RulePack(
        pack_id="android-screen-callback-quality-v1",
        name="Android screen and callback quality guardrails v1",
        summary=(
            "Compose screen-size and boundary-callback test guardrails for Android native repos."
        ),
        rule_ids=(
            "android.maintainability.no-oversized-screen-composable",
            "android.testing.no-boundary-callback-without-test",
        ),
    ),
    RulePack(
        pack_id="python-background-supervision-v1",
        name="Python background supervision guardrails v1",
        summary=(
            "Daemon failure-sink guardrails for Python backend repos where long-lived "
            "background tasks must surface durable failures."
        ),
        rule_ids=(
            "python.architecture.no-daemon-task-without-failure-sink",
        ),
    ),
    RulePack(
        pack_id="java-spring-wiring-v1",
        name="Java Spring wiring guardrails v1",
        summary=(
            "Self-provider circular-wiring guardrails for Java service/workflow beans."
        ),
        rule_ids=(
            "java.architecture.no-service-layer-objectprovider-circular-self-reference",
        ),
    ),
    RulePack(
        pack_id="web-server-isolation-v1",
        name="Web server isolation guardrails v1",
        summary=(
            "Server-route tenant isolation guardrails for TypeScript web/admin repos."
        ),
        rule_ids=(
            "typescript.web.no-server-api-tenant-isolation-bypass",
        ),
    ),
    RulePack(
        pack_id="android-service-boundary-v1",
        name="Android service boundary guardrails v1",
        summary=(
            "Service-locator guardrails for Android service and receiver boundaries."
        ),
        rule_ids=(
            "android.architecture.no-service-or-receiver-direct-service-locator-access",
        ),
    ),
    RulePack(
        pack_id="web-boundary-v1",
        name="Web transport and response boundary guardrails v1",
        summary="Transport-client and response-normalization guardrails for TS web/admin repos.",
        rule_ids=(
            "typescript.web.no-raw-transport-calls",
            "typescript.web.no-direct-response-casting",
        ),
    ),
    RulePack(
        pack_id="web-route-contract-v1",
        name="Web route contract guardrails v1",
        summary="Route manifest, access-policy, and codec guardrails for TypeScript web/admin"
            "repos.",
        rule_ids=(
            "typescript.web.route-manifest-centralization",
            "typescript.web.route-access-policy-centralization",
            "typescript.web.route-query-codec-centralization",
            "typescript.web.route-family-literal-consistency",
        ),
    ),
    RulePack(
        pack_id="web-browser-sideeffect-v1",
        name="Web browser side-effect guardrails v1",
        summary=(
            "High-signal browser dialog, navigation, storage, and modal-controller "
            "guardrails for TS web/admin repos."
        ),
        rule_ids=(
            "typescript.web.no-window-confirm",
            "typescript.web.no-hard-browser-navigation",
            "typescript.web.no-direct-browser-storage",
            "typescript.web.no-modal-controller-bypass",
        ),
    ),
    RulePack(
        pack_id="web-semantic-token-v1",
        name="Web semantic token guardrails v1",
        summary=("Status/badge semantic helper and token guardrails for TS web/admin repos."),
        rule_ids=(
            "typescript.web.no-local-status-variant-map",
            "typescript.web.no-raw-semantic-tailwind-status-classes",
            "typescript.web.no-semantic-status-hex-literals",
        ),
    ),
    RulePack(
        pack_id="ui-coverage-v1",
        name="React Native UI coverage guardrails v1",
        summary="Diff-first coverage checks for changed React Native screens and components.",
        rule_ids=("shared.testing.changed-code-has-tests",),
    ),
    RulePack(
        pack_id="testing-hygiene-v1",
        name="Testing hygiene guardrails v1",
        summary="Diff-first skip and disable marker guardrails for changed test files.",
        rule_ids=(
            "shared.testing.no-unconditional-skip",
            "shared.testing.test-with-change-ratchet",
        ),
    ),
    RulePack(
        pack_id="ui-lifecycle-v1",
        name="React Native lifecycle timer guardrails v1",
        summary="Cleanup-first timer and poller lifecycle checks for React Native effects.",
        rule_ids=(
            "typescript.ui.no-orphaned-effect-intervals",
            "typescript.ui.no-orphaned-effect-timeouts",
        ),
    ),
    RulePack(
        pack_id="ui-accessibility-v1",
        name="React Native readability accessibility guardrails v1",
        summary="Contrast and readability-color guardrails for React Native UI surfaces.",
        rule_ids=(
            "typescript.ui.no-low-contrast-readability-pairings",
            "typescript.ui.avoid-raw-readability-colors",
            "typescript.ui.risky-status-badge-contrast",
        ),
    ),
    RulePack(
        pack_id="java-jpa-transaction-reliability-v1",
        name="Java JPA and transaction reliability guardrails v1",
        summary=(
            "Transaction, async, JPA, migration, and upload guardrails for Java Spring "
            "backend repos."
        ),
        rule_ids=(
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
            "java.reliability.no-jpql-null-or-lower-on-optional-filter",
            "java.reliability.no-readonly-transactional-on-composite-read-service",
            "java.reliability.transactional-event-listener-requires-phase",
            "java.reliability.no-requires-new-self-invocation",
        ),
    ),
    RulePack(
        pack_id="web-frontend-correctness-v1",
        name="Web frontend correctness guardrails v1",
        summary="TypeScript React/Next.js correctness, security, and accessibility guardrails.",
        rule_ids=(
            "typescript.correctness.no-falsy-default-for-numeric-zero",
            "typescript.react.no-mixed-controlled-uncontrolled",
            "typescript.web.no-manual-multipart-headers",
            "typescript.accessibility.modal-focus-trap",
            "typescript.security.no-raw-error-in-error-boundary",
            "typescript.security.no-unvalidated-external-href",
            "typescript.reliability.no-concurrent-token-refresh",
            "typescript.performance.no-eager-heavy-dependency-import",
            "typescript.web.no-ephemeral-ids-for-deep-linking",
            "typescript.maintainability.no-console-in-production-browser-code",
            "typescript.correctness.no-unvalidated-numeric-precision",
            "typescript.web.no-unauthenticated-image-blob-urls",
            "typescript.architecture.no-inline-filter-logic-in-components",
            "typescript.correctness.no-unvalidated-url-tab-param",
            "typescript.accessibility.no-number-input-without-wheel-blur",
            "typescript.web.no-client-api-url-in-server-backend-fetch",
            "typescript.react.query-key-registry",
            "typescript.react.mutation-requires-cache-invalidation",
            "typescript.react.polled-query-requires-placeholder-data",
        ),
    ),
    RulePack(
        pack_id="android-compose-reliability-v1",
        name="Android Compose reliability guardrails v1",
        summary="Kotlin/Jetpack Compose correctness, security, and transport guardrails.",
        rule_ids=(
            "android.correctness.gson-nonnull-field-needs-nullable-type",
            "android.reliability.api-response-type-must-match-contract",
            "android.lifecycle.viewmodel-cleared-must-be-singular",
            "android.lifecycle.geofence-transition-needs-debounce",
            "android.security.no-hardcoded-credentials-in-buildconfig",
            "android.security.no-sensitive-token-in-url-query",
            "android.correctness.fcm-default-notification-channel-required",
            "android.compose.dialog-state-must-be-hoisted-above-conditional",
            "android.compose.dark-theme-textfield-needs-explicit-text-color",
            "android.reliability.proguard-r8-must-keep-generic-type-signatures",
            "android.correctness.custom-flow-first-extension-is-unsafe",
            "android.reliability.okhttp-legacy-mediatype-needs-extension",
            "android.architecture.deep-link-routing-must-use-shared-target-parser",
            "android.correctness.keyboard-input-needs-ime-padding",
            "android.reliability.notification-deep-link-must-fetch-by-id",
            "android.reliability.no-async-paginated-fetch-without-generation-guard",
        ),
    ),
    RulePack(
        pack_id="python-ai-integration-v1",
        name="Python AI integration reliability guardrails v1",
        summary="LLM, MCP, webhook, and async integration guardrails for Python AI platforms.",
        rule_ids=(
            "python.ai.no-unvalidated-llm-output-on-customer-channel",
            "python.ai.no-raw-tool-response-to-llm",
            "python.ai.no-generic-session-identity-collapse",
            "python.ai.no-mcp-process-leak",
            "python.correctness.no-timeout-kwarg-to-async-callable-without-signature",
            "python.security.no-webhook-replay-without-origin-validation",
            "python.reliability.no-db-sslmode-require-with-verification",
            "python.correctness.no-context-manager-exit-suppressing-exceptions",
            "python.ai.no-unhandled-failed-generation-pattern",
            "python.ai.no-missing-llm-timeout-in-retryable-pattern",
            "python.security.no-tenant-shared-webhook-secret",
            "python.reliability.no-lifespan-without-cleanup-guard",
            "python.reliability.no-orphaned-async-task-on-disconnect",
            "python.reliability.no-long-poll-read-timeout-mismatch",
            "python.reliability.no-unhandled-idempotent-duplicate-api-response",
        ),
    ),
    RulePack(
        pack_id="go-server-security-v1",
        name="Go server security and reliability guardrails v1",
        summary="Input validation, OAuth, JSON decoding, and state-store guardrails for Go servers.",
        rule_ids=(
            "go.correctness.no-squared-vector-magnitude-without-sqrt",
            "go.reliability.no-hardcoded-sql-schema-reference-without-migration-check",
            "go.reliability.no-json-numeric-field-without-flexible-decoder",
            "go.security.no-plaintext-http-error-for-unconfigured-service",
            "go.security.authoritative-server-must-validate-client-input",
            "go.security.no-oauth-callback-without-csrf-state",
            "go.reliability.no-in-memory-store-without-expiry-pruning",
            "go.security.no-unvalidated-enumerated-input",
            "go.architecture.no-implicit-cross-module-session-fields",
        ),
    ),
    RulePack(
        pack_id="unity-gameplay-reliability-v1",
        name="Unity gameplay reliability guardrails v1",
        summary="Batch-mode, physics, lifecycle, and allocation guardrails for Unity C# repos.",
        rule_ids=(
            "unity.reliability.no-renderer-creation-in-batchmode",
            "unity.reliability.no-destroyimmediate-on-resources-assets",
            "unity.performance.no-per-frame-allocation-in-hot-path",
            "unity.physics.no-gravity-stacking",
            "unity.performance.no-alloc-physics-overlap",
            "unity.reliability.no-singleton-access-before-instantiation",
            "unity.correctness.no-input-zeroed-before-lateupdate",
            "unity.physics.no-moverotation-canceled-by-fixedupdate",
            "unity.physics.no-ignorecollision-without-query-guard",
            "unity.reliability.no-network-singleton-after-ui-bootstrap",
        ),
    ),
    RulePack(
        pack_id="react-native-network-v1",
        name="React Native network reliability guardrails v1",
        summary="Module side-effect, binary upload, buffer, and websocket guardrails for React Native apps.",
        rule_ids=(
            "typescript.reliability.no-module-level-throwing-side-effect",
            "typescript.reliability.no-formdata-for-raw-binary-upload",
            "typescript.reliability.no-unbounded-buffer-without-chunking",
            "typescript.react.no-websocket-reconnect-after-unmount",
        ),
    ),
)


class RulePackResolutionError(ValueError):
    """Raised when a rule pack cannot be resolved or validated."""


class RulePackRegistry:
    """Registry of curated rule packs validated against the main rule registry."""

    def __init__(
        self,
        packs: Iterable[RulePack] | None = None,
        *,
        rules_registry: RulesRegistry | None = None,
    ):
        self._rules_registry = rules_registry or create_default_registry()
        self._packs: dict[str, RulePack] = {}
        for pack in packs or ():
            self.register(pack)

    def register(self, pack: RulePack) -> None:
        unknown_rule_ids = [
            rule_id for rule_id in pack.rule_ids if self._rules_registry.get(rule_id) is None
        ]
        if unknown_rule_ids:
            rendered = ", ".join(sorted(unknown_rule_ids))
            raise RulePackResolutionError(
                f"Rule pack {pack.pack_id} references unknown rules: {rendered}"
            )
        self._packs[pack.pack_id] = pack

    def get(self, pack_id: str) -> RulePack | None:
        return self._packs.get(pack_id)

    def list_packs(self) -> list[RulePack]:
        return sorted(self._packs.values(), key=lambda pack: pack.pack_id)

    def resolve_rule_ids(self, pack_ids: Iterable[str]) -> tuple[str, ...]:
        resolved: list[str] = []
        seen: set[str] = set()
        missing_pack_ids: list[str] = []
        for pack_id in pack_ids:
            pack = self.get(pack_id)
            if pack is None:
                missing_pack_ids.append(pack_id)
                continue
            for rule_id in pack.rule_ids:
                if rule_id in seen:
                    continue
                resolved.append(rule_id)
                seen.add(rule_id)
        if missing_pack_ids:
            rendered = ", ".join(sorted(missing_pack_ids))
            raise RulePackResolutionError(f"Unknown rule pack(s): {rendered}")
        return tuple(resolved)


def create_default_pack_registry(
    *, rules_registry: RulesRegistry | None = None
) -> RulePackRegistry:
    """Return the default curated rule-pack registry."""

    return RulePackRegistry(_DEFAULT_PACKS, rules_registry=rules_registry)
