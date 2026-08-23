"""Java adapter for backend config, secret, and SQL safety rules."""

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

_WEB_LAYER_VALUE_RULE_ID = "java.config.no-web-layer-value-injection"
_WEB_LAYER_FILE_IO_RULE_ID = "java.architecture.no-web-layer-local-file-io"
_WEB_LAYER_CONCRETE_DEPENDENCY_RULE_ID = "java.architecture.no-web-layer-concrete-dependency"
_CONTROLLER_DIRECT_REPOSITORY_ACCESS_RULE_ID = (
    "java.architecture.no-controller-direct-repository-access"
)
_WEB_LAYER_SERVICE_LOCATOR_RULE_ID = "java.architecture.no-web-layer-service-locator-access"
_WEB_LAYER_ASYNC_RULE_ID = "java.architecture.no-web-layer-detached-async-launch"
_WEB_LAYER_ASYNC_OBSERVABILITY_RULE_ID = "java.architecture.no-web-layer-log-only-async-outcome"
_WEB_LAYER_RESPONSE_LIFECYCLE_RULE_ID = (
    "java.architecture.no-web-layer-terminal-response-fallthrough"
)
_AUTH_FILTER_FAIL_OPEN_RULE_ID = "java.security.no-auth-filter-broad-exception-fallthrough"
_SERVICE_LAYER_ASYNC_RULE_ID = "java.architecture.no-service-layer-detached-async-launch"
_SERVICE_LAYER_ASYNC_OBSERVABILITY_RULE_ID = (
    "java.architecture.no-service-layer-log-only-async-outcome"
)
_SERVICE_LAYER_OUTBOUND_CLIENT_RULE_ID = (
    "java.architecture.no-service-layer-outbound-client-construction"
)
_SERVICE_LAYER_TIMEOUT_RULE_ID = (
    "java.architecture.no-service-layer-rest-template-without-timeout-shaping"
)
_SERVICE_LAYER_TRANSACTIONAL_EXTERNAL_IO_RULE_ID = (
    "java.architecture.no-service-layer-transactional-external-io"
)
_SERVICE_LAYER_SERVICE_LOCATOR_RULE_ID = "java.architecture.no-service-layer-service-locator-access"
_SERVICE_LAYER_OBJECTPROVIDER_CIRCULAR_SELF_REFERENCE_RULE_ID = (
    "java.architecture.no-service-layer-objectprovider-circular-self-reference"
)
_CONCURRENTMAP_SCHEDULED_UNSAFE_REMOVAL_RULE_ID = (
    "java.concurrency.no-concurrentmap-scheduled-unsafe-removal"
)
_STATIC_LOCK_POOL_WITHOUT_EVICTION_RULE_ID = "java.concurrency.no-static-lock-pool-without-eviction"
_BATCH_SAVEALL_WITHOUT_PARTIAL_FAILURE_GUARD_RULE_ID = (
    "java.reliability.no-batch-saveall-without-partial-failure-guard"
)
_UNBOUNDED_FINDALL_WITHOUT_PAGINATION_RULE_ID = (
    "java.reliability.no-unbounded-findall-without-pagination"
)
_EVENT_LISTENER_TRANSACTION_PHASE_BOUNDARY_RULE_ID = (
    "java.architecture.event-listener-needs-transaction-phase-boundary"
)
_NONADDITIVE_FLYWAY_MIGRATION_RULE_ID = "java.reliability.no-nonadditive-flyway-migration"
_ENTITY_ASYNC_TRANSACTION_BOUNDARY_RULE_ID = (
    "java.architecture.no-entity-crossing-async-or-requires-new-boundary"
)
_SECRET_FALLBACK_RULE_ID = "java.security.no-secret-fallback-literal"
_DYNAMIC_SQL_RULE_ID = "java.security.no-dynamic-sql-execution"
_EXTERNAL_LITERAL_RULE_ID = "java.reliability.no-hardcoded-external-literals"
_CREDENTIAL_LOGGING_RULE_ID = "java.security.no-raw-credential-logging"
_PII_LOGGING_RULE_ID = "java.security.no-raw-pii-logging"
_CONTROLLER_WITHOUT_TEST_CLASS_RULE_ID = "java.testing.no-controller-without-test-class"
_SCHEDULED_SERVICE_WITHOUT_SCHEDULER_TEST_RULE_ID = (
    "java.testing.no-scheduled-service-without-scheduler-test"
)
_SERVICE_LAYER_CLASS_SIZE_RULE_ID = "java.maintainability.no-oversized-service-class"
_SERVICE_LAYER_METHOD_SIZE_RULE_ID = "java.maintainability.no-oversized-service-method"
_CYCLOMATIC_HOTSPOT_METHOD_RULE_ID = "java.maintainability.no-cyclomatic-hotspot-method"
_CRITICAL_PATH_EXCEPTION_SWALLOWING_RULE_ID = (
    "java.maintainability.no-exception-swallowing-in-critical-paths"
)
_JAVA_OVERSIZED_CLASS_LINE_THRESHOLD = 500
_JAVA_OVERSIZED_METHOD_LINE_THRESHOLD = 50
_JAVA_CYCLOMATIC_HOTSPOT_SCORE_THRESHOLD = 10
_JAVA_CYCLOMATIC_HOTSPOT_HIGH_SCORE_THRESHOLD = 14
_JAVA_CYCLOMATIC_HOTSPOT_NESTING_THRESHOLD = 3
_JAVA_CYCLOMATIC_HOTSPOT_LINE_THRESHOLD = 20
_JAVA_CONTROLLER_ENDPOINT_SURFACE_THRESHOLD = 3
_SKIP_DIRECTORIES = frozenset(
    {".git", ".gradle", ".idea", "build", "generated", "node_modules", "out", "target"}
)
_JAVA_CONTROLLER_TEST_CLASS_SUFFIXES = ("Test", "IT", "IntegrationTest")
_JAVA_LOCK_POOL_VALUE_TYPE_SUFFIXES = ("Lock", "Semaphore", "Mutex")
_JAVA_CONTROLLER_PATH_MARKERS = frozenset({"controller", "controllers"})
_WEB_LAYER_PATH_MARKERS = frozenset({"controller", "controllers", "filter", "filters", "web"})
_JAVA_CONTROLLER_HINT_PATTERN = re.compile(r"@RestController\b|@Controller\b")
_WEB_LAYER_HINT_PATTERN = re.compile(r"@RestController|@Controller|\bOncePerRequestFilter\b")
_JAVA_AUTH_FILTER_STEM_MARKERS = frozenset({"api", "auth", "authentication", "jwt", "key", "token"})
_JAVA_BATCH_PATH_MARKERS = frozenset({"batch", "batches", "job", "jobs", "scheduler", "schedulers"})
_JAVA_FACTORY_CONTEXT_MARKERS = frozenset({"factory", "factories"})
_SERVICE_LAYER_PATH_MARKERS = frozenset(
    {"event", "events", "integration", "notification", "service", "services", "workflow"}
)
_JAVA_BOOTSTRAP_CONTEXT_MARKERS = frozenset(
    {
        "bootstrap",
        "bootstrapper",
        "fixture",
        "fixtures",
        "initialise",
        "initialize",
        "initializer",
        "migration",
        "migrator",
        "seed",
        "seeder",
        "startup",
    }
)
_SERVICE_LAYER_HINT_PATTERN = re.compile(r"@Service\b|@Component\b|@EventListener\b")
_CONFIGURATION_HINT_PATTERN = re.compile(r"@Configuration\b|@Bean\b")
_JAVA_SERVICE_LOCATOR_OWNER_MARKERS = frozenset({"context", "factory", "provider", "registry"})
_JAVA_SERVICE_LOCATOR_OWNER_EXACT_NAMES = frozenset(
    {"ApplicationContext", "AutowireCapableBeanFactory", "BeanFactory", "FirebaseMessaging"}
)
_JAVA_EXECUTOR_OWNER_MARKERS = frozenset({"executor"})
_VALUE_INJECTION_PATTERN = re.compile(r"@Value\s*\(")
_ASYNC_ANNOTATION_PATTERN = re.compile(r"@Async(?:\s*\([^)]*\))?")
_JAVA_DETACHED_ASYNC_PATTERN = re.compile(
    r"\b(?P<owner>CompletableFuture|[A-Za-z_][A-Za-z0-9_]*)\."
    r"(?P<member>runAsync|execute)\s*\("
)
_JAVA_TENANT_CONTEXT_SET_PATTERN = re.compile(r"TenantContext\.setCurrentTenant(?:Id|Code)\s*\(")
_JAVA_TENANT_CONTEXT_BIND_PATTERN = re.compile(
    r"TenantContext\.setCurrent(?:Tenant|Branch)[A-Za-z0-9_]*\s*\("
)
_JAVA_TENANT_CONTEXT_CLEAR_PATTERN = re.compile(r"TenantContext\.clear\s*\(")
_JAVA_TENANT_CONTEXT_DIRECT_MUTATION_PATTERN = re.compile(
    r"TenantContext\.(?P<member>setCurrent(?:Tenant|Branch)[A-Za-z0-9_]*|clear)\s*\("
)
_JAVA_TENANT_CONTEXT_VALUE_PATTERN = re.compile(
    r"\btenantId\b|\.tenantId\s*\(\)|\.getTenantId\s*\(|"
    r"\btenantCode\b|\.tenantCode\s*\(\)|\.getTenantCode\s*\("
)
_SCHEDULED_ANNOTATION_PATTERN = re.compile(r"@Scheduled\b(?:\s*\([^)]*\))?")
_JAVA_HANDLER_INTERCEPTOR_HINT_PATTERN = re.compile(
    r"\b(?:HandlerInterceptor|WebRequestInterceptor)\b"
)
_JAVA_REQUEST_BOUNDARY_HINT_PATTERN = re.compile(
    r"\b(?:HttpServletRequest|ServletRequest|ServerHttpRequest|RequestContextHolder)\b"
)
_JAVA_BOOTSTRAP_HINT_PATTERN = re.compile(
    r"@PostConstruct\b|\b(?:CommandLineRunner|ApplicationRunner)\b"
)
_JAVA_BACKGROUND_SURFACE_PATTERN = re.compile(
    r"\b(?:"
    r"meterRegistry|metrics?|counter|gauge|histogram|audit|incident|capture"
    r"|record(?:Failure|Error|Outcome|Result|Status)"
    r"|save(?:Failure|Error|Outcome|Result|Status)"
    r"|persist(?:Failure|Error|Outcome|Result|Status)"
    r"|update(?:Failure|Error|Outcome|Result|Status)"
    r"|emit(?:Metric|Event)|publish(?:Metric|Event)"
    r")\b",
    re.IGNORECASE,
)
_JAVA_ASYNC_METHOD_PATTERN = re.compile(
    r"(?:@\w+(?:\([^)]*\))?\s*)*"
    r"(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*"
    r"(?P<return>[A-Za-z_][A-Za-z0-9_<>, ?\[\].]*)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_JAVA_PRIMARY_TYPE_PATTERN = re.compile(
    r"\b(?:class|interface|enum|record)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_JAVA_RESPONSE_PARAM_PATTERN = re.compile(
    r"\bHttpServletResponse\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_JAVA_FILTER_CHAIN_PARAM_PATTERN = re.compile(r"\bFilterChain\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_JAVA_IMPORT_PATTERN = re.compile(r"^\s*import\s+(?P<fqcn>[A-Za-z0-9_.]+)\s*;", re.MULTILINE)
_JAVA_ENTITY_ANNOTATION_PATTERN = re.compile(r"@Entity\b(?:\s*\([^)]*\))?")
_JAVA_REPOSITORY_INTERFACE_PATTERN = re.compile(r"\binterface\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_JAVA_REPOSITORY_FIELD_PATTERN = re.compile(
    r"\b(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?"
    r"(?P<type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*Repository)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:[;=])"
)
_JAVA_REPOSITORY_FINDALL_PATTERN = re.compile(
    r"\b(?:this\.)?(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>findAll(?:[A-Z][A-Za-z0-9_]*)?)\s*\(\s*\)"
)
_JAVA_PAGINATION_PARAMETER_PATTERN = re.compile(r"\b(?:PageRequest|Pageable)\b")
_JAVA_CONCURRENT_MAP_DECLARATION_PATTERN = re.compile(
    r"\b(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?"
    r"(?P<type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:ConcurrentMap|ConcurrentHashMap))"
    r"(?:\s*<[^;=(){}]+>)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_JAVA_CONCURRENT_MAP_ENTRY_ITERATOR_PATTERN = re.compile(
    r"\b(?:final\s+)?(?:Iterator|var)\s*(?:<[^;=]+>)?\s+"
    r"(?P<iterator>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:this\.)?(?P<map>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*entrySet\s*\(\s*\)\s*"
    r"\.\s*iterator\s*\(\s*\)"
)
_JAVA_STATIC_LOCK_POOL_FIELD_PATTERN = re.compile(
    r"\b(?:private|protected|public)?\s*static\s+(?:final\s+)?"
    r"(?P<map_type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:(?:[A-Za-z_][A-Za-z0-9_]*)?Map))"
    r"\s*<\s*[^,<>]+(?:<[^>]+>)?\s*,\s*"
    r"(?P<value_type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*<[^>]+>)?\s*>\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_JAVA_LOCK_POOL_GROWTH_PATTERN = re.compile(
    r"\b(?:this\.|[A-Za-z_][A-Za-z0-9_]*\.)?(?P<map>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>computeIfAbsent|putIfAbsent)\s*\("
)
_JAVA_COLLABORATOR_FIELD_PATTERN = re.compile(
    r"^\s*(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?"
    r"(?P<type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:[;=])",
    re.MULTILINE,
)
_JAVA_COLLECTION_FOREACH_PATTERN = re.compile(
    r"\b(?:this\.)?(?P<collection>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*forEach\s*\("
)
_JAVA_SAVEALL_CALL_PATTERN = re.compile(
    r"\b(?:this\.)?(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*saveAll\s*\(\s*"
    r"(?:this\.)?(?P<collection>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_JAVA_TENANT_SCOPED_ID_LOOKUP_PATTERN = re.compile(
    r"\b(?P<method>"
    r"findByIdAndTenantId(?:[A-Za-z0-9_]*)?"
    r"|findByTenantIdAndId(?:[A-Za-z0-9_]*)?"
    r")\s*\("
)
_JAVA_BARE_TENANT_LOOKUP_PATTERN = re.compile(
    r"\b(?:this\.)?(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>findById|getReferenceById)\s*\("
)
_JAVA_SAVE_CALL_PATTERN = re.compile(
    r"\b(?:this\.)?(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*save\s*\(\s*"
    r"(?:this\.)?(?P<artifact>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_JAVA_ACTIVE_SETTER_PATTERN_TEMPLATE = r"\b{artifact}\s*\.\s*setActive\s*\(\s*true\s*\)"
_JAVA_ACTIVE_STATUS_PATTERN_TEMPLATE = (
    r"\b{artifact}\s*\.\s*set(?:Status|State)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?P<state>ACTIVE|OPEN|PENDING|ENABLED|CURRENT)\b"
)
_JAVA_ACTIVE_GUARD_PATTERN = re.compile(
    r"\b(?:exists|count|find(?:First|Top)?)By[A-Za-z0-9_]*(?:ActiveTrue|Status|State)[A-Za-z0-9_]*\s*\("
)
_JAVA_UNIQUENESS_METHOD_PATTERN = re.compile(
    r"\b(?:boolean|Boolean|long|Long|int|Integer)\s+"
    r"(?P<method>(?:exists|count)By[A-Z][A-Za-z0-9_]*)\s*\("
)
_TRANSACTIONAL_ANNOTATION_PATTERN = re.compile(r"@Transactional\b(?:\s*\((?P<args>[^)]*)\))?")
_EVENT_LISTENER_ANNOTATION_PATTERN = re.compile(r"@EventListener\b(?:\s*\([^)]*\))?")
_TRANSACTIONAL_EVENT_LISTENER_ANNOTATION_PATTERN = re.compile(r"@TransactionalEventListener\b")
_JAVA_TRANSACTIONAL_READ_ONLY_PATTERN = re.compile(r"\breadOnly\s*=\s*true\b")
_JAVA_REQUIRES_NEW_PROPAGATION_PATTERN = re.compile(r"\b(?:Propagation\.)?REQUIRES_NEW\b")
_JAVA_TRANSACTIONAL_EXTERNAL_IO_CALL_PATTERN = re.compile(
    r"\b(?:this\.)?(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_JAVA_TRANSACTIONAL_EXTERNAL_IO_OWNER_MARKERS = frozenset(
    {"client", "connector", "gateway", "sender", "storage"}
)
_JAVA_TRANSACTIONAL_EXTERNAL_IO_METHOD_MARKERS = frozenset(
    {
        "delete",
        "dispatch",
        "exchange",
        "execute",
        "initiate",
        "patch",
        "post",
        "put",
        "send",
        "store",
        "upload",
    }
)
_JAVA_EVENT_LISTENER_READ_METHOD_MARKERS = frozenset(
    {"count", "exists", "fetch", "find", "get", "list", "load", "read"}
)
_JAVA_EVENT_LISTENER_WRITE_METHOD_MARKERS = frozenset(
    {"delete", "flush", "insert", "merge", "persist", "remove", "save", "update"}
)
_JAVA_EVENT_LISTENER_ORCHESTRATION_OWNER_MARKERS = frozenset(
    {
        "dispatcher",
        "job",
        "orchestrator",
        "outbox",
        "processor",
        "publisher",
        "queue",
        "scheduler",
        "service",
        "workflow",
    }
)
_JAVA_EVENT_LISTENER_ORCHESTRATION_METHOD_MARKERS = frozenset(
    {
        "create",
        "delete",
        "dispatch",
        "enqueue",
        "persist",
        "publish",
        "queue",
        "save",
        "schedule",
        "send",
        "start",
        "store",
        "submit",
        "sync",
        "trigger",
        "update",
    }
)
_JAVA_BROAD_EXCEPTION_CATCH_PATTERN = re.compile(
    r"catch\s*\(\s*(?:final\s+)?(?:java\.lang\.)?Exception(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*\)"
)
_JAVA_CATCH_CLAUSE_PATTERN = re.compile(
    r"catch\s*\(\s*(?:final\s+)?"
    r"(?P<type>(?:[A-Za-z_][A-Za-z0-9_.]*\s*\|\s*)*[A-Za-z_][A-Za-z0-9_.]*)"
    r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_JAVA_SUPPRESSION_CONTROL_PATTERN = re.compile(r"\b(?:break|continue|return)\b")
_JAVA_ENDPOINT_MAPPING_ANNOTATION_PATTERN = re.compile(
    r"@(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\b"
    r"(?:\s*\([^)]*\))?"
)
_WEB_LAYER_LOCAL_FILE_IO_PATTERN = re.compile(
    r"(?P<access>"
    r"Files\.(?:exists|notExists|readAllBytes|readString|write(?:String|Bytes)?|copy|"
    r"delete(?:IfExists)?|newInputStream|newOutputStream)"
    r"|Paths\.get"
    r"|Path\.of"
    r"|new\s+FileInputStream"
    r"|new\s+FileOutputStream"
    r"|new\s+FileReader"
    r"|new\s+FileWriter"
    r"|new\s+File"
    r")\s*\("
)
_WEB_LAYER_CONCRETE_DEPENDENCY_PATTERN = re.compile(
    r"(?P<access>"
    r"new\s+(?:RestTemplate|ObjectMapper)"
    r"|new\s+[A-Z][A-Za-z0-9_]*(?:Client|Service|Repository|Gateway|Sender|Notifier|Publisher|Store)"
    r"|WebClient\.(?:builder|create)"
    r"|HttpClient\.newHttpClient"
    r")\s*\("
)
_SERVICE_LAYER_OUTBOUND_CLIENT_PATTERN = re.compile(
    r"(?P<access>"
    r"new\s+(?:RestTemplate|ObjectMapper)"
    r"|new\s+[A-Z][A-Za-z0-9_]*(?:Client|Gateway|Sender|Notifier|Publisher)"
    r"|WebClient\.(?:builder|create)"
    r"|HttpClient\.newHttpClient"
    r")\s*\("
)
_SERVICE_LAYER_REST_TEMPLATE_TIMEOUT_PATTERN = re.compile(
    r"(?P<access>new\s+RestTemplate\s*\(\s*\))"
)
_SERVICE_LOCATOR_ACCESS_PATTERN = re.compile(
    r"\b(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\.(?P<member>getBean|getInstance|INSTANCE)\b(?P<call>\s*\()?"
)
_SYSTEM_GETENV_PATTERN = re.compile(r"\bSystem\.getenv\s*\(")
_SECRET_FALLBACK_PATTERN = re.compile(
    r'@Value\(\s*"(?P<expr>\$\{(?P<key>[^:{}]+):(?P<default>[^{}]+)\})"\s*\)'
)
_SQL_KEYWORD_PATTERN = re.compile(
    r"\b("
    r"select|insert|update|delete|with|create|drop|alter|where|from|into|join|values|set|"
    r"and|or|order|limit|offset|group|having|union"
    r")\b",
    re.IGNORECASE,
)
_SQL_ASSIGNMENT_PATTERN = re.compile(
    r"(?:\b(?:final\s+)?(?:String|var)\s+(?P<decl_name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
    r"|(?:\b(?P<assign_name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<assign_op>\+=|=(?!=))\s*)"
)
_SQL_EXECUTION_PATTERN = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\."
    r"(?P<method>queryForMap|queryForList|queryForObject|query|update|batchUpdate|execute|executeBatch|executeQuery|executeUpdate|createNativeQuery|createQuery)\s*\("
)
_EXTERNAL_URL_PATTERN = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s]*)?$")
_EXTERNAL_DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+\.[a-z]{2,}$")
_EXTERNAL_IDENTIFIER_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")
_URL_CONTEXT_MARKERS = frozenset({"url", "uri", "host", "domain", "endpoint"})
_JAVA_LOG_CALL_PATTERN = re.compile(
    r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_.]*)\."
    r"(?P<method>trace|debug|info|warn|error|fatal)\s*\("
)
_JAVA_MEMBER_CALL_PATTERN = re.compile(
    r"\b(?P<owner>[A-Za-z_][A-Za-z0-9_.]*)\.(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_JAVA_FINALLY_PATTERN = re.compile(r"\bfinally\s*\{")
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
_JAVA_CRITICAL_PATH_MARKERS = frozenset(
    {
        "dispatch",
        "dispatcher",
        "drain",
        "job",
        "outbox",
        "processor",
        "publish",
        "publisher",
        "queue",
        "relay",
        "retry",
        "scheduler",
        "sender",
        "sync",
        "worker",
    }
)
_JAVA_CRITICAL_PATH_METHOD_MARKERS = frozenset(
    {
        "dispatch",
        "drain",
        "enqueue",
        "flush",
        "publish",
        "relay",
        "retry",
        "schedule",
        "send",
        "sync",
        "trigger",
    }
)
_JAVA_DURABLE_SURFACE_TOKENS = frozenset(
    {
        "audit",
        "counter",
        "dead",
        "dlq",
        "dlt",
        "error",
        "failure",
        "gauge",
        "histogram",
        "incident",
        "metric",
        "metrics",
        "outcome",
        "result",
        "status",
    }
)
_JAVA_DURABLE_SURFACE_METHOD_MARKERS = frozenset(
    {"capture", "emit", "increment", "persist", "publish", "record", "save", "store", "update"}
)
_JAVA_SCHEDULED_SERVICE_TYPE_SUFFIXES = (
    "Job",
    "Processor",
    "Relay",
    "Scheduler",
    "Service",
    "Worker",
    "Workflow",
)
_JAVA_SCHEDULER_TEST_FOCUS_SUFFIXES = (
    "Scheduling",
    "Scheduler",
    "Scheduled",
    "Cron",
    "Trigger",
)
_JAVA_SCHEDULER_TEST_FOCUS_PATTERN = re.compile(
    r"@Scheduled\b|\bfixed(?:Delay|Rate)\b|\b(?:cron|job|schedule|scheduled|scheduler|scheduling|trigger)\b",
    re.IGNORECASE,
)
_JAVA_TENANT_SCOPE_MARKERS = frozenset({"branch", "tenant"})
_JAVA_BUSINESS_SCOPE_MARKERS = frozenset(
    {
        "account",
        "branch",
        "business",
        "company",
        "dealer",
        "location",
        "shop",
        "tenant",
        "workshop",
    }
)
_JAVA_BUSINESS_KEY_MARKERS = frozenset(
    {
        "code",
        "email",
        "mobile",
        "name",
        "number",
        "phone",
        "plate",
        "reference",
        "registration",
        "vin",
    }
)
_JAVA_TENANT_BOUNDARY_INFRA_MARKERS = frozenset(
    {"decorator", "executor", "runner", "scope", "scoped", "template"}
)
_JAVA_SCHEDULER_ACTION_METHOD_MARKERS = frozenset(
    {
        "dispatch",
        "enqueue",
        "execute",
        "handle",
        "process",
        "publish",
        "refresh",
        "reconcile",
        "relay",
        "retry",
        "run",
        "send",
        "start",
        "sync",
        "trigger",
        "update",
    }
)
_JAVA_PAGE_RETURN_PATTERN = re.compile(r"\bPage\s*<")
_JAVA_PAGEABLE_PARAM_PATTERN = re.compile(r"\bPageable\s+")
_JAVA_ENTITY_GRAPH_PATTERN = re.compile(r"@EntityGraph\b|JOIN\s+FETCH\b")
_JAVA_LAZY_ASSOCIATION_PATTERN = re.compile(r"@(?:OneToMany|ManyToOne|OneToOne|ManyToMany)\b")
_JAVA_DTO_MAPPING_METHOD_PATTERN = re.compile(
    r"\b(?:toDto|fromEntity|toEntity|mapToDto|mapFromEntity)\b"
)
_JAVA_LAZY_COLLECTION_TOUCH_PATTERN = re.compile(
    r"\b\w+\.(?:get\w*\(\)\.)?(?:size|stream|get)\s*\("
)
_JAVA_ADD_TO_COLLECTION_PATTERN = re.compile(r"\b\w+\.(?:get\w*\(\)\.)?add\s*\(\s*(\w+)\s*\)")
_JAVA_REPOSITORY_SAVE_PATTERN = re.compile(r"\b(?:this\.)?(?:\w+)\s*\.\s*save\s*\(\s*(\w+)\s*\)")
_JAVA_REPOSITORY_QUERY_PATTERN = re.compile(
    r"\b(?:this\.)?(?:\w+)\s*\.\s*(?:find|get|count|exists)\w*\s*\("
)
_JAVA_TRANSACTIONAL_EVENT_LISTENER_PATTERN = re.compile(r"@TransactionalEventListener\b")
_JAVA_ASYNC_SELF_INVOCATION_PATTERN = re.compile(r"\bthis\.(\w+)\s*\(")
_JAVA_TRY_PATTERN = re.compile(r"\btry\s*\{")
_JAVA_ENTITY_LAZY_TOUCH_PATTERN = re.compile(r"\b\w+\.(?:get\w*\(\)\.)?(?:size|stream|get)\s*\(")
_JAVA_AFTER_COMMIT_PATTERN = re.compile(r"afterCommit\s*\(")
_JAVA_STATE_TRANSITION_METHOD_PATTERN = re.compile(
    r"\b(?:transition|changeState|approve|reject|cancel|complete|updateStatus)\w*\b"
)
_JAVA_FIND_BY_ID_PATTERN = re.compile(r"\b(?:this\.)?(?:\w+)\s*\.\s*findById\s*\(")
_JAVA_LOCK_MODE_PATTERN = re.compile(r"LockModeType\.PESSIMISTIC_WRITE|ForUpdate")
_JAVA_AUTH_FALLBACK_PATTERN = re.compile(
    r"\b(?:getCurrentUser|getPrincipal)\s*\(\s*\)\s*"
    r"(?:\?|:|\.orElse(?:Get)?)\s*\(\s*(?:\w*\s*,\s*)?"
    r"(?:1|admin|system|root)\b"
)
_JAVA_PUSH_NOTIFICATION_PATTERN = re.compile(r"\b(?:push|fcm)\w*\.\s*(?:send|notify|publish)\s*\(")
_JAVA_IN_APP_NOTIFICATION_PATTERN = re.compile(r"\b(?:inApp|notificationRepository)\b")
_JAVA_RETRY_LOOP_PATTERN = re.compile(r"\b(?:while|for)\s*\([^)]*(?:retry|attempt)\w*[^)]*\)")
_JAVA_STATUS_SETTER_PATTERN = re.compile(r"\bset(?:Status|State|RetryCount|Attempt)\s*\(")
_JAVA_LOB_BYTEA_PATTERN = re.compile(
    r"@Lob(?:\s*\([^)]*\))?\s+(?:private|protected|public)?\s*"
    r"(?:static\s+)?(?:final\s+)?byte\[\]"
)
_JAVA_FLYWAY_VERSION_PATTERN = re.compile(r"^[VR](\d+)__.+")
_JAVA_POST_MAPPING_PATTERN = re.compile(r"@PostMapping\b")
_JAVA_MULTIPART_FILE_PATTERN = re.compile(r"\bMultipartFile\b")
_JAVA_FILE_VALIDATION_PATTERN = re.compile(
    r"\b(?:maxSize|maxFileSize|contentType|MediaType|@Size|@MaxFileSize)\b"
)
_JAVA_ENHANCED_FOR_LOOP_PATTERN = re.compile(
    r"\bfor\s*\(\s*(?:final\s+)?(?P<type>[^:;()]+?)\s+"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<iterable>(?:[^()]|\([^)]*\))+)\)\s*\{"
)
_JAVA_FOREACH_ITERATION_PATTERN = re.compile(
    r"\b(?P<iterable>[A-Za-z_][A-Za-z0-9_.]*)\s*\.\s*forEach\s*\("
)
_JAVA_LAZY_PROVIDER_DECLARATION_PATTERN = re.compile(
    r"\b(?P<provider_type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
    r"(?:ObjectFactory|ObjectProvider|Provider))\s*<\s*"
    r"(?P<target_type>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*>\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_JAVA_LAZY_SERVICE_TARGET_SUFFIXES = (
    "Dispatcher",
    "Handler",
    "Listener",
    "Orchestrator",
    "Processor",
    "Service",
    "Workflow",
)
_N_PLUS_ONE_WITHOUT_ENTITY_GRAPH_RULE_ID = "java.performance.no-n-plus-one-without-entity-graph"
_LAZY_COLLECTION_TOUCH_DTO_RULE_ID = "java.correctness.no-lazy-collection-touch-in-dto-mapping"
_CASCADE_REDUNDANT_SAVE_RULE_ID = "java.reliability.no-cascade-redundant-save"
_REQUERY_UNCOMMITTED_STATE_RULE_ID = (
    "java.correctness.no-requery-uncommitted-state-across-transaction-boundary"
)
_ROLLBACK_ONLY_POISONING_RULE_ID = (
    "java.reliability.no-rollback-only-poisoning-in-concurrent-workload"
)
_ASYNC_SELF_INVOCATION_RULE_ID = "java.correctness.no-async-self-invocation"
_PAYLOAD_BUILD_AFTER_ASYNC_RULE_ID = "java.reliability.no-payload-build-after-async-boundary"
_ASYNC_READ_BEFORE_COMMIT_RULE_ID = (
    "java.correctness.no-async-read-before-owning-transaction-commit"
)
_STATE_TRANSITION_WITHOUT_LOCK_RULE_ID = (
    "java.reliability.no-state-transition-without-pessimistic-lock"
)
_AUTH_FALLBACK_PRIVILEGED_RULE_ID = "java.security.no-auth-fallback-to-privileged-user"
_RETRY_WITHOUT_REEXECUTION_RULE_ID = "java.correctness.no-retry-without-re-execution"
_DUPLICATE_FLYWAY_VERSION_RULE_ID = "java.reliability.no-duplicate-flyway-migration-version"
_FILE_UPLOAD_WITHOUT_VALIDATION_RULE_ID = "java.correctness.no-file-upload-without-validation"
_JPQL_NULL_OR_LOWER_OPTIONAL_FILTER_RULE_ID = (
    "java.reliability.no-jpql-null-or-lower-on-optional-filter"
)
_READONLY_TRANSACTIONAL_COMPOSITE_READ_SERVICE_RULE_ID = (
    "java.reliability.no-readonly-transactional-on-composite-read-service"
)
_TRANSACTIONAL_EVENT_LISTENER_REQUIRES_PHASE_RULE_ID = (
    "java.reliability.transactional-event-listener-requires-phase"
)
_REQUIRES_NEW_SELF_INVOCATION_RULE_ID = "java.reliability.no-requires-new-self-invocation"
_JAVA_REPOSITORY_WRITE_CALL_PATTERN = re.compile(
    r"\b(?:this\.)?(?:\w+)\s*\.\s*"
    r"(?:save|delete(?:By\w+|All)?|update|merge|remove|persist)\s*\("
)
_TRANSACTIONAL_EVENT_LISTENER_WITH_ARGS_PATTERN = re.compile(
    r"@TransactionalEventListener\b(?:\s*\((?P<args>[^)]*)\))?"
)
_JAVA_QUERY_ANNOTATION_PREFIX = re.compile(
    r"@Query\s*\(\s*(?:value\s*=\s*)?",
    re.DOTALL,
)
_JAVA_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_JAVA_STRING_CONSTANT_PREFIX = re.compile(
    r"(?:(?:public|protected|private|static|final)\s+)*String\s+(\w+)\s*=\s*"
)
_JAVA_QUERY_EXPRESSION_KEYWORDS = frozenset(
    {"true", "false", "null", "value", "countQuery", "nativeQuery", "name"}
)
_JAVA_JPQL_NULL_OR_LOWER_PATTERN = re.compile(
    r":\w+\s+IS\s+NULL\s+OR[\s\S]*?LOWER\s*\(|"
    r"LOWER\s*\([^)]+\)\s*=\s*LOWER\s*\(\s*:\w+\s*\)[\s\S]*?:\w+\s+IS\s+NULL\s+OR",
    re.IGNORECASE,
)
_JAVA_DISPATCH_COALESCING_TRANSACTIONAL_PATTERN = re.compile(
    r"\bdispatchCoalescingTransactional\s*\("
)
_JAVA_EVENT_LISTENER_CONTEXT_PATTERN = re.compile(
    r"@TransactionalEventListener\b|@EventListener\b|\bclass\s+\w*Listener\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _JavaDynamicSqlSource:
    line_range: range
    line_number: int
    construction_kind: str | None


@dataclass(frozen=True)
class _JavaExecutionCall:
    method: str
    argument_text: str
    line_range: range
    line_number: int


@dataclass(frozen=True)
class _JavaServiceLocatorMatch:
    line_range: range
    line_number: int
    access_pattern: str
    resolution_kind: str


@dataclass(frozen=True)
class _JavaTenantContextMutationMatch:
    line_range: range
    line_number: int
    access_pattern: str
    mutation_kind: str


@dataclass(frozen=True)
class _JavaDetachedAsyncMatch:
    line_range: range
    line_number: int
    access_pattern: str
    launch_kind: str


@dataclass(frozen=True)
class _JavaAsyncContextGapMatch:
    line_range: range
    line_number: int
    access_pattern: str
    propagation_kind: str


@dataclass(frozen=True)
class _JavaBackgroundObservabilityMatch:
    line_range: range
    line_number: int
    access_pattern: str
    observability_kind: str


@dataclass(frozen=True)
class _JavaResponseLifecycleMatch:
    line_range: range
    line_number: int
    access_pattern: str
    lifecycle_kind: str


@dataclass(frozen=True)
class _JavaExternalLiteralMatch:
    line_range: range
    line_number: int
    context_name: str | None
    literal_kind: str
    literal_value: str


@dataclass(frozen=True)
class _JavaAuthFilterFailOpenMatch:
    line_range: range
    line_number: int
    catch_type: str
    continuation_call: str
    filter_method: str


@dataclass(frozen=True)
class _JavaLogCall:
    method: str
    arguments: tuple[str, ...]
    line_range: range
    line_number: int


@dataclass(frozen=True)
class _JavaSensitiveLoggingMatch:
    log_method: str
    identifier_name: str
    sensitivity_kind: str
    line_range: range
    line_number: int


@dataclass(frozen=True)
class _JavaTimeoutShapingMatch:
    line_range: range
    line_number: int
    access_pattern: str
    timeout_kind: str


@dataclass(frozen=True)
class _JavaControllerRepositoryAccessMatch:
    line_range: range
    line_number: int
    access_pattern: str
    repository_type: str
    access_kind: str


@dataclass(frozen=True)
class _JavaRepositoryContract:
    simple_name: str
    fqcn: str
    tenant_lookup_methods: tuple[str, ...]


@dataclass(frozen=True)
class _JavaRepositoryContractIndex:
    by_fqcn: dict[str, _JavaRepositoryContract]
    by_simple_name: dict[str, tuple[_JavaRepositoryContract, ...]]


@dataclass(frozen=True)
class _JavaEntityIndex:
    by_fqcn: dict[str, str]
    by_simple_name: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class _JavaTenantScopeLookupMatch:
    line_range: range
    line_number: int
    access_pattern: str
    repository_type: str
    tenant_lookup_methods: tuple[str, ...]
    lookup_kind: str


@dataclass(frozen=True)
class _JavaTransactionalExternalIOMatch:
    line_range: range
    line_number: int
    access_pattern: str
    collaborator_type: str
    transactional_method: str
    io_kind: str


@dataclass(frozen=True)
class _JavaScheduledConcurrentMapRemovalMatch:
    line_range: range
    line_number: int
    access_pattern: str
    map_type: str
    scheduled_method: str


@dataclass(frozen=True)
class _JavaStaticLockPoolMatch:
    line_range: range
    declaration_line_range: range
    line_number: int
    access_pattern: str
    map_name: str
    map_type: str
    lock_type: str
    growth_method: str


@dataclass(frozen=True)
class _JavaBatchSaveAllMatch:
    line_range: range
    line_number: int
    access_pattern: str
    repository_type: str
    collection_name: str
    batch_method: str
    guard_kind: str


@dataclass(frozen=True)
class _JavaUnboundedFindAllMatch:
    line_range: range
    line_number: int
    access_pattern: str
    repository_type: str
    service_method: str
    repository_method: str


@dataclass(frozen=True)
class _JavaEventListenerTransactionBoundaryMatch:
    line_range: range
    line_number: int
    access_pattern: str
    listener_method: str
    write_kind: str


@dataclass(frozen=True)
class _JavaActiveArtifactMatch:
    line_range: range
    line_number: int
    access_pattern: str
    service_method: str
    artifact_guard: str


@dataclass(frozen=True)
class _JavaBusinessUniquenessMatch:
    line_range: range
    line_number: int
    repository_method: str
    scope_kind: str


@dataclass(frozen=True)
class _JavaFlywayMigrationMatch:
    line_range: range
    line_number: int
    migration_kind: str
    operation_kind: str


@dataclass(frozen=True)
class _JavaEntityBoundaryMatch:
    line_range: range
    line_number: int
    boundary_kind: str
    boundary_method: str
    entity_type: str


@dataclass(frozen=True)
class _JavaScheduledCrossTenantIterationMatch:
    line_range: range
    line_number: int
    access_pattern: str
    scheduled_method: str
    tenant_source: str
    iteration_kind: str


@dataclass(frozen=True)
class _JavaCriticalPathExceptionSwallowingMatch:
    line_range: range
    line_number: int
    catch_type: str
    critical_method: str
    suppression_kind: str


@dataclass(frozen=True)
class _JavaLazyServiceProviderMatch:
    line_range: range
    line_number: int
    access_pattern: str
    provider_type: str
    target_type: str
    provider_kind: str


@dataclass(frozen=True)
class _JavaMethodContext:
    name: str
    return_type: str
    response_name: str
    body: str
    line_range: range
    body_start_line: int


@dataclass(frozen=True)
class _JavaFilterMethodContext:
    name: str
    filter_chain_name: str
    body: str
    line_range: range
    body_start_line: int


@dataclass(frozen=True)
class _JavaControlLine:
    text: str
    line_number: int
    start_depth: int
    end_depth: int


class JavaAdapter(RulesAdapter):
    adapter_key = "java"

    def __init__(self, registry: RulesRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> tuple[NormalizedFinding, ...]:
        requested_rule_ids = tuple(dict.fromkeys(rule_ids))
        if not requested_rule_ids:
            return ()

        controller_test_index = (
            _discover_java_controller_test_index(context.repo_root)
            if _CONTROLLER_WITHOUT_TEST_CLASS_RULE_ID in requested_rule_ids
            else None
        )
        scheduler_test_index = (
            _discover_java_scheduler_test_index(context.repo_root)
            if _SCHEDULED_SERVICE_WITHOUT_SCHEDULER_TEST_RULE_ID in requested_rule_ids
            else None
        )
        entity_index = (
            _discover_java_entity_index(context.repo_root)
            if _ENTITY_ASYNC_TRANSACTION_BOUNDARY_RULE_ID in requested_rule_ids
            else None
        )
        jpql_constants = (
            _discover_java_string_constants(context.repo_root)
            if _JPQL_NULL_OR_LOWER_OPTIONAL_FILTER_RULE_ID in requested_rule_ids
            else None
        )

        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_java_files(context, requested_rule_ids=requested_rule_ids):
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
            if _WEB_LAYER_VALUE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_VALUE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_value_injection_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _WEB_LAYER_FILE_IO_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_FILE_IO_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_local_file_io_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _WEB_LAYER_CONCRETE_DEPENDENCY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_CONCRETE_DEPENDENCY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_concrete_dependency_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CONTROLLER_DIRECT_REPOSITORY_ACCESS_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CONTROLLER_DIRECT_REPOSITORY_ACCESS_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_controller_direct_repository_access_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CONTROLLER_WITHOUT_TEST_CLASS_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CONTROLLER_WITHOUT_TEST_CLASS_RULE_ID)
                if rule is not None and controller_test_index is not None:
                    findings.extend(
                        _find_controller_without_test_class_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            controller_test_index=controller_test_index,
                        )
                    )
            if _SCHEDULED_SERVICE_WITHOUT_SCHEDULER_TEST_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SCHEDULED_SERVICE_WITHOUT_SCHEDULER_TEST_RULE_ID)
                if rule is not None and scheduler_test_index is not None:
                    findings.extend(
                        _find_scheduled_service_without_scheduler_test_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            scheduler_test_index=scheduler_test_index,
                        )
                    )
            if _WEB_LAYER_SERVICE_LOCATOR_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_SERVICE_LOCATOR_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_service_locator_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _WEB_LAYER_ASYNC_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_ASYNC_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_detached_async_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _WEB_LAYER_ASYNC_OBSERVABILITY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_ASYNC_OBSERVABILITY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_async_observability_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _WEB_LAYER_RESPONSE_LIFECYCLE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_WEB_LAYER_RESPONSE_LIFECYCLE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_web_layer_response_lifecycle_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _AUTH_FILTER_FAIL_OPEN_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_AUTH_FILTER_FAIL_OPEN_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_auth_filter_fail_open_findings(
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
            if _SERVICE_LAYER_TIMEOUT_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_TIMEOUT_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_outbound_timeout_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_TRANSACTIONAL_EXTERNAL_IO_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_TRANSACTIONAL_EXTERNAL_IO_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_transactional_external_io_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _EVENT_LISTENER_TRANSACTION_PHASE_BOUNDARY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_EVENT_LISTENER_TRANSACTION_PHASE_BOUNDARY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_event_listener_transaction_phase_boundary_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _NONADDITIVE_FLYWAY_MIGRATION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_NONADDITIVE_FLYWAY_MIGRATION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_nonadditive_flyway_migration_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if (
                _ENTITY_ASYNC_TRANSACTION_BOUNDARY_RULE_ID in requested_rule_ids
                and entity_index is not None
            ):
                rule = self._registry.get(_ENTITY_ASYNC_TRANSACTION_BOUNDARY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_entity_crossing_async_transaction_boundary_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            entity_index=entity_index,
                        )
                    )
            if _SERVICE_LAYER_ASYNC_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_ASYNC_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_detached_async_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_ASYNC_OBSERVABILITY_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_ASYNC_OBSERVABILITY_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_async_observability_findings(
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
            if _SERVICE_LAYER_OBJECTPROVIDER_CIRCULAR_SELF_REFERENCE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(
                    _SERVICE_LAYER_OBJECTPROVIDER_CIRCULAR_SELF_REFERENCE_RULE_ID
                )
                if rule is not None:
                    findings.extend(
                        _find_service_layer_objectprovider_circular_self_reference_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CONCURRENTMAP_SCHEDULED_UNSAFE_REMOVAL_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CONCURRENTMAP_SCHEDULED_UNSAFE_REMOVAL_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_concurrentmap_scheduled_unsafe_removal_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _STATIC_LOCK_POOL_WITHOUT_EVICTION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_STATIC_LOCK_POOL_WITHOUT_EVICTION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_static_lock_pool_without_eviction_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _BATCH_SAVEALL_WITHOUT_PARTIAL_FAILURE_GUARD_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_BATCH_SAVEALL_WITHOUT_PARTIAL_FAILURE_GUARD_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_batch_saveall_without_partial_failure_guard_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _UNBOUNDED_FINDALL_WITHOUT_PAGINATION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_UNBOUNDED_FINDALL_WITHOUT_PAGINATION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_unbounded_findall_without_pagination_findings(
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
            if _SERVICE_LAYER_CLASS_SIZE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_CLASS_SIZE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_oversized_class_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _SERVICE_LAYER_METHOD_SIZE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_SERVICE_LAYER_METHOD_SIZE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_service_layer_oversized_method_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CYCLOMATIC_HOTSPOT_METHOD_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CYCLOMATIC_HOTSPOT_METHOD_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_cyclomatic_hotspot_method_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CRITICAL_PATH_EXCEPTION_SWALLOWING_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CRITICAL_PATH_EXCEPTION_SWALLOWING_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_critical_path_exception_swallowing_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _N_PLUS_ONE_WITHOUT_ENTITY_GRAPH_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_N_PLUS_ONE_WITHOUT_ENTITY_GRAPH_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_n_plus_one_without_entity_graph_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _LAZY_COLLECTION_TOUCH_DTO_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_LAZY_COLLECTION_TOUCH_DTO_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_lazy_collection_touch_in_dto_mapping_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _CASCADE_REDUNDANT_SAVE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_CASCADE_REDUNDANT_SAVE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_cascade_redundant_save_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _REQUERY_UNCOMMITTED_STATE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_REQUERY_UNCOMMITTED_STATE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_requery_uncommitted_state_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _ROLLBACK_ONLY_POISONING_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_ROLLBACK_ONLY_POISONING_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_rollback_only_poisoning_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _ASYNC_SELF_INVOCATION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_ASYNC_SELF_INVOCATION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_async_self_invocation_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _PAYLOAD_BUILD_AFTER_ASYNC_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_PAYLOAD_BUILD_AFTER_ASYNC_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_payload_build_after_async_boundary_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _ASYNC_READ_BEFORE_COMMIT_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_ASYNC_READ_BEFORE_COMMIT_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_async_read_before_commit_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _STATE_TRANSITION_WITHOUT_LOCK_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_STATE_TRANSITION_WITHOUT_LOCK_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_state_transition_without_pessimistic_lock_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _AUTH_FALLBACK_PRIVILEGED_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_AUTH_FALLBACK_PRIVILEGED_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_auth_fallback_to_privileged_user_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _RETRY_WITHOUT_REEXECUTION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_RETRY_WITHOUT_REEXECUTION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_retry_without_reexecution_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _DUPLICATE_FLYWAY_VERSION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_DUPLICATE_FLYWAY_VERSION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_duplicate_flyway_migration_version_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            context=context,
                        )
                    )
            if _FILE_UPLOAD_WITHOUT_VALIDATION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_FILE_UPLOAD_WITHOUT_VALIDATION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_file_upload_without_validation_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _JPQL_NULL_OR_LOWER_OPTIONAL_FILTER_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_JPQL_NULL_OR_LOWER_OPTIONAL_FILTER_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_jpql_null_or_lower_on_optional_filter_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                            extra_constants=jpql_constants,
                        )
                    )
            if _READONLY_TRANSACTIONAL_COMPOSITE_READ_SERVICE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_READONLY_TRANSACTIONAL_COMPOSITE_READ_SERVICE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_readonly_transactional_on_composite_read_service_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _TRANSACTIONAL_EVENT_LISTENER_REQUIRES_PHASE_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_TRANSACTIONAL_EVENT_LISTENER_REQUIRES_PHASE_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_transactional_event_listener_requires_phase_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
            if _REQUIRES_NEW_SELF_INVOCATION_RULE_ID in requested_rule_ids:
                rule = self._registry.get(_REQUIRES_NEW_SELF_INVOCATION_RULE_ID)
                if rule is not None:
                    findings.extend(
                        _find_requires_new_self_invocation_findings(
                            source=source,
                            relative_path=relative_path,
                            changed_lines=changed_lines,
                            rule=rule,
                            adapter_id=self.adapter_key,
                        )
                    )
        return tuple(findings)


def _candidate_java_files(
    context: AdapterContext, *, requested_rule_ids: Sequence[str]
) -> tuple[str, ...]:
    if context.mode is ExecutionMode.DIFF:
        candidates: list[str] = []
        include_flyway = _NONADDITIVE_FLYWAY_MIGRATION_RULE_ID in requested_rule_ids
        for path in context.target_files:
            if (
                path.endswith(".java") and not _should_skip_path(path)
            ) or (
                include_flyway and _is_flyway_migration_path(path)
            ):
                candidates.append(path)
        return tuple(candidates)

    candidates: list[str] = []
    for file_path in sorted(context.repo_root.rglob("*.java")):
        try:
            relative_path = file_path.relative_to(context.repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path):
            continue
        candidates.append(relative_path)
    if _NONADDITIVE_FLYWAY_MIGRATION_RULE_ID in requested_rule_ids:
        for file_path in sorted(context.repo_root.rglob("*.sql")):
            try:
                relative_path = file_path.relative_to(context.repo_root).as_posix()
            except ValueError:
                continue
            if _should_skip_path(relative_path) or not _is_flyway_migration_path(relative_path):
                continue
            candidates.append(relative_path)
    return tuple(candidates)


def _find_service_layer_oversized_class_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> tuple[NormalizedFinding, ...]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return ()
    line_count = len(source.splitlines())
    if line_count <= _JAVA_OVERSIZED_CLASS_LINE_THRESHOLD:
        return ()
    if changed_lines is not None and not changed_lines:
        return ()

    type_name, line_number = _java_primary_type_name(source, relative_path)
    return (
        NormalizedFinding.from_rule(
            rule,
            message=(
                f"Java service/workflow type `{type_name}` spans {line_count} lines; split "
                "responsibilities before the class becomes harder to review and evolve."
            ),
            location=FindingLocation(path=relative_path, line=line_number),
            adapter_id=adapter_id,
            language=RepoLanguage.JAVA,
            suggestion=(
                "Extract cohesive collaborators or feature slices so each service/workflow class "
                "stays within a reviewable size."
            ),
            metadata={
                "symbol": type_name,
                "line_count": str(line_count),
                "line_threshold": str(_JAVA_OVERSIZED_CLASS_LINE_THRESHOLD),
            },
        ),
    )


def _find_service_layer_oversized_method_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> tuple[NormalizedFinding, ...]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return ()

    findings: list[NormalizedFinding] = []
    type_name, _ = _java_primary_type_name(source, relative_path)
    for method_name, line_range in _iter_java_method_line_ranges(source):
        line_count = line_range.stop - line_range.start
        if line_count <= _JAVA_OVERSIZED_METHOD_LINE_THRESHOLD:
            continue
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        symbol_name = f"{type_name}.{method_name}"
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Java service/workflow method `{symbol_name}` spans {line_count} lines; "
                    "split branching and orchestration before it turns into a god-method."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Extract validation, persistence, and integration steps into smaller helpers "
                    "or collaborators so each method stays focused."
                ),
                metadata={
                    "symbol": symbol_name,
                    "line_count": str(line_count),
                    "line_threshold": str(_JAVA_OVERSIZED_METHOD_LINE_THRESHOLD),
                },
            )
        )
    return tuple(findings)


def _find_cyclomatic_hotspot_method_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> tuple[NormalizedFinding, ...]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return ()

    findings: list[NormalizedFinding] = []
    type_name, _ = _java_primary_type_name(source, relative_path)
    for context in _iter_java_method_contexts(source):
        line_count = context.line_range.stop - context.line_range.start
        if line_count < _JAVA_CYCLOMATIC_HOTSPOT_LINE_THRESHOLD:
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in context.line_range
        ):
            continue
        cyclomatic_score, max_nesting = _java_method_cyclomatic_metrics(context)
        if cyclomatic_score < _JAVA_CYCLOMATIC_HOTSPOT_SCORE_THRESHOLD:
            continue
        if (
            cyclomatic_score < _JAVA_CYCLOMATIC_HOTSPOT_HIGH_SCORE_THRESHOLD
            and max_nesting < _JAVA_CYCLOMATIC_HOTSPOT_NESTING_THRESHOLD
        ):
            continue
        symbol_name = f"{type_name}.{context.name}"
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    f"Java service/workflow method `{symbol_name}` has cyclomatic score "
                    f"{cyclomatic_score} with max nesting {max_nesting}."
                ),
                location=FindingLocation(path=relative_path, line=context.line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Split decision-heavy orchestration into smaller collaborators or helper "
                    "methods so each branch is easier to reason about and test."
                ),
                metadata={
                    "symbol": symbol_name,
                    "cyclomatic_score": str(cyclomatic_score),
                    "line_count": str(line_count),
                    "max_nesting": str(max_nesting),
                },
            )
        )
    return tuple(findings)


def _should_skip_path(relative_path: str) -> bool:
    path = Path(relative_path)
    return any(part in _SKIP_DIRECTORIES for part in path.parts)


def _is_web_layer_path(relative_path: str, source: str) -> bool:
    path = Path(relative_path)
    if any(part.lower() in _WEB_LAYER_PATH_MARKERS for part in path.parts):
        return True
    return bool(_WEB_LAYER_HINT_PATTERN.search(source))


def _is_java_controller_path(relative_path: str, source: str) -> bool:
    path = Path(relative_path)
    if any(part.lower() in _JAVA_CONTROLLER_PATH_MARKERS for part in path.parts):
        return True
    return bool(_JAVA_CONTROLLER_HINT_PATTERN.search(source))


def _is_java_auth_filter_path(relative_path: str, source: str) -> bool:
    if _is_test_java_path(relative_path) or not _is_web_layer_path(relative_path, source):
        return False
    if "OncePerRequestFilter" not in source:
        return False
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    return "security" in markers and bool(markers & _JAVA_AUTH_FILTER_STEM_MARKERS)


def _is_java_service_or_workflow_path(relative_path: str, source: str) -> bool:
    if _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return False
    if _CONFIGURATION_HINT_PATTERN.search(source):
        return False
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    if any(marker in _SERVICE_LAYER_PATH_MARKERS for marker in markers):
        return True
    return bool(_SERVICE_LAYER_HINT_PATTERN.search(source))


def _is_java_repository_path(relative_path: str) -> bool:
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    return "repository" in markers or path.stem.endswith("Repository")


def _is_java_batch_or_scheduler_path(relative_path: str, source: str) -> bool:
    if _is_test_java_path(relative_path):
        return False
    if _is_java_service_or_workflow_path(relative_path, source):
        return True
    path = Path(relative_path)
    markers = {part.lower() for part in path.parts}
    markers.update(_shared_split_identifier_tokens(path.stem))
    if any(marker in _JAVA_BATCH_PATH_MARKERS for marker in markers):
        return True
    return bool(_SCHEDULED_ANNOTATION_PATTERN.search(source))


def _java_path_and_type_tokens(relative_path: str, source: str) -> set[str]:
    tokens = {part.lower() for part in Path(relative_path).parts}
    tokens.update(_shared_split_identifier_tokens(Path(relative_path).stem))
    type_name, _ = _java_primary_type_name(source, relative_path)
    tokens.update(_shared_split_identifier_tokens(type_name))
    return tokens


def _is_java_bootstrap_or_initializer_context(
    relative_path: str, source: str, *, method_name: str | None = None
) -> bool:
    tokens = _java_path_and_type_tokens(relative_path, source)
    if method_name is not None:
        tokens.update(_shared_split_identifier_tokens(method_name))
    if tokens & _JAVA_BOOTSTRAP_CONTEXT_MARKERS:
        return True
    return _JAVA_BOOTSTRAP_HINT_PATTERN.search(source) is not None


def _looks_like_java_critical_path_context(
    relative_path: str,
    source: str,
    *,
    method_name: str,
    scheduled_methods: set[str],
) -> bool:
    if method_name in scheduled_methods:
        return True
    if _java_path_and_type_tokens(relative_path, source) & _JAVA_CRITICAL_PATH_MARKERS:
        return True
    method_tokens = set(_shared_split_identifier_tokens(method_name))
    return bool(method_tokens & _JAVA_CRITICAL_PATH_METHOD_MARKERS)


def _is_java_meaningful_scheduled_service(
    relative_path: str, source: str, *, type_name: str
) -> bool:
    if _is_test_java_path(relative_path) or _CONFIGURATION_HINT_PATTERN.search(source):
        return False
    if (
        _WEB_LAYER_HINT_PATTERN.search(source)
        or _JAVA_HANDLER_INTERCEPTOR_HINT_PATTERN.search(source)
        or _JAVA_REQUEST_BOUNDARY_HINT_PATTERN.search(source)
    ):
        return False
    if not _is_java_batch_or_scheduler_path(relative_path, source):
        return False
    if type_name.endswith(_JAVA_SCHEDULED_SERVICE_TYPE_SUFFIXES):
        return True
    collaborator_fields = _java_collaborator_field_types(_strip_java_comments(source))
    for field_name, field_type in collaborator_fields.items():
        if _looks_like_java_log_receiver(field_name) or _looks_like_java_log_receiver(field_type):
            continue
        return True
    return False


def _is_java_transactional_external_io_path(relative_path: str, source: str) -> bool:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return False
    stem_tokens = set(_shared_split_identifier_tokens(Path(relative_path).stem))
    return not bool(stem_tokens & _JAVA_TRANSACTIONAL_EXTERNAL_IO_OWNER_MARKERS)


def _is_java_explicit_tenant_boundary(relative_path: str, source: str) -> bool:
    tokens = _java_path_and_type_tokens(relative_path, source)
    if tokens & {"filter", "filters", "interceptor", "interceptors"}:
        return True
    if _JAVA_HANDLER_INTERCEPTOR_HINT_PATTERN.search(source):
        return True
    return bool(
        tokens & _JAVA_TENANT_SCOPE_MARKERS and tokens & _JAVA_TENANT_BOUNDARY_INFRA_MARKERS
    )


def _is_java_factory_or_bootstrap_context(relative_path: str, source: str) -> bool:
    if _is_java_bootstrap_or_initializer_context(relative_path, source):
        return True
    return bool(_java_path_and_type_tokens(relative_path, source) & _JAVA_FACTORY_CONTEXT_MARKERS)


def _is_test_java_path(relative_path: str) -> bool:
    return any(part.lower() in {"test", "tests"} for part in Path(relative_path).parts)


def _is_java_test_or_integration_path(relative_path: str) -> bool:
    return any(
        part.lower().replace("-", "").replace("_", "")
        in {"test", "tests", "integrationtest", "integrationtests"}
        for part in Path(relative_path).parts
    )


def _is_flyway_migration_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    path = Path(normalized)
    if path.suffix not in {".java", ".sql"}:
        return False
    if not re.match(r"^[VR]\d*__.+", path.name):
        return False
    return (
        normalized.startswith("migrations/")
        or "/db/migration/" in normalized
        or normalized.startswith("db/migration/")
    )


def _normalize_java_construction_pattern(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value.strip())
    return normalized.removesuffix("(").strip()


def _java_rest_template_timeout_variable_name(lines: Sequence[str], line_number: int) -> str | None:
    if line_number < 1 or line_number > len(lines):
        return None
    line_text = lines[line_number - 1]
    match = re.search(
        r"\b(?:this\.)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+RestTemplate\s*\(\s*\)",
        line_text,
    )
    if match is None:
        return None
    return match.group("name")


def _java_rest_template_has_request_factory_setup(
    lines: Sequence[str], *, variable_name: str, start_line: int
) -> bool:
    request_factory_pattern = re.compile(
        rf"\b(?:this\.)?{re.escape(variable_name)}\s*\.\s*setRequestFactory\s*\("
    )
    lookahead_start = max(0, start_line - 1)
    lookahead_end = min(len(lines), start_line + 20)
    return any(
        request_factory_pattern.search(line) for line in lines[lookahead_start:lookahead_end]
    )


def _iter_java_service_locator_matches(source: str) -> tuple[_JavaServiceLocatorMatch, ...]:
    scannable_source = _strip_java_comments(source)
    matches: list[_JavaServiceLocatorMatch] = []
    for match in _SERVICE_LOCATOR_ACCESS_PATTERN.finditer(scannable_source):
        access = _java_service_locator_access_pattern(match)
        if access is None:
            continue
        access_pattern, resolution_kind = access
        line_range = _match_line_range(scannable_source, match.start("owner"), match.end("member"))
        matches.append(
            _JavaServiceLocatorMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                resolution_kind=resolution_kind,
            )
        )
    return tuple(matches)


def _java_tenant_context_mutation_kind(member: str) -> str:
    member_tokens = set(_shared_split_identifier_tokens(member))
    if "clear" in member_tokens:
        return "clear"
    if "branch" in member_tokens:
        return "set-current-branch"
    return "set-current-tenant"


def _iter_java_tenant_context_mutation_matches(
    source: str,
) -> tuple[_JavaTenantContextMutationMatch, ...]:
    scannable_source = _strip_java_comments(source)
    matches: list[_JavaTenantContextMutationMatch] = []
    for match in _JAVA_TENANT_CONTEXT_DIRECT_MUTATION_PATTERN.finditer(scannable_source):
        member = match.group("member")
        line_range = _match_line_range(scannable_source, match.start(), match.end("member"))
        matches.append(
            _JavaTenantContextMutationMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=f"TenantContext.{member}",
                mutation_kind=_java_tenant_context_mutation_kind(member),
            )
        )
    return tuple(matches)


def _java_has_balanced_tenant_context_finally_boundary(body_text: str) -> bool:
    return bool(
        _JAVA_TENANT_CONTEXT_BIND_PATTERN.search(body_text)
        and _JAVA_TENANT_CONTEXT_CLEAR_PATTERN.search(body_text)
        and _JAVA_FINALLY_PATTERN.search(body_text)
    )


def _iter_java_balanced_tenant_boundary_ranges(source: str) -> tuple[range, ...]:
    scannable_source = _strip_java_comments(source)
    boundary_ranges: list[range] = []
    for annotation_pattern in (
        _ASYNC_ANNOTATION_PATTERN,
        _EVENT_LISTENER_ANNOTATION_PATTERN,
    ):
        for annotation_match in annotation_pattern.finditer(scannable_source):
            context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
            if context_info is None:
                continue
            method_context, _ = context_info
            if _java_has_balanced_tenant_context_finally_boundary(method_context.body):
                boundary_ranges.append(method_context.line_range)
    return tuple(boundary_ranges)


def _iter_java_service_layer_timeout_matches(source: str) -> tuple[_JavaTimeoutShapingMatch, ...]:
    scannable_source = _strip_java_comments(source)
    lines = scannable_source.splitlines()
    matches: list[_JavaTimeoutShapingMatch] = []
    for match in _SERVICE_LAYER_REST_TEMPLATE_TIMEOUT_PATTERN.finditer(scannable_source):
        line_range = _match_line_range(scannable_source, match.start("access"), match.end("access"))
        variable_name = _java_rest_template_timeout_variable_name(lines, line_range.start)
        if variable_name is not None and _java_rest_template_has_request_factory_setup(
            lines,
            variable_name=variable_name,
            start_line=line_range.start,
        ):
            continue
        matches.append(
            _JavaTimeoutShapingMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern="new RestTemplate",
                timeout_kind="missing-timeout-shaping",
            )
        )
    return tuple(matches)


def _iter_java_service_layer_tenant_scope_matches(
    source: str,
    *,
    repository_contract_index: _JavaRepositoryContractIndex,
) -> tuple[_JavaTenantScopeLookupMatch, ...]:
    scannable_source = _strip_java_comments(source)
    repository_fields = _java_repository_field_contracts(
        scannable_source, repository_contract_index=repository_contract_index
    )
    if not repository_fields:
        return ()

    matches: list[_JavaTenantScopeLookupMatch] = []
    for match in _JAVA_BARE_TENANT_LOOKUP_PATTERN.finditer(scannable_source):
        owner = match.group("owner")
        contract = repository_fields.get(owner)
        if contract is None:
            continue
        line_range = _match_line_range(scannable_source, match.start("owner"), match.end("method"))
        bare_method = match.group("method")
        matches.append(
            _JavaTenantScopeLookupMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=f"{owner}.{bare_method}",
                repository_type=contract.simple_name,
                tenant_lookup_methods=contract.tenant_lookup_methods,
                lookup_kind=bare_method,
            )
        )
    return tuple(matches)


def _iter_java_unbounded_findall_matches(
    source: str, *, relative_path: str
) -> tuple[_JavaUnboundedFindAllMatch, ...]:
    scannable_source = _strip_java_comments(source)
    repository_fields = _java_repository_field_types(scannable_source)
    if not repository_fields or _is_java_bootstrap_or_initializer_context(
        relative_path, scannable_source
    ):
        return ()

    matches: list[_JavaUnboundedFindAllMatch] = []
    for context in _iter_java_method_contexts(scannable_source):
        if _is_java_bootstrap_or_initializer_context(
            relative_path, scannable_source, method_name=context.name
        ):
            continue
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_REPOSITORY_FINDALL_PATTERN.finditer(scannable_body):
            owner_name = match.group("owner")
            repository_type = repository_fields.get(owner_name)
            if repository_type is None:
                continue
            repository_method = match.group("method")
            if repository_method != "findAll" and not (
                _java_repository_has_paginated_findall_overload(
                    scannable_source,
                    repository_type=repository_type,
                    method_name=repository_method,
                )
            ):
                continue
            relative_range = _match_line_range(
                scannable_body, match.start("owner"), match.end("method")
            )
            absolute_start = context.body_start_line + relative_range.start - 1
            absolute_stop = context.body_start_line + relative_range.stop - 1
            matches.append(
                _JavaUnboundedFindAllMatch(
                    line_range=range(absolute_start, absolute_stop),
                    line_number=absolute_start,
                    access_pattern=f"{owner_name}.{repository_method}",
                    repository_type=repository_type,
                    service_method=context.name,
                    repository_method=repository_method,
                )
            )
    return tuple(matches)


def _iter_java_transactional_method_contexts(source: str) -> tuple[_JavaMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaMethodContext] = []
    for annotation_match in _TRANSACTIONAL_ANNOTATION_PATTERN.finditer(scannable_source):
        annotation_args = annotation_match.group("args") or ""
        if _JAVA_TRANSACTIONAL_READ_ONLY_PATTERN.search(annotation_args):
            continue
        method_context = _java_transactional_method_context(scannable_source, annotation_match)
        if method_context is not None:
            contexts.append(method_context)
    return tuple(contexts)


def _iter_java_transactional_external_io_matches(
    source: str,
) -> tuple[_JavaTransactionalExternalIOMatch, ...]:
    scannable_source = _strip_java_comments(source)
    collaborator_fields = _java_collaborator_field_types(scannable_source)
    if not collaborator_fields:
        return ()

    matches: list[_JavaTransactionalExternalIOMatch] = []
    for context in _iter_java_transactional_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_TRANSACTIONAL_EXTERNAL_IO_CALL_PATTERN.finditer(scannable_body):
            owner_name = match.group("owner")
            collaborator_type = collaborator_fields.get(owner_name)
            if collaborator_type is None:
                continue
            method_name = match.group("method")
            if not _looks_like_java_transactional_external_io_owner(
                owner_name=owner_name, collaborator_type=collaborator_type
            ):
                continue
            io_kind = _java_transactional_external_io_kind(method_name)
            if io_kind is None:
                continue
            line_range = _match_line_range(
                scannable_body, match.start("owner"), match.end("method")
            )
            absolute_line_range = range(
                context.body_start_line + line_range.start - 1,
                context.body_start_line + line_range.stop - 1,
            )
            matches.append(
                _JavaTransactionalExternalIOMatch(
                    line_range=absolute_line_range,
                    line_number=absolute_line_range.start,
                    access_pattern=f"{owner_name}.{method_name}",
                    collaborator_type=_java_simple_type_name(collaborator_type),
                    transactional_method=context.name,
                    io_kind=io_kind,
                )
            )
    return tuple(matches)


def _iter_java_controller_repository_access_matches(
    source: str,
) -> tuple[_JavaControllerRepositoryAccessMatch, ...]:
    scannable_source = _strip_java_comments(source)
    repository_fields = _java_repository_field_types(scannable_source)
    if not repository_fields:
        return ()

    object_method_names = {"equals", "hashCode", "notify", "notifyAll", "toString", "wait"}
    call_matches: list[_JavaControllerRepositoryAccessMatch] = []
    called_fields: set[str] = set()
    scannable_without_strings = _strip_java_string_literals(scannable_source)
    for match in _JAVA_TRANSACTIONAL_EXTERNAL_IO_CALL_PATTERN.finditer(scannable_without_strings):
        owner_name = match.group("owner")
        repository_type = repository_fields.get(owner_name)
        if repository_type is None:
            continue
        method_name = match.group("method")
        if method_name in object_method_names:
            continue
        line_range = _match_line_range(
            scannable_without_strings, match.start("owner"), match.end("method")
        )
        call_matches.append(
            _JavaControllerRepositoryAccessMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=f"{owner_name}.{method_name}",
                repository_type=repository_type,
                access_kind="repository-call",
            )
        )
        called_fields.add(owner_name)

    field_matches: list[_JavaControllerRepositoryAccessMatch] = []
    for match in _JAVA_REPOSITORY_FIELD_PATTERN.finditer(scannable_source):
        field_name = match.group("name")
        repository_type = repository_fields.get(field_name)
        if repository_type is None or field_name in called_fields:
            continue
        line_range = _match_line_range(scannable_source, match.start("type"), match.end("name"))
        field_matches.append(
            _JavaControllerRepositoryAccessMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=repository_type,
                repository_type=repository_type,
                access_kind="repository-injection",
            )
        )
    return tuple(sorted((*field_matches, *call_matches), key=lambda match: match.line_number))


def _looks_like_java_lock_pool_value_type(type_name: str) -> bool:
    simple_name = _java_simple_type_name(type_name)
    return simple_name.endswith(_JAVA_LOCK_POOL_VALUE_TYPE_SUFFIXES)


def _java_concurrent_map_variable_types(source: str) -> dict[str, str]:
    return {
        match.group("name"): _java_simple_type_name(match.group("type"))
        for match in _JAVA_CONCURRENT_MAP_DECLARATION_PATTERN.finditer(source)
    }


def _iter_java_static_lock_pool_matches(source: str) -> tuple[_JavaStaticLockPoolMatch, ...]:
    scannable_source = _strip_java_comments(source)
    lock_pools: dict[str, tuple[str, str, range]] = {}
    for match in _JAVA_STATIC_LOCK_POOL_FIELD_PATTERN.finditer(scannable_source):
        lock_type = _java_simple_type_name(match.group("value_type"))
        if not _looks_like_java_lock_pool_value_type(lock_type):
            continue
        line_range = _match_line_range(scannable_source, match.start("map_type"), match.end("name"))
        lock_pools[match.group("name")] = (
            _java_simple_type_name(match.group("map_type")),
            lock_type,
            line_range,
        )
    if not lock_pools:
        return ()

    matches: list[_JavaStaticLockPoolMatch] = []
    for growth_match in _JAVA_LOCK_POOL_GROWTH_PATTERN.finditer(scannable_source):
        map_name = growth_match.group("map")
        pool_info = lock_pools.get(map_name)
        if pool_info is None or _java_static_lock_pool_has_cleanup(
            scannable_source,
            map_name=map_name,
        ):
            continue
        if any(existing.map_name == map_name for existing in matches):
            continue
        map_type, lock_type, declaration_line_range = pool_info
        growth_method = growth_match.group("method")
        line_range = _match_line_range(
            scannable_source, growth_match.start("map"), growth_match.end("method")
        )
        matches.append(
            _JavaStaticLockPoolMatch(
                line_range=line_range,
                declaration_line_range=declaration_line_range,
                line_number=line_range.start,
                access_pattern=f"{map_name}.{growth_method}",
                map_name=map_name,
                map_type=map_type,
                lock_type=lock_type,
                growth_method=growth_method,
            )
        )
    return tuple(matches)


def _java_static_lock_pool_has_cleanup(source: str, *, map_name: str) -> bool:
    escaped_name = re.escape(map_name)
    cleanup_patterns = (
        rf"\b(?:this\.|[A-Za-z_][A-Za-z0-9_]*\.)?{escaped_name}\s*\.\s*remove\s*\(",
        rf"\b(?:this\.|[A-Za-z_][A-Za-z0-9_]*\.)?{escaped_name}\s*\.\s*clear\s*\(",
        rf"\b(?:this\.|[A-Za-z_][A-Za-z0-9_]*\.)?{escaped_name}\s*\.\s*"
        r"(?:entrySet|keySet|values)\s*\(\s*\)\s*\.\s*removeIf\s*\(",
    )
    return any(re.search(pattern, source) is not None for pattern in cleanup_patterns)


def _java_absolute_body_line_range(context: _JavaMethodContext, line_range: range) -> range:
    return range(
        context.body_start_line + line_range.start - 1,
        context.body_start_line + line_range.stop - 1,
    )


def _iter_java_scheduled_concurrentmap_removal_matches(
    source: str,
) -> tuple[_JavaScheduledConcurrentMapRemovalMatch, ...]:
    scannable_source = _strip_java_comments(source)
    concurrent_map_types = _java_concurrent_map_variable_types(scannable_source)
    if not concurrent_map_types:
        return ()

    matches: list[_JavaScheduledConcurrentMapRemovalMatch] = []
    for context in _iter_java_scheduled_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        for iterator_match in _JAVA_CONCURRENT_MAP_ENTRY_ITERATOR_PATTERN.finditer(scannable_body):
            map_name = iterator_match.group("map")
            map_type = concurrent_map_types.get(map_name)
            if map_type is None:
                continue
            iterator_name = iterator_match.group("iterator")
            iterator_access = re.escape(iterator_name)
            if (
                re.search(rf"\b(?:this\.)?{iterator_access}\.hasNext\s*\(\s*\)", scannable_body)
                is None
            ):
                continue
            if (
                re.search(rf"\b(?:this\.)?{iterator_access}\.next\s*\(\s*\)", scannable_body)
                is None
            ):
                continue
            remove_match = re.search(
                rf"\b(?:this\.)?{iterator_access}\.remove\s*\(",
                scannable_body[iterator_match.end() :],
            )
            if remove_match is None:
                continue
            remove_start = iterator_match.end() + remove_match.start()
            remove_end = iterator_match.end() + remove_match.end()
            iterator_line_range = _match_line_range(
                scannable_body,
                iterator_match.start("iterator"),
                iterator_match.end("map"),
            )
            remove_line_range = _match_line_range(scannable_body, remove_start, remove_end)
            absolute_line_range = _java_absolute_body_line_range(
                context,
                _combine_line_ranges(iterator_line_range, remove_line_range),
            )
            matches.append(
                _JavaScheduledConcurrentMapRemovalMatch(
                    line_range=absolute_line_range,
                    line_number=absolute_line_range.start,
                    access_pattern=f"{iterator_name}.remove",
                    map_type=map_type,
                    scheduled_method=context.name,
                )
            )
    return tuple(matches)


def _java_foreach_lambda_looks_mutating(argument_text: str) -> bool:
    arrow_index = argument_text.find("->")
    if arrow_index == -1:
        return False
    lambda_body = argument_text[arrow_index + 2 :].strip()
    if not lambda_body:
        return False
    if lambda_body.startswith("{"):
        lambda_body, _ = _scan_java_block(lambda_body, 0)
    return bool(
        re.search(
            r"\b(?:assign|clear|disable|enable|expire|mark|set|touch|update)\w*\s*\(",
            lambda_body,
        )
        or re.search(r"[A-Za-z_][A-Za-z0-9_.]*\s*=", lambda_body)
    )


def _java_has_visible_try_catch_guard(body_text: str, *, save_start: int, save_end: int) -> bool:
    window_start = max(0, save_start - 200)
    window_end = min(len(body_text), save_end + 400)
    window = body_text[window_start:window_end]
    relative_save_start = save_start - window_start
    relative_save_end = save_end - window_start
    try_match = re.search(r"\btry\b", window)
    catch_match = re.search(r"\bcatch\s*\(", window)
    return (
        try_match is not None
        and catch_match is not None
        and try_match.start() <= relative_save_start
        and catch_match.start() >= relative_save_end
    )


def _iter_java_batch_saveall_matches(
    source: str,
) -> tuple[_JavaBatchSaveAllMatch, ...]:
    scannable_source = _strip_java_comments(source)
    repository_fields = _java_repository_field_types(scannable_source)
    if not repository_fields:
        return ()

    matches: list[_JavaBatchSaveAllMatch] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        foreach_candidates: list[tuple[str, range, int]] = []
        for foreach_match in _JAVA_COLLECTION_FOREACH_PATTERN.finditer(scannable_body):
            arguments, argument_end = _extract_java_call_arguments(
                scannable_body, foreach_match.end()
            )
            if not arguments or not _java_foreach_lambda_looks_mutating(arguments[0]):
                continue
            line_range = _match_line_range(
                scannable_body,
                foreach_match.start("collection"),
                argument_end,
            )
            foreach_candidates.append((foreach_match.group("collection"), line_range, argument_end))
        if not foreach_candidates:
            continue

        for save_match in _JAVA_SAVEALL_CALL_PATTERN.finditer(scannable_body):
            owner_name = save_match.group("owner")
            repository_type = repository_fields.get(owner_name)
            if repository_type is None:
                continue
            collection_name = save_match.group("collection")
            if _java_has_visible_try_catch_guard(
                scannable_body,
                save_start=save_match.start("owner"),
                save_end=save_match.end("collection"),
            ):
                continue
            candidate = max(
                (
                    (line_range, argument_end)
                    for foreach_collection, line_range, argument_end in foreach_candidates
                    if foreach_collection == collection_name
                    and argument_end <= save_match.start()
                    and _match_line_range(
                        scannable_body,
                        save_match.start("owner"),
                        save_match.end("collection"),
                    ).start
                    - line_range.stop
                    <= 20
                ),
                default=None,
                key=lambda value: value[0].start,
            )
            if candidate is None:
                continue
            save_line_range = _match_line_range(
                scannable_body,
                save_match.start("owner"),
                save_match.end("collection"),
            )
            absolute_line_range = _java_absolute_body_line_range(
                context,
                _combine_line_ranges(candidate[0], save_line_range),
            )
            matches.append(
                _JavaBatchSaveAllMatch(
                    line_range=absolute_line_range,
                    line_number=absolute_line_range.start,
                    access_pattern=f"{owner_name}.saveAll",
                    repository_type=repository_type,
                    collection_name=collection_name,
                    batch_method=context.name,
                    guard_kind="missing-try-catch",
                )
            )
    return tuple(matches)


def _java_annotation_preamble(lines: Sequence[str], start_line: int) -> str:
    if start_line <= 1:
        return ""
    collected: list[str] = []
    reverse_paren_depth = 0
    index = start_line - 2
    while index >= 0:
        text = lines[index]
        stripped = text.strip()
        if not stripped:
            if collected and reverse_paren_depth == 0:
                break
            index -= 1
            continue
        reverse_paren_depth += stripped.count(")") - stripped.count("(")
        if stripped.startswith("@") or reverse_paren_depth > 0:
            collected.append(text)
            index -= 1
            continue
        break
    collected.reverse()
    return "\n".join(collected)


def _java_event_listener_write_kind(
    *, owner_name: str, collaborator_type: str, method_name: str
) -> str | None:
    type_name = _java_simple_type_name(collaborator_type)
    method_tokens = set(_shared_split_identifier_tokens(method_name))
    if not method_tokens:
        return None
    if type_name.endswith("Repository"):
        if method_tokens & _JAVA_EVENT_LISTENER_WRITE_METHOD_MARKERS:
            return "repository-write"
        return None
    if method_tokens and method_tokens <= _JAVA_EVENT_LISTENER_READ_METHOD_MARKERS:
        return None
    if not method_tokens & _JAVA_EVENT_LISTENER_ORCHESTRATION_METHOD_MARKERS:
        return None
    collaborator_tokens = set(_shared_split_identifier_tokens(owner_name))
    collaborator_tokens.update(_shared_split_identifier_tokens(type_name))
    if collaborator_tokens & _JAVA_EVENT_LISTENER_ORCHESTRATION_OWNER_MARKERS:
        return "write-orchestration"
    return None


def _iter_java_event_listener_boundary_matches(
    source: str,
) -> tuple[_JavaEventListenerTransactionBoundaryMatch, ...]:
    scannable_source = _strip_java_comments(source)
    collaborator_fields = _java_collaborator_field_types(scannable_source)
    if not collaborator_fields:
        return ()

    source_lines = scannable_source.splitlines()
    matches: list[_JavaEventListenerTransactionBoundaryMatch] = []
    for annotation_match in _EVENT_LISTENER_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        context, signature = context_info
        annotation_block = "\n".join(
            filter(
                None,
                (
                    _java_annotation_preamble(source_lines, context.line_range.start),
                    signature,
                ),
            )
        )
        if _TRANSACTIONAL_EVENT_LISTENER_ANNOTATION_PATTERN.search(annotation_block):
            continue
        transactional_match = _TRANSACTIONAL_ANNOTATION_PATTERN.search(annotation_block)
        if transactional_match is not None:
            annotation_args = transactional_match.group("args") or ""
            if _JAVA_TRANSACTIONAL_READ_ONLY_PATTERN.search(annotation_args):
                continue
            if _JAVA_REQUIRES_NEW_PROPAGATION_PATTERN.search(annotation_args):
                continue

        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_TRANSACTIONAL_EXTERNAL_IO_CALL_PATTERN.finditer(scannable_body):
            owner_name = match.group("owner")
            collaborator_type = collaborator_fields.get(owner_name)
            if collaborator_type is None:
                continue
            method_name = match.group("method")
            write_kind = _java_event_listener_write_kind(
                owner_name=owner_name,
                collaborator_type=collaborator_type,
                method_name=method_name,
            )
            if write_kind is None:
                continue
            line_range = _match_line_range(
                scannable_body, match.start("owner"), match.end("method")
            )
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            matches.append(
                _JavaEventListenerTransactionBoundaryMatch(
                    line_range=absolute_line_range,
                    line_number=absolute_line_range.start,
                    access_pattern=f"{owner_name}.{method_name}",
                    listener_method=context.name,
                    write_kind=write_kind,
                )
            )
    return tuple(matches)


def _java_variable_has_active_artifact_state(body_text: str, artifact_name: str) -> bool:
    active_pattern = re.compile(
        _JAVA_ACTIVE_SETTER_PATTERN_TEMPLATE.format(artifact=re.escape(artifact_name))
    )
    if active_pattern.search(body_text):
        return True
    status_pattern = re.compile(
        _JAVA_ACTIVE_STATUS_PATTERN_TEMPLATE.format(artifact=re.escape(artifact_name))
    )
    return status_pattern.search(body_text) is not None


def _iter_java_active_artifact_matches(source: str) -> tuple[_JavaActiveArtifactMatch, ...]:
    scannable_source = _strip_java_comments(source)
    repository_fields = _java_repository_field_types(scannable_source)
    if not repository_fields:
        return ()

    matches: list[_JavaActiveArtifactMatch] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        if not _JAVA_ACTIVE_GUARD_PATTERN.search(scannable_body):
            for save_match in _JAVA_SAVE_CALL_PATTERN.finditer(scannable_body):
                owner_name = save_match.group("owner")
                if owner_name not in repository_fields:
                    continue
                artifact_name = save_match.group("artifact")
                if not _java_variable_has_active_artifact_state(scannable_body, artifact_name):
                    continue
                line_range = _match_line_range(
                    scannable_body, save_match.start("owner"), save_match.end("artifact")
                )
                absolute_line_range = _java_absolute_body_line_range(context, line_range)
                matches.append(
                    _JavaActiveArtifactMatch(
                        line_range=absolute_line_range,
                        line_number=absolute_line_range.start,
                        access_pattern=f"{owner_name}.save",
                        service_method=context.name,
                        artifact_guard="missing-idempotency-check",
                    )
                )
    return tuple(matches)


def _iter_java_business_uniqueness_matches(source: str) -> tuple[_JavaBusinessUniquenessMatch, ...]:
    scannable_source = _strip_java_comments(source)
    matches: list[_JavaBusinessUniquenessMatch] = []
    for method_match in _JAVA_UNIQUENESS_METHOD_PATTERN.finditer(scannable_source):
        method_name = method_match.group("method")
        tokens = set(_shared_split_identifier_tokens(method_name))
        business_key_tokens = tokens & _JAVA_BUSINESS_KEY_MARKERS
        if not business_key_tokens:
            continue
        if tokens & _JAVA_BUSINESS_SCOPE_MARKERS:
            continue
        line_range = _match_line_range(
            scannable_source, method_match.start("method"), method_match.end("method")
        )
        matches.append(
            _JavaBusinessUniquenessMatch(
                line_range=line_range,
                line_number=line_range.start,
                repository_method=method_name,
                scope_kind="missing-business-scope",
            )
        )
    return tuple(matches)


def _java_migration_operation_kind(source: str) -> tuple[str, range] | None:
    stripped = _strip_java_comments(source)
    patterns: tuple[tuple[str, str], ...] = (
        ("drop-column", r"\balter\s+table\b[\s\S]*?\bdrop\s+column\b"),
        ("drop-table", r"\bdrop\s+table\b"),
        ("drop-index", r"\bdrop\s+index\b"),
        ("truncate-table", r"\btruncate\s+table\b"),
        ("alter-column", r"\balter\s+table\b[\s\S]*?\balter\s+column\b"),
        ("rename-column", r"\balter\s+table\b[\s\S]*?\brename\s+column\b"),
        ("drop-constraint", r"\balter\s+table\b[\s\S]*?\bdrop\s+constraint\b"),
    )
    for operation_kind, pattern in patterns:
        match = re.search(pattern, stripped, re.IGNORECASE)
        if match is not None:
            return operation_kind, _match_line_range(stripped, match.start(), match.end())
    return None


def _iter_java_flyway_nonadditive_matches(
    source: str, *, relative_path: str
) -> tuple[_JavaFlywayMigrationMatch, ...]:
    if not _is_flyway_migration_path(relative_path):
        return ()
    if Path(relative_path).name.startswith("R__"):
        return ()
    operation = _java_migration_operation_kind(source)
    if operation is None:
        return ()
    operation_kind, line_range = operation
    migration_kind = (
        "java-flyway-versioned" if relative_path.endswith(".java") else "sql-flyway-versioned"
    )
    return (
        _JavaFlywayMigrationMatch(
            line_range=line_range,
            line_number=line_range.start,
            migration_kind=migration_kind,
            operation_kind=operation_kind,
        ),
    )


def _java_signature_parameters(signature: str, method_name: str) -> tuple[str, ...]:
    method_pattern = re.compile(rf"\b{re.escape(method_name)}\s*\((?P<params>[^)]*)\)")
    method_match = method_pattern.search(signature)
    if method_match is None:
        return ()
    params = method_match.group("params").strip()
    if not params:
        return ()
    return tuple(part.strip() for part in params.split(",") if part.strip())


def _java_parameter_entity_type(
    parameter_text: str,
    *,
    import_map: dict[str, str],
    entity_index: _JavaEntityIndex,
) -> str | None:
    normalized = re.sub(r"@\w+(?:\([^)]*\))?\s*", " ", parameter_text)
    normalized = re.sub(r"\bfinal\s+", " ", normalized)
    parts = [part for part in normalized.split() if part]
    if len(parts) < 2:
        return None
    type_text = " ".join(parts[:-1])
    simple_name = _java_simple_type_name(type_text)
    fqcn = type_text if "." in type_text else import_map.get(simple_name)
    if fqcn is not None and fqcn in entity_index.by_fqcn:
        return entity_index.by_fqcn[fqcn]
    simple_matches = entity_index.by_simple_name.get(simple_name, ())
    if len(simple_matches) == 1:
        return simple_matches[0]
    return None


def _iter_java_entity_boundary_matches(
    source: str, *, entity_index: _JavaEntityIndex
) -> tuple[_JavaEntityBoundaryMatch, ...]:
    scannable_source = _strip_java_comments(source)
    import_map = _java_import_map(scannable_source)
    matches: list[_JavaEntityBoundaryMatch] = []

    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        context, signature = context_info
        for parameter_text in _java_signature_parameters(signature, context.name):
            entity_type = _java_parameter_entity_type(
                parameter_text, import_map=import_map, entity_index=entity_index
            )
            if entity_type is None:
                continue
            matches.append(
                _JavaEntityBoundaryMatch(
                    line_range=context.line_range,
                    line_number=context.line_range.start,
                    boundary_kind="async",
                    boundary_method=context.name,
                    entity_type=entity_type,
                )
            )
            break

    for annotation_match in _TRANSACTIONAL_ANNOTATION_PATTERN.finditer(scannable_source):
        annotation_args = annotation_match.group("args") or ""
        if not _JAVA_REQUIRES_NEW_PROPAGATION_PATTERN.search(annotation_args):
            continue
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        context, signature = context_info
        for parameter_text in _java_signature_parameters(signature, context.name):
            entity_type = _java_parameter_entity_type(
                parameter_text, import_map=import_map, entity_index=entity_index
            )
            if entity_type is None:
                continue
            matches.append(
                _JavaEntityBoundaryMatch(
                    line_range=context.line_range,
                    line_number=context.line_range.start,
                    boundary_kind="requires-new",
                    boundary_method=context.name,
                    entity_type=entity_type,
                )
            )
            break

    return tuple(matches)


def _iter_java_detached_async_matches(source: str) -> tuple[_JavaDetachedAsyncMatch, ...]:
    scannable_source = _strip_java_comments(source)
    matches: list[_JavaDetachedAsyncMatch] = []
    for match in _JAVA_DETACHED_ASYNC_PATTERN.finditer(scannable_source):
        access = _java_detached_async_access_pattern(match)
        if access is None:
            continue
        access_pattern, launch_kind = access
        line_range = _match_line_range(scannable_source, match.start("owner"), match.end("member"))
        matches.append(
            _JavaDetachedAsyncMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                launch_kind=launch_kind,
            )
        )

    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        async_match = _java_async_annotation_match(scannable_source, annotation_match)
        if async_match is not None:
            matches.append(async_match)
    return tuple(matches)


def _java_async_method_threads_tenant_identity(
    method_body: str, *, collaborator_fields: dict[str, str]
) -> bool:
    scannable_body = _strip_java_string_literals(method_body)
    collaborator_call_count = 0
    for match in _JAVA_MEMBER_CALL_PATTERN.finditer(scannable_body):
        owner_name = match.group("owner").split(".")[-1]
        if owner_name == "TenantContext" or _looks_like_java_log_receiver(owner_name):
            continue
        if owner_name not in collaborator_fields:
            continue
        arguments, _ = _extract_java_call_arguments(scannable_body, match.end())
        collaborator_call_count += 1
        if not any(
            _JAVA_TENANT_CONTEXT_VALUE_PATTERN.search(argument) is not None
            for argument in arguments
        ):
            return False
    return collaborator_call_count > 0


def _iter_java_async_tenant_context_gap_matches(
    source: str,
) -> tuple[_JavaAsyncContextGapMatch, ...]:
    scannable_source = _strip_java_comments(source)
    collaborator_fields = _java_collaborator_field_types(scannable_source)
    matches: list[_JavaAsyncContextGapMatch] = []
    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        async_method = _java_async_method_context(scannable_source, annotation_match)
        if async_method is None:
            continue
        method_name, method_body, line_range = async_method
        if _JAVA_TENANT_CONTEXT_SET_PATTERN.search(method_body):
            continue
        if _java_async_method_threads_tenant_identity(
            method_body, collaborator_fields=collaborator_fields
        ):
            continue
        if _JAVA_TENANT_CONTEXT_VALUE_PATTERN.search(method_body) is None:
            continue
        matches.append(
            _JavaAsyncContextGapMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=f"@Async {method_name}",
                propagation_kind="tenant-context-not-bound",
            )
        )
    return tuple(matches)


def _iter_java_background_observability_matches(
    source: str,
) -> tuple[_JavaBackgroundObservabilityMatch, ...]:
    scannable_source = _strip_java_comments(source)
    matches: list[_JavaBackgroundObservabilityMatch] = []
    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        async_method = _java_async_method_context(scannable_source, annotation_match)
        if async_method is None:
            continue
        method_name, method_body, line_range = async_method
        if not _java_has_log_only_async_outcome(method_body):
            continue
        matches.append(
            _JavaBackgroundObservabilityMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=f"@Async {method_name}",
                observability_kind="log-only-async-outcome",
            )
        )

    for match in _JAVA_DETACHED_ASYNC_PATTERN.finditer(scannable_source):
        access = _java_detached_async_access_pattern(match)
        if access is None:
            continue
        access_pattern, _ = access
        lambda_body, line_range = _java_async_lambda_context(scannable_source, match)
        if lambda_body is None or line_range is None:
            continue
        if not _java_has_log_only_async_outcome(lambda_body):
            continue
        matches.append(
            _JavaBackgroundObservabilityMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                observability_kind="log-only-async-outcome",
            )
        )
    return tuple(matches)


def _java_service_locator_access_pattern(match: re.Match[str]) -> tuple[str, str] | None:
    owner = match.group("owner")
    member = match.group("member")
    if member == "getBean":
        if not _looks_like_java_locator_owner(owner):
            return None
        return f"{owner}.getBean", "service-locator"
    if member == "getInstance":
        if not _looks_like_java_singleton_owner(owner):
            return None
        return f"{owner}.getInstance", "singleton"
    if member == "INSTANCE":
        if not _looks_like_java_singleton_owner(owner):
            return None
        return f"{owner}.INSTANCE", "singleton"
    return None


def _java_detached_async_access_pattern(match: re.Match[str]) -> tuple[str, str] | None:
    owner = match.group("owner")
    member = match.group("member")
    if owner == "CompletableFuture" and member == "runAsync":
        return "CompletableFuture.runAsync", "completablefuture-runasync"
    if member == "execute" and _looks_like_java_executor_owner(owner):
        return f"{owner}.execute", "executor-execute"
    return None


def _looks_like_java_locator_owner(name: str) -> bool:
    if name in _JAVA_SERVICE_LOCATOR_OWNER_EXACT_NAMES:
        return True
    tokens = set(_shared_split_identifier_tokens(name))
    return bool(tokens & _JAVA_SERVICE_LOCATOR_OWNER_MARKERS)


def _looks_like_java_executor_owner(name: str) -> bool:
    tokens = set(_shared_split_identifier_tokens(name))
    return bool(tokens & _JAVA_EXECUTOR_OWNER_MARKERS)


def _looks_like_java_singleton_owner(name: str) -> bool:
    return _looks_like_java_locator_owner(name) or _shared_looks_like_dependency_boundary_name(
        name, outbound_only=False
    )


def _java_async_annotation_match(
    source: str, annotation_match: re.Match[str]
) -> _JavaDetachedAsyncMatch | None:
    snippet = source[annotation_match.end() : annotation_match.end() + 320]
    brace_index = snippet.find("{")
    if brace_index != -1:
        snippet = snippet[:brace_index]
    normalized = re.sub(r"\s+", " ", snippet).strip()
    if not normalized:
        return None
    method_match = _JAVA_ASYNC_METHOD_PATTERN.search(normalized)
    if method_match is None:
        return None
    return_type = re.sub(r"\s+", " ", method_match.group("return").strip())
    if return_type != "void":
        return None
    line_range = _match_line_range(source, annotation_match.start(), annotation_match.end())
    method_name = method_match.group("name")
    return _JavaDetachedAsyncMatch(
        line_range=line_range,
        line_number=line_range.start,
        access_pattern=f"@Async void {method_name}",
        launch_kind="async-annotation",
    )


def _java_async_method_context(
    source: str, annotation_match: re.Match[str]
) -> tuple[str, str, range] | None:
    search_start = annotation_match.end()
    brace_index = source.find("{", search_start, search_start + 600)
    if brace_index == -1:
        return None
    signature = source[search_start:brace_index]
    normalized = re.sub(r"\s+", " ", signature).strip()
    if not normalized:
        return None
    method_match = _JAVA_ASYNC_METHOD_PATTERN.search(normalized)
    if method_match is None:
        return None
    body, end_offset = _scan_java_block(source, brace_index)
    line_range = _match_line_range(source, annotation_match.start(), end_offset)
    return method_match.group("name"), body, line_range


def _java_transactional_method_context(
    source: str, annotation_match: re.Match[str]
) -> _JavaMethodContext | None:
    search_start = annotation_match.end()
    brace_index = source.find("{", search_start, search_start + 600)
    if brace_index == -1:
        return None
    signature = source[search_start:brace_index]
    normalized = re.sub(r"\s+", " ", signature).strip()
    if not normalized:
        return None
    method_match = _JAVA_ASYNC_METHOD_PATTERN.search(normalized)
    if method_match is None:
        return None
    body, end_offset = _scan_java_block(source, brace_index)
    line_range = _match_line_range(source, annotation_match.start(), end_offset)
    body_start_line = _match_line_range(source, brace_index + 1, brace_index + 1).start
    return _JavaMethodContext(
        name=method_match.group("name"),
        return_type=re.sub(r"\s+", " ", method_match.group("return").strip()),
        response_name="",
        body=body,
        line_range=line_range,
        body_start_line=body_start_line,
    )


def _iter_java_method_contexts(source: str) -> tuple[_JavaMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaMethodContext] = []
    for method_match in _JAVA_ASYNC_METHOD_PATTERN.finditer(scannable_source):
        search_start = method_match.end()
        brace_index = scannable_source.find("{", search_start, search_start + 800)
        if brace_index == -1:
            continue
        semicolon_index = scannable_source.find(";", search_start, brace_index)
        if semicolon_index != -1:
            continue
        body, end_offset = _scan_java_block(scannable_source, brace_index)
        contexts.append(
            _JavaMethodContext(
                name=method_match.group("name"),
                return_type=re.sub(r"\s+", " ", method_match.group("return").strip()),
                response_name="",
                body=body,
                line_range=_match_line_range(scannable_source, method_match.start(), end_offset),
                body_start_line=_match_line_range(
                    scannable_source, brace_index + 1, brace_index + 1
                ).start,
            )
        )
    return tuple(contexts)


def _java_method_context_for_annotation(
    source: str, annotation_match: re.Match[str]
) -> tuple[_JavaMethodContext, str] | None:
    search_start = annotation_match.end()
    brace_index = source.find("{", search_start, search_start + 600)
    if brace_index == -1:
        return None
    semicolon_index = source.find(";", search_start, brace_index)
    if semicolon_index != -1:
        return None
    signature = source[annotation_match.start() : brace_index]
    normalized = re.sub(r"\s+", " ", source[search_start:brace_index]).strip()
    if not normalized:
        return None
    method_match = _JAVA_ASYNC_METHOD_PATTERN.search(normalized)
    if method_match is None:
        return None
    body, end_offset = _scan_java_block(source, brace_index)
    line_range = _match_line_range(source, annotation_match.start(), end_offset)
    body_start_line = _match_line_range(source, brace_index + 1, brace_index + 1).start
    context = _JavaMethodContext(
        name=method_match.group("name"),
        return_type=re.sub(r"\s+", " ", method_match.group("return").strip()),
        response_name="",
        body=body,
        line_range=line_range,
        body_start_line=body_start_line,
    )
    return context, signature


def _iter_java_scheduled_method_contexts(source: str) -> tuple[_JavaMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaMethodContext] = []
    for annotation_match in _SCHEDULED_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        method_context, _ = context_info
        contexts.append(method_context)
    return tuple(contexts)


def _java_iteration_lambda_context(argument_text: str) -> tuple[str, str] | None:
    arrow_index = argument_text.find("->")
    if arrow_index == -1:
        return None
    parameter_text = argument_text[:arrow_index].strip()
    if parameter_text.startswith("(") and parameter_text.endswith(")"):
        parameter_text = parameter_text[1:-1].strip()
    if not parameter_text:
        return None
    parameter_names = [
        part.rsplit(" ", 1)[-1].strip() for part in parameter_text.split(",") if part.strip()
    ]
    parameter_names = [
        name for name in parameter_names if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
    ]
    if not parameter_names:
        return None
    parameter_name = next(
        (
            name
            for name in parameter_names
            if set(_shared_split_identifier_tokens(name)) & _JAVA_TENANT_SCOPE_MARKERS
        ),
        parameter_names[-1],
    )
    body_text = argument_text[arrow_index + 2 :].strip()
    if not body_text:
        return None
    if body_text.startswith("{"):
        body_text, _ = _scan_java_block(body_text, 0)
    return parameter_name, body_text


def _java_loop_variable_has_tenant_accessor(loop_variable: str, loop_body: str) -> bool:
    accessor_pattern = re.compile(
        rf"\b{re.escape(loop_variable)}\s*\.\s*"
        r"(?:getTenant(?:Id|Code)?|tenant(?:Id|Code)|"
        r"getBranch(?:Id|Code)?|branch(?:Id|Code))\s*\("
    )
    return accessor_pattern.search(loop_body) is not None


def _java_cross_tenant_iteration_kind(
    *,
    loop_variable: str,
    iterable_expression: str,
    loop_body: str,
) -> str | None:
    iterable_tokens = _java_identifier_tokens(iterable_expression)
    loop_tokens = set(_shared_split_identifier_tokens(loop_variable))
    if (iterable_tokens | loop_tokens) & _JAVA_TENANT_SCOPE_MARKERS:
        return "tenant-collection-iteration"
    if _java_loop_variable_has_tenant_accessor(loop_variable, loop_body):
        return "tenant-scoped-batch-iteration"
    return None


def _java_has_tenant_context_reset_boundary(body_text: str) -> bool:
    return bool(
        _JAVA_TENANT_CONTEXT_BIND_PATTERN.search(body_text)
        and _JAVA_TENANT_CONTEXT_CLEAR_PATTERN.search(body_text)
    )


def _java_call_looks_like_tenant_boundary(
    owner_name: str, method_name: str, collaborator_type: str | None
) -> bool:
    tokens = set(_shared_split_identifier_tokens(owner_name.split(".")[-1]))
    tokens.update(_shared_split_identifier_tokens(method_name))
    if collaborator_type is not None:
        tokens.update(_shared_split_identifier_tokens(_java_simple_type_name(collaborator_type)))
    if tokens & _JAVA_TENANT_SCOPE_MARKERS and tokens & _JAVA_TENANT_BOUNDARY_INFRA_MARKERS:
        return True
    method_tokens = set(_shared_split_identifier_tokens(method_name))
    return "tenant" in method_tokens and bool(
        method_tokens & {"execute", "for", "in", "run", "with", "within"}
    )


def _java_has_explicit_tenant_boundary(
    loop_body: str, *, collaborator_fields: dict[str, str]
) -> bool:
    scannable_body = _strip_java_string_literals(loop_body)
    if _java_has_tenant_context_reset_boundary(scannable_body):
        return True
    for match in _JAVA_MEMBER_CALL_PATTERN.finditer(scannable_body):
        owner_name = match.group("owner").split(".")[-1]
        collaborator_type = collaborator_fields.get(owner_name)
        if _java_call_looks_like_tenant_boundary(
            owner_name,
            match.group("method"),
            collaborator_type,
        ):
            return True
    return False


def _java_scheduler_downstream_access(
    loop_body: str, *, collaborator_fields: dict[str, str]
) -> str | None:
    scannable_body = _strip_java_string_literals(loop_body)
    for match in _JAVA_MEMBER_CALL_PATTERN.finditer(scannable_body):
        owner_name = match.group("owner").split(".")[-1]
        method_name = match.group("method")
        if owner_name == "TenantContext" or _looks_like_java_log_receiver(owner_name):
            continue
        collaborator_type = collaborator_fields.get(owner_name)
        if _java_call_looks_like_tenant_boundary(owner_name, method_name, collaborator_type):
            continue
        method_tokens = set(_shared_split_identifier_tokens(method_name))
        if not method_tokens & _JAVA_SCHEDULER_ACTION_METHOD_MARKERS:
            continue
        return f"{owner_name}.{method_name}"
    return None


def _iter_java_scheduled_cross_tenant_iteration_matches(
    source: str,
) -> tuple[_JavaScheduledCrossTenantIterationMatch, ...]:
    scannable_source = _strip_java_comments(source)
    collaborator_fields = _java_collaborator_field_types(scannable_source)
    matches: list[_JavaScheduledCrossTenantIterationMatch] = []
    for context in _iter_java_scheduled_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        for loop_match in _JAVA_ENHANCED_FOR_LOOP_PATTERN.finditer(scannable_body):
            loop_body, loop_end = _scan_java_block(scannable_body, loop_match.end() - 1)
            iteration_kind = _java_cross_tenant_iteration_kind(
                loop_variable=loop_match.group("var"),
                iterable_expression=loop_match.group("iterable"),
                loop_body=loop_body,
            )
            if iteration_kind is None or _java_has_explicit_tenant_boundary(
                loop_body, collaborator_fields=collaborator_fields
            ):
                continue
            access_pattern = _java_scheduler_downstream_access(
                loop_body, collaborator_fields=collaborator_fields
            )
            if access_pattern is None:
                continue
            loop_line_range = _match_line_range(scannable_body, loop_match.start(), loop_end)
            absolute_line_range = _java_absolute_body_line_range(context, loop_line_range)
            matches.append(
                _JavaScheduledCrossTenantIterationMatch(
                    line_range=absolute_line_range,
                    line_number=absolute_line_range.start,
                    access_pattern=access_pattern,
                    scheduled_method=context.name,
                    tenant_source=_normalize_java_construction_pattern(
                        loop_match.group("iterable")
                    ),
                    iteration_kind=iteration_kind,
                )
            )
        for loop_match in _JAVA_FOREACH_ITERATION_PATTERN.finditer(scannable_body):
            arguments, argument_end = _extract_java_call_arguments(scannable_body, loop_match.end())
            if len(arguments) != 1:
                continue
            lambda_context = _java_iteration_lambda_context(arguments[0])
            if lambda_context is None:
                continue
            loop_variable, loop_body = lambda_context
            iteration_kind = _java_cross_tenant_iteration_kind(
                loop_variable=loop_variable,
                iterable_expression=loop_match.group("iterable"),
                loop_body=loop_body,
            )
            if iteration_kind is None or _java_has_explicit_tenant_boundary(
                loop_body, collaborator_fields=collaborator_fields
            ):
                continue
            access_pattern = _java_scheduler_downstream_access(
                loop_body, collaborator_fields=collaborator_fields
            )
            if access_pattern is None:
                continue
            loop_line_range = _match_line_range(scannable_body, loop_match.start(), argument_end)
            absolute_line_range = _java_absolute_body_line_range(context, loop_line_range)
            matches.append(
                _JavaScheduledCrossTenantIterationMatch(
                    line_range=absolute_line_range,
                    line_number=absolute_line_range.start,
                    access_pattern=access_pattern,
                    scheduled_method=context.name,
                    tenant_source=_normalize_java_construction_pattern(
                        loop_match.group("iterable")
                    ),
                    iteration_kind=iteration_kind,
                )
            )
    return tuple(matches)


def _scan_java_block(source: str, brace_index: int) -> tuple[str, int]:
    if brace_index < 0 or brace_index >= len(source) or source[brace_index] != "{":
        return "", brace_index
    depth = 0
    index = brace_index
    while index < len(source):
        char = source[index]
        if char == '"':
            index = _advance_java_string_literal(source, index)
            continue
        if char == "'":
            index = _advance_java_char_literal(source, index)
            continue
        if char == "{":
            depth += 1
            index += 1
            continue
        if char == "}":
            depth -= 1
            index += 1
            if depth == 0:
                return source[brace_index + 1 : index - 1], index
            continue
        index += 1
    return source[brace_index + 1 :], len(source)


def _advance_java_string_literal(source: str, start: int) -> int:
    delimiter = source[start]
    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == delimiter:
            return index + 1
        index += 1
    return len(source)


def _advance_java_char_literal(source: str, start: int) -> int:
    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "'":
            return index + 1
        index += 1
    return len(source)


def _java_async_lambda_context(
    source: str, match: re.Match[str]
) -> tuple[str | None, range | None]:
    arguments, argument_end = _extract_java_call_arguments(source, match.end())
    if not arguments:
        return None, None
    lambda_text = arguments[0]
    arrow_index = lambda_text.find("->")
    if arrow_index == -1:
        return None, None
    lambda_body = lambda_text[arrow_index + 2 :].strip()
    if not lambda_body:
        return None, None
    if lambda_body.startswith("{"):
        body, _ = _scan_java_block(lambda_body, 0)
    else:
        body = lambda_body
    line_range = _match_line_range(source, match.start("owner"), argument_end)
    return body, line_range


def _java_has_log_only_async_outcome(body_text: str) -> bool:
    return _java_has_log_call(body_text) and not _java_has_durable_background_surface(body_text)


def _java_has_log_call(body_text: str) -> bool:
    return any(
        _looks_like_java_log_receiver(match.group("receiver"))
        for match in _JAVA_LOG_CALL_PATTERN.finditer(body_text)
    )


def _java_has_durable_background_surface(body_text: str) -> bool:
    if _JAVA_BACKGROUND_SURFACE_PATTERN.search(body_text) is not None:
        return True
    for match in _JAVA_MEMBER_CALL_PATTERN.finditer(body_text):
        owner_tokens = set(_shared_split_identifier_tokens(match.group("owner").split(".")[-1]))
        method_tokens = set(_shared_split_identifier_tokens(match.group("method")))
        if not method_tokens & _JAVA_DURABLE_SURFACE_METHOD_MARKERS:
            continue
        if (owner_tokens | method_tokens) & _JAVA_DURABLE_SURFACE_TOKENS:
            return True
    return False


def _strip_java_log_statements(body_text: str) -> tuple[str, bool]:
    segments: list[str] = []
    cursor = 0
    found_log_call = False
    for match in _JAVA_LOG_CALL_PATTERN.finditer(body_text):
        if not _looks_like_java_log_receiver(match.group("receiver")):
            continue
        _, call_end = _extract_java_call_arguments(body_text, match.end())
        statement_end = call_end
        while statement_end < len(body_text) and body_text[statement_end].isspace():
            statement_end += 1
        if statement_end < len(body_text) and body_text[statement_end] == ";":
            statement_end += 1
        segments.append(body_text[cursor : match.start()])
        cursor = statement_end
        found_log_call = True
    segments.append(body_text[cursor:])
    return "".join(segments), found_log_call


def _java_catch_suppression_kind(catch_body: str) -> str | None:
    sanitized_body = _strip_java_string_literals(_strip_java_comments(catch_body))
    if re.search(r"\bthrow\b", sanitized_body):
        return None
    if _java_has_durable_background_surface(sanitized_body):
        return None

    body_without_logs, has_log_call = _strip_java_log_statements(sanitized_body)
    has_control_flow = _JAVA_SUPPRESSION_CONTROL_PATTERN.search(body_without_logs) is not None
    residual_body = _JAVA_SUPPRESSION_CONTROL_PATTERN.sub("", body_without_logs)
    residual_body = re.sub(r"[{};\s]+", "", residual_body)
    if residual_body:
        return None
    if has_log_call and has_control_flow:
        return "log-and-suppress"
    if has_log_call:
        return "log-only"
    if has_control_flow or not sanitized_body.strip():
        return "silent-suppression"
    return None


def _is_java_broad_exception_type(type_text: str) -> bool:
    normalized_parts = {
        part.strip().rsplit(".", 1)[-1] for part in type_text.split("|") if part.strip()
    }
    return bool(normalized_parts & {"Error", "Exception", "RuntimeException", "Throwable"})


def _java_collaborator_field_types(source: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("type")
        for match in _JAVA_COLLABORATOR_FIELD_PATTERN.finditer(source)
    }


def _java_repository_field_types(source: str) -> dict[str, str]:
    return {
        match.group("name"): _java_simple_type_name(match.group("type"))
        for match in _JAVA_REPOSITORY_FIELD_PATTERN.finditer(source)
    }


def _java_repository_interface_body(source: str, *, repository_type: str) -> str | None:
    interface_pattern = re.compile(rf"\binterface\s+{re.escape(repository_type)}\b")
    interface_match = interface_pattern.search(source)
    if interface_match is None:
        return None
    brace_index = source.find("{", interface_match.end(), interface_match.end() + 400)
    if brace_index == -1:
        return None
    body, _ = _scan_java_block(source, brace_index)
    return body


def _java_repository_has_paginated_findall_overload(
    source: str, *, repository_type: str, method_name: str
) -> bool:
    interface_body = _java_repository_interface_body(source, repository_type=repository_type)
    search_text = interface_body if interface_body is not None else source
    method_pattern = re.compile(rf"\b{re.escape(method_name)}\s*\((?P<params>[^)]*)\)\s*(?:;|\{{)")
    return any(
        _JAVA_PAGINATION_PARAMETER_PATTERN.search(match.group("params") or "") is not None
        for match in method_pattern.finditer(search_text)
    )


def _java_simple_type_name(value: str) -> str:
    return value.rsplit(".", 1)[-1].split("<", 1)[0].strip()


def _java_identifier_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for identifier in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text):
        tokens.update(_shared_split_identifier_tokens(identifier))
    return tokens


def _looks_like_java_lazy_service_target(type_name: str) -> bool:
    simple_name = _java_simple_type_name(type_name)
    return simple_name.endswith(_JAVA_LAZY_SERVICE_TARGET_SUFFIXES)


def _iter_java_lazy_service_provider_matches(
    source: str, *, relative_path: str
) -> tuple[_JavaLazyServiceProviderMatch, ...]:
    scannable_source = _strip_java_comments(source)
    if _is_java_factory_or_bootstrap_context(relative_path, scannable_source):
        return ()
    type_name, _ = _java_primary_type_name(scannable_source, relative_path)
    matches: list[_JavaLazyServiceProviderMatch] = []
    seen_patterns: set[tuple[int, str]] = set()
    for match in _JAVA_LAZY_PROVIDER_DECLARATION_PATTERN.finditer(scannable_source):
        target_type = _java_simple_type_name(match.group("target_type"))
        if not _looks_like_java_lazy_service_target(target_type):
            continue
        line_range = _match_line_range(
            scannable_source,
            match.start("provider_type"),
            match.end("name"),
        )
        access_pattern = f"{_java_simple_type_name(match.group('provider_type'))}<{target_type}>"
        dedupe_key = (line_range.start, access_pattern)
        if dedupe_key in seen_patterns:
            continue
        seen_patterns.add(dedupe_key)
        provider_kind = "lazy-service-provider"
        if target_type == _java_simple_type_name(type_name):
            provider_kind = "self-provider"
        matches.append(
            _JavaLazyServiceProviderMatch(
                line_range=line_range,
                line_number=line_range.start,
                access_pattern=access_pattern,
                provider_type=_java_simple_type_name(match.group("provider_type")),
                target_type=target_type,
                provider_kind=provider_kind,
            )
        )
    return tuple(matches)


def _looks_like_java_transactional_external_io_owner(
    *, owner_name: str, collaborator_type: str
) -> bool:
    if _shared_looks_like_dependency_boundary_name(collaborator_type, outbound_only=True):
        return True
    if _shared_looks_like_dependency_boundary_name(owner_name, outbound_only=True):
        return True
    tokens = set(_shared_split_identifier_tokens(owner_name))
    tokens.update(_shared_split_identifier_tokens(collaborator_type))
    return bool(tokens & _JAVA_TRANSACTIONAL_EXTERNAL_IO_OWNER_MARKERS)


def _java_transactional_external_io_kind(method_name: str) -> str | None:
    method_tokens = set(_shared_split_identifier_tokens(method_name))
    if not method_tokens:
        return None
    if "send" in method_tokens:
        return "message-send"
    if "post" in method_tokens:
        return "http-post"
    if "store" in method_tokens or "upload" in method_tokens:
        return "storage-write"
    if "initiate" in method_tokens:
        return "provider-initiation"
    if method_tokens & _JAVA_TRANSACTIONAL_EXTERNAL_IO_METHOD_MARKERS:
        return "external-io"
    return None


def _iter_java_response_method_contexts(source: str) -> tuple[_JavaMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaMethodContext] = []
    for method_match in _JAVA_ASYNC_METHOD_PATTERN.finditer(scannable_source):
        search_start = method_match.end()
        brace_index = scannable_source.find("{", search_start, search_start + 800)
        if brace_index == -1:
            continue
        signature = scannable_source[method_match.start() : brace_index]
        response_match = _JAVA_RESPONSE_PARAM_PATTERN.search(signature)
        if response_match is None:
            continue
        body, end_offset = _scan_java_block(scannable_source, brace_index)
        contexts.append(
            _JavaMethodContext(
                name=method_match.group("name"),
                return_type=re.sub(r"\s+", " ", method_match.group("return").strip()),
                response_name=response_match.group("name"),
                body=body,
                line_range=_match_line_range(scannable_source, method_match.start(), end_offset),
                body_start_line=_match_line_range(
                    scannable_source, brace_index + 1, brace_index + 1
                ).start,
            )
        )
    return tuple(contexts)


def _iter_java_method_contexts(source: str) -> tuple[_JavaMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaMethodContext] = []
    for method_match in _JAVA_ASYNC_METHOD_PATTERN.finditer(scannable_source):
        search_start = method_match.end()
        brace_index = scannable_source.find("{", search_start, search_start + 800)
        if brace_index == -1:
            continue
        signature = scannable_source[method_match.start() : brace_index]
        normalized = re.sub(r"\s+", " ", signature).strip()
        if not normalized:
            continue
        body, end_offset = _scan_java_block(scannable_source, brace_index)
        contexts.append(
            _JavaMethodContext(
                name=method_match.group("name"),
                return_type=re.sub(r"\s+", " ", method_match.group("return").strip()),
                response_name="",
                body=body,
                line_range=_match_line_range(scannable_source, method_match.start(), end_offset),
                body_start_line=_match_line_range(
                    scannable_source, brace_index + 1, brace_index + 1
                ).start,
            )
        )
    return tuple(contexts)


def _iter_java_method_line_ranges(source: str) -> tuple[tuple[str, range], ...]:
    return tuple(
        (context.name, context.line_range) for context in _iter_java_method_contexts(source)
    )


def _iter_java_endpoint_method_contexts(source: str) -> tuple[_JavaMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaMethodContext] = []
    seen_methods: set[tuple[str, int]] = set()
    for annotation_match in _JAVA_ENDPOINT_MAPPING_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        context, _ = context_info
        key = (context.name, context.line_range.start)
        if key in seen_methods:
            continue
        seen_methods.add(key)
        contexts.append(context)
    return tuple(contexts)


def _java_response_call_pattern(response_name: str) -> re.Pattern[str]:
    escaped = re.escape(response_name)
    return re.compile(
        rf"\b(?P<access>"
        rf"{escaped}\.(?:sendError|sendRedirect)"
        rf"|{escaped}\.getWriter\(\)\.write"
        rf"|{escaped}\.getOutputStream\(\)\.write"
        rf")\s*\("
    )


def _java_control_flow_lines(body_text: str, *, start_line: int) -> tuple[_JavaControlLine, ...]:
    sanitized = _strip_java_string_literals(_strip_java_comments(body_text))
    lines: list[_JavaControlLine] = []
    depth = 0
    for index, text in enumerate(sanitized.splitlines(), start=start_line):
        start_depth = depth
        depth = max(0, depth + text.count("{") - text.count("}"))
        lines.append(
            _JavaControlLine(
                text=text,
                line_number=index,
                start_depth=start_depth,
                end_depth=depth,
            )
        )
    return tuple(lines)


def _java_line_is_control_structure(stripped_line: str) -> bool:
    if not stripped_line:
        return True
    if stripped_line in {"{", "}"}:
        return True
    normalized = stripped_line.lstrip("}").strip()
    if not normalized:
        return True
    if normalized.startswith(("else", "catch", "finally")):
        return True
    return bool(
        normalized.startswith(
            (
                "if ",
                "if(",
                "for ",
                "for(",
                "while ",
                "while(",
                "switch ",
                "switch(",
                "try",
                "case ",
                "default:",
            )
        )
    )


def _java_line_starts_sibling_branch(stripped_line: str) -> bool:
    normalized = stripped_line.lstrip("}").strip()
    return normalized.startswith(("else", "catch", "finally"))


def _java_line_decision_points(stripped_line: str) -> int:
    normalized = stripped_line.lstrip("}").strip()
    if not normalized:
        return 0
    if normalized.startswith("else "):
        normalized = normalized[5:].lstrip()

    decision_points = normalized.count("&&") + normalized.count("||")
    if normalized.startswith(
        ("if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(", "catch")
    ):
        decision_points += 1
    if normalized.startswith(("case ", "default:")):
        decision_points += 1
    return decision_points


def _java_method_cyclomatic_metrics(context: _JavaMethodContext) -> tuple[int, int]:
    decision_points = 0
    max_nesting = 0
    for line in _java_control_flow_lines(context.body, start_line=context.body_start_line):
        line_decisions = _java_line_decision_points(line.text.strip())
        if line_decisions == 0:
            continue
        decision_points += line_decisions
        max_nesting = max(max_nesting, line.start_depth + 1)
    return 1 + decision_points, max_nesting


def _java_line_is_safe_terminator(stripped_line: str, *, return_type: str) -> bool:
    normalized = stripped_line.strip()
    if normalized.startswith("throw "):
        return True
    if re.match(r"return\s*;", normalized):
        return True
    return bool(
        return_type in {"boolean", "Boolean"}
        and re.match(
            r"return\s+(?:false|Boolean\.FALSE)\s*;",
            normalized,
        )
    )


def _java_has_inline_safe_terminator(line_fragment: str, *, return_type: str) -> bool:
    if "throw " in line_fragment:
        return True
    if re.search(r"return\s*;", line_fragment):
        return True
    return bool(
        return_type in {"boolean", "Boolean"}
        and re.search(
            r"return\s+(?:false|Boolean\.FALSE)\s*;",
            line_fragment,
        )
    )


def _java_call_end_index(
    lines: Sequence[_JavaControlLine], *, start_index: int, start_offset: int
) -> int:
    balance = 0
    for index in range(start_index, len(lines)):
        text = lines[index].text[start_offset:] if index == start_index else lines[index].text
        balance += text.count("(") - text.count(")")
        if balance <= 0:
            return index
        start_offset = 0
    return start_index


def _java_first_meaningful_line_after(
    lines: Sequence[_JavaControlLine], *, start_index: int
) -> _JavaControlLine | None:
    for line in lines[start_index:]:
        if line.text.strip():
            return line
    return None


def _java_response_fallthrough_line(
    lines: Sequence[_JavaControlLine],
    *,
    response_index: int,
    call_end_index: int,
    return_type: str,
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
        if _java_line_starts_sibling_branch(stripped):
            sibling_branch = True
            continue
        if line.start_depth == current_depth and _java_line_is_safe_terminator(
            stripped,
            return_type=return_type,
        ):
            return None
        if line.start_depth == current_depth and not _java_line_is_control_structure(stripped):
            return line.line_number
        if line.end_depth < current_depth:
            branch_end_index = index + 1
            break
    if branch_end_index is None:
        branch_end_index = len(lines)
    next_line = _java_first_meaningful_line_after(lines, start_index=branch_end_index)
    if next_line is None:
        return None
    if _java_line_is_safe_terminator(next_line.text.strip(), return_type=return_type):
        return None
    return next_line.line_number


def _iter_java_response_lifecycle_matches(source: str) -> tuple[_JavaResponseLifecycleMatch, ...]:
    matches: list[_JavaResponseLifecycleMatch] = []
    for context in _iter_java_response_method_contexts(source):
        response_pattern = _java_response_call_pattern(context.response_name)
        control_lines = _java_control_flow_lines(context.body, start_line=context.body_start_line)
        for index, line in enumerate(control_lines):
            match = response_pattern.search(line.text)
            if match is None:
                continue
            if _java_has_inline_safe_terminator(
                line.text[match.end() :],
                return_type=context.return_type,
            ):
                continue
            call_end_index = _java_call_end_index(
                control_lines,
                start_index=index,
                start_offset=match.start(),
            )
            continuation_line = _java_response_fallthrough_line(
                control_lines,
                response_index=index,
                call_end_index=call_end_index,
                return_type=context.return_type,
            )
            if continuation_line is None:
                continue
            matches.append(
                _JavaResponseLifecycleMatch(
                    line_range=range(line.line_number, continuation_line + 1),
                    line_number=line.line_number,
                    access_pattern=match.group("access"),
                    lifecycle_kind="terminal-response-fallthrough",
                )
            )
    return tuple(matches)


def _iter_java_filter_method_contexts(source: str) -> tuple[_JavaFilterMethodContext, ...]:
    scannable_source = _strip_java_comments(source)
    contexts: list[_JavaFilterMethodContext] = []
    for method_match in _JAVA_ASYNC_METHOD_PATTERN.finditer(scannable_source):
        search_start = method_match.end()
        brace_index = scannable_source.find("{", search_start, search_start + 800)
        if brace_index == -1:
            continue
        signature = scannable_source[method_match.start() : brace_index]
        filter_match = _JAVA_FILTER_CHAIN_PARAM_PATTERN.search(signature)
        if filter_match is None:
            continue
        body, end_offset = _scan_java_block(scannable_source, brace_index)
        contexts.append(
            _JavaFilterMethodContext(
                name=method_match.group("name"),
                filter_chain_name=filter_match.group("name"),
                body=body,
                line_range=_match_line_range(scannable_source, method_match.start(), end_offset),
                body_start_line=_match_line_range(
                    scannable_source, brace_index + 1, brace_index + 1
                ).start,
            )
        )
    return tuple(contexts)


def _java_filter_chain_call_pattern(filter_chain_name: str) -> re.Pattern[str]:
    escaped = re.escape(filter_chain_name)
    return re.compile(rf"\b(?P<access>{escaped}\.doFilter)\s*\(")


def _iter_java_auth_filter_fail_open_matches(
    source: str,
) -> tuple[_JavaAuthFilterFailOpenMatch, ...]:
    matches: list[_JavaAuthFilterFailOpenMatch] = []
    for context in _iter_java_filter_method_contexts(source):
        sanitized_body = _strip_java_string_literals(_strip_java_comments(context.body))
        continuation_pattern = _java_filter_chain_call_pattern(context.filter_chain_name)
        for catch_match in _JAVA_BROAD_EXCEPTION_CATCH_PATTERN.finditer(sanitized_body):
            brace_index = sanitized_body.find("{", catch_match.end())
            if brace_index == -1:
                continue
            catch_body, catch_end = _scan_java_block(sanitized_body, brace_index)
            if re.search(r"\b(?:return|throw)\b", catch_body):
                continue
            continuation_match = continuation_pattern.search(sanitized_body, catch_end)
            if continuation_match is None:
                continue
            relative_range = _match_line_range(
                sanitized_body, catch_match.start(), continuation_match.end("access")
            )
            absolute_start = context.body_start_line + relative_range.start - 1
            absolute_stop = context.body_start_line + relative_range.stop - 1
            matches.append(
                _JavaAuthFilterFailOpenMatch(
                    line_range=range(absolute_start, absolute_stop),
                    line_number=absolute_start,
                    catch_type="Exception",
                    continuation_call=continuation_match.group("access"),
                    filter_method=context.name,
                )
            )
    return tuple(matches)


def _iter_java_critical_path_exception_swallowing_matches(
    source: str, *, relative_path: str
) -> tuple[_JavaCriticalPathExceptionSwallowingMatch, ...]:
    scannable_source = _strip_java_comments(source)
    scheduled_methods = {
        context.name for context in _iter_java_scheduled_method_contexts(scannable_source)
    }
    matches: list[_JavaCriticalPathExceptionSwallowingMatch] = []
    for context in _iter_java_method_contexts(scannable_source):
        if not _looks_like_java_critical_path_context(
            relative_path,
            scannable_source,
            method_name=context.name,
            scheduled_methods=scheduled_methods,
        ):
            continue
        scannable_body = _strip_java_string_literals(context.body)
        for catch_match in _JAVA_CATCH_CLAUSE_PATTERN.finditer(scannable_body):
            catch_type = catch_match.group("type").strip()
            if not _is_java_broad_exception_type(catch_type):
                continue
            brace_index = scannable_body.find("{", catch_match.end())
            if brace_index == -1:
                continue
            catch_body, catch_end = _scan_java_block(scannable_body, brace_index)
            suppression_kind = _java_catch_suppression_kind(catch_body)
            if suppression_kind is None:
                continue
            relative_range = _match_line_range(scannable_body, catch_match.start(), catch_end)
            absolute_start = context.body_start_line + relative_range.start - 1
            absolute_stop = context.body_start_line + relative_range.stop - 1
            matches.append(
                _JavaCriticalPathExceptionSwallowingMatch(
                    line_range=range(absolute_start, absolute_stop),
                    line_number=absolute_start,
                    catch_type=catch_type,
                    critical_method=context.name,
                    suppression_kind=suppression_kind,
                )
            )
    return tuple(matches)


def _find_web_layer_value_injection_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if changed_lines is not None and line_number not in changed_lines:
            continue
        if _VALUE_INJECTION_PATTERN.search(line):
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message="Java web-layer surface injects config directly with @Value.",
                    location=FindingLocation(path=relative_path, line=line_number),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Move property resolution into a typed configuration bean or service "
                        "and inject that collaborator into the controller/filter."
                    ),
                    metadata={"access_pattern": "@Value"},
                )
            )
        elif _SYSTEM_GETENV_PATTERN.search(line):
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message="Java web-layer surface reads environment variables directly.",
                    location=FindingLocation(path=relative_path, line=line_number),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Resolve env-backed config in a typed configuration bean instead of "
                        "calling System.getenv(...) inside the web layer."
                    ),
                    metadata={"access_pattern": "System.getenv"},
                )
            )
    return findings


def _find_web_layer_local_file_io_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if changed_lines is not None and line_number not in changed_lines:
            continue
        match = _WEB_LAYER_LOCAL_FILE_IO_PATTERN.search(line)
        if match is None:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message="Java web-layer surface performs local file I/O directly.",
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Move the local file access into a storage/service collaborator and inject "
                    "that into the controller/filter instead of reading files inline."
                ),
                metadata={
                    "access_pattern": re.sub(r"\s+", " ", match.group("access").strip()),
                },
            )
        )
    return findings


def _find_web_layer_concrete_dependency_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    scannable_source = _strip_java_comments(source)
    for match in _WEB_LAYER_CONCRETE_DEPENDENCY_PATTERN.finditer(scannable_source):
        constructor_name = _normalize_java_construction_pattern(match.group("access"))
        if not _shared_looks_like_dependency_boundary_name(constructor_name, outbound_only=False):
            continue
        line_range = _match_line_range(scannable_source, match.start("access"), match.end("access"))
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java web-layer surface constructs concrete dependency "
                    f"'{constructor_name}' inline."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Construct the collaborator in configuration/bootstrap code and inject it "
                    "into the controller/filter instead of instantiating it inline."
                ),
                metadata={"access_pattern": constructor_name},
            )
        )
    return findings


def _find_controller_direct_repository_access_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_controller_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_controller_repository_access_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        if match.access_kind == "repository-injection":
            message = f"Java controller injects repository '{match.repository_type}' directly."
            suggestion = (
                "Inject an application/service collaborator into the controller instead of "
                "wiring a repository into the web layer."
            )
        else:
            message = f"Java controller calls repository access '{match.access_pattern}' directly."
            suggestion = (
                "Route the lookup/write through a service or use-case boundary instead of "
                "calling the repository from controller code."
            )
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=message,
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=suggestion,
                metadata={
                    "access_pattern": match.access_pattern,
                    "repository_type": match.repository_type,
                    "access_kind": match.access_kind,
                },
            )
        )
    return findings


def _find_controller_without_test_class_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    controller_test_index: dict[str, tuple[str, ...]],
) -> list[NormalizedFinding]:
    if not _is_java_controller_path(relative_path, source) or _is_test_java_path(relative_path):
        return []
    if changed_lines is not None and not changed_lines:
        return []

    controller_name, line_number = _java_primary_type_name(source, relative_path)
    if not controller_name.endswith("Controller"):
        return []
    if controller_name in controller_test_index:
        return []

    endpoint_count = len(_iter_java_endpoint_method_contexts(source))
    if endpoint_count < _JAVA_CONTROLLER_ENDPOINT_SURFACE_THRESHOLD:
        return []

    expected_tests = ", ".join(_expected_java_controller_test_patterns(controller_name))
    return [
        NormalizedFinding.from_rule(
            rule,
            message=(
                f"Java controller `{controller_name}` exposes {endpoint_count} mapped endpoints "
                "without a nearby controller test class."
            ),
            location=FindingLocation(path=relative_path, line=line_number),
            adapter_id=adapter_id,
            language=RepoLanguage.JAVA,
            suggestion=(
                "Add a focused controller test or integration test before expanding the endpoint "
                "surface further."
            ),
            metadata={
                "symbol": controller_name,
                "endpoint_count": str(endpoint_count),
                "expected_tests": expected_tests,
            },
        )
    ]


def _find_scheduled_service_without_scheduler_test_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    scheduler_test_index: dict[str, tuple[str, ...]],
) -> list[NormalizedFinding]:
    scheduled_contexts = _iter_java_scheduled_method_contexts(source)
    if not scheduled_contexts:
        return []

    type_name, line_number = _java_primary_type_name(source, relative_path)
    if not _is_java_meaningful_scheduled_service(relative_path, source, type_name=type_name):
        return []
    if changed_lines is not None and not any(
        any(line in changed_lines for line in context.line_range) for context in scheduled_contexts
    ):
        return []
    if type_name in scheduler_test_index:
        return []

    scheduled_methods = ", ".join(context.name for context in scheduled_contexts)
    expected_tests = ", ".join(_expected_java_scheduler_test_patterns(type_name))
    return [
        NormalizedFinding.from_rule(
            rule,
            message=(
                f"Java scheduled service `{type_name}` declares {len(scheduled_contexts)} "
                "@Scheduled method(s) without a scheduler-focused test surface."
            ),
            location=FindingLocation(path=relative_path, line=line_number),
            adapter_id=adapter_id,
            language=RepoLanguage.JAVA,
            suggestion=(
                "Add a focused scheduler test that exercises the scheduled entrypoint/trigger "
                "behavior before expanding background orchestration."
            ),
            metadata={
                "symbol": type_name,
                "scheduled_method_count": str(len(scheduled_contexts)),
                "scheduled_methods": scheduled_methods,
                "expected_tests": expected_tests,
            },
        )
    ]


def _find_service_layer_outbound_client_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    scannable_source = _strip_java_comments(source)
    for match in _SERVICE_LAYER_OUTBOUND_CLIENT_PATTERN.finditer(scannable_source):
        constructor_name = _normalize_java_construction_pattern(match.group("access"))
        if not _shared_looks_like_dependency_boundary_name(constructor_name, outbound_only=True):
            continue
        line_range = _match_line_range(scannable_source, match.start("access"), match.end("access"))
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code constructs outbound client "
                    f"'{constructor_name}' inline."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Wire the outbound collaborator through configuration or constructor "
                    "injection instead of constructing it directly in service/workflow code."
                ),
                metadata={"access_pattern": constructor_name},
            )
        )
    return findings


def _find_service_layer_outbound_timeout_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_service_layer_timeout_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code constructs RestTemplate without explicit timeout "
                    "shaping."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Inject a RestTemplate that already carries request-factory timeout settings, "
                    "or set a request factory with explicit connect/read timeouts before using it "
                    "from service/workflow code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "timeout_kind": match.timeout_kind,
                },
            )
        )
    return findings


def _find_service_layer_tenant_scope_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    repository_contract_index: _JavaRepositoryContractIndex,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_service_layer_tenant_scope_matches(
        source, repository_contract_index=repository_contract_index
    ):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        tenant_lookup_methods = ", ".join(match.tenant_lookup_methods)
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code loads a tenant-owned entity via bare primary-key "
                    f"lookup '{match.access_pattern}' even though repository "
                    f"'{match.repository_type}' exposes tenant-scoped id lookup."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Use the tenant-scoped repository lookup instead of bare findById/"
                    f"getReferenceById (for example: {tenant_lookup_methods})."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "repository_type": match.repository_type,
                    "tenant_lookup_methods": tenant_lookup_methods,
                    "lookup_kind": match.lookup_kind,
                },
            )
        )
    return findings


def _find_unbounded_findall_without_pagination_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []
    if _is_java_bootstrap_or_initializer_context(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_unbounded_findall_matches(source, relative_path=relative_path):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow method "
                    f"`{match.service_method}` calls repository `{match.access_pattern}()` "
                    "without pagination or scoping."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Use a paged/streamed query or a repository method with explicit predicates "
                    "instead of loading the full table through bare findAll()."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "repository_type": match.repository_type,
                    "service_method": match.service_method,
                },
            )
        )
    return findings


def _find_service_layer_transactional_external_io_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_transactional_external_io_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_transactional_external_io_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java transactional service/workflow method "
                    f"'{match.transactional_method}' calls outbound collaborator "
                    f"'{match.access_pattern}' inside the active transaction."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Move the provider/message/storage call to an after-commit or explicitly "
                    "non-transactional boundary instead of performing outbound I/O inside the "
                    "@Transactional method body."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "collaborator_type": match.collaborator_type,
                    "transactional_method": match.transactional_method,
                    "io_kind": match.io_kind,
                },
            )
        )
    return findings


def _find_event_listener_transaction_phase_boundary_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_event_listener_boundary_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java @EventListener method "
                    f"'{match.listener_method}' performs '{match.access_pattern}' "
                    "without an explicit transaction phase boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Use @TransactionalEventListener for an after-commit phase or isolate the "
                    "work in @Transactional(propagation = REQUIRES_NEW) before performing "
                    "writes or write-sensitive orchestration from the listener."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "listener_method": match.listener_method,
                    "write_kind": match.write_kind,
                },
            )
        )
    return findings


def _find_active_artifact_creation_without_idempotency_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_active_artifact_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow method "
                    f"'{match.service_method}' persists a new active artifact via "
                    f"'{match.access_pattern}' without an idempotency guard."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Check the business scope for an existing active artifact before saving, or "
                    "route creation through a durable uniqueness/idempotency boundary."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "service_method": match.service_method,
                    "artifact_guard": match.artifact_guard,
                },
            )
        )
    return findings


def _find_business_uniqueness_without_scope_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_repository_path(relative_path) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_business_uniqueness_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java repository uniqueness helper "
                    f"'{match.repository_method}' checks a business key without tenant or "
                    "business scope."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Add tenant/branch/business scope to the uniqueness query so the check "
                    "matches the database uniqueness boundary."
                ),
                metadata={
                    "repository_method": match.repository_method,
                    "scope_kind": match.scope_kind,
                },
            )
        )
    return findings


def _find_nonadditive_flyway_migration_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for match in _iter_java_flyway_nonadditive_matches(source, relative_path=relative_path):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Changed Flyway migration "
                    f"'{Path(relative_path).name}' performs non-additive '{match.operation_kind}' "
                    "work."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Prefer additive repair migrations that preserve historical Flyway scripts "
                    "instead of destructive schema edits."
                ),
                metadata={
                    "migration_kind": match.migration_kind,
                    "operation_kind": match.operation_kind,
                },
            )
        )
    return findings


def _find_entity_crossing_async_transaction_boundary_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    entity_index: _JavaEntityIndex,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_entity_boundary_matches(source, entity_index=entity_index):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java boundary method "
                    f"'{match.boundary_method}' passes entity '{match.entity_type}' across a "
                    f"'{match.boundary_kind}' boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Pass identifiers or immutable snapshots across @Async and REQUIRES_NEW "
                    "boundaries, then reload the entity inside the new boundary."
                ),
                metadata={
                    "boundary_kind": match.boundary_kind,
                    "boundary_method": match.boundary_method,
                    "entity_type": match.entity_type,
                },
            )
        )
    return findings


def _find_web_layer_service_locator_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_service_locator_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java web-layer surface resolves collaborator through runtime locator "
                    f"access '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Resolve the collaborator in configuration/bootstrap code or constructor "
                    "injection instead of fetching it from a singleton or application context "
                    "inside controller/filter code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "resolution_kind": match.resolution_kind,
                },
            )
        )
    return findings


def _find_web_layer_detached_async_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_detached_async_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java web-layer surface launches detached async work via "
                    f"'{match.access_pattern}' without an explicit cancellation boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Return a caller-visible future/handle or route the work through an "
                    "explicit lifecycle boundary instead of fire-and-forget async launch "
                    "from controller/filter code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "launch_kind": match.launch_kind,
                },
            )
        )
    return findings


def _find_web_layer_async_tenant_context_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_async_tenant_context_gap_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java web-layer async work has tenant-bearing input but "
                    f"'{match.access_pattern}' does not bind TenantContext before execution."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Set and clear TenantContext explicitly inside the async method, or route the "
                    "tenant identity through an explicit request-context wrapper before touching "
                    "tenant-scoped collaborators."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "propagation_kind": match.propagation_kind,
                },
            )
        )
    return findings


def _find_web_layer_async_observability_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_background_observability_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java web-layer async work surfaces outcomes only through local logs via "
                    f"'{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Emit a durable failure/status surface (for example a tracked status record, "
                    "incident/audit event, or metric) instead of relying only on logs inside the "
                    "async boundary."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "observability_kind": match.observability_kind,
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
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_service_locator_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code resolves collaborator through runtime locator "
                    f"access '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Inject the collaborator or pass it through explicit wiring instead of "
                    "pulling it from a singleton or service-locator style API at runtime."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "resolution_kind": match.resolution_kind,
                },
            )
        )
    return findings


def _find_service_layer_direct_tenant_context_mutation_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []
    if _is_java_explicit_tenant_boundary(relative_path, source):
        return []

    balanced_boundary_ranges = _iter_java_balanced_tenant_boundary_ranges(source)
    findings: list[NormalizedFinding] = []
    for match in _iter_java_tenant_context_mutation_matches(source):
        if any(
            line in boundary_range
            for boundary_range in balanced_boundary_ranges
            for line in match.line_range
        ):
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code mutates tenant execution state directly via "
                    f"'{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Move TenantContext binding to an explicit tenant runner, interceptor, or "
                    "other infrastructure boundary instead of mutating it inside service or "
                    "listener orchestration code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "mutation_kind": match.mutation_kind,
                },
            )
        )
    return findings


def _find_scheduler_cross_tenant_iteration_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_batch_or_scheduler_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_scheduled_cross_tenant_iteration_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java scheduled method "
                    f"'{match.scheduled_method}' iterates tenant-scoped work and invokes "
                    f"'{match.access_pattern}' without an explicit tenant-runner/reset boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Wrap each tenant/item dispatch in a tenant runner (for example withTenant/"
                    "runForTenant) or introduce an explicit bind-and-clear boundary before "
                    "calling downstream collaborators from the scheduled loop."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "scheduled_method": match.scheduled_method,
                    "tenant_source": match.tenant_source,
                    "iteration_kind": match.iteration_kind,
                },
            )
        )
    return findings


def _find_service_layer_objectprovider_circular_self_reference_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_lazy_service_provider_matches(source, relative_path=relative_path):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code hides collaborator wiring behind lazy provider "
                    f"access '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Break the circular/hidden dependency with explicit constructor wiring or a "
                    "separate orchestration boundary instead of injecting "
                    f"{match.provider_type}<{match.target_type}> into service code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "provider_kind": match.provider_kind,
                    "provider_type": match.provider_type,
                    "target_type": match.target_type,
                },
            )
        )
    return findings


def _find_concurrentmap_scheduled_unsafe_removal_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_batch_or_scheduler_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_scheduled_concurrentmap_removal_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java scheduled cleanup method "
                    f"'{match.scheduled_method}' removes ConcurrentMap entries inline via "
                    f"'{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Collect keys to remove or use a compare/remove pattern instead of calling "
                    "Iterator.remove() while iterating a ConcurrentMap cleanup loop."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "map_type": match.map_type,
                    "scheduled_method": match.scheduled_method,
                },
            )
        )
    return findings


def _find_static_lock_pool_without_eviction_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if _is_test_java_path(relative_path) or _CONFIGURATION_HINT_PATTERN.search(source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_static_lock_pool_matches(source):
        if changed_lines is not None and not (
            any(line in changed_lines for line in match.line_range)
            or any(line in changed_lines for line in match.declaration_line_range)
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java static lock pool "
                    f"'{match.map_name}' grows per key via '{match.access_pattern}(...)' "
                    "without visible eviction/removal."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Remove per-key locks after release or move the lock pool behind a bounded "
                    "coordinator so the static map cannot grow forever."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "growth_method": match.growth_method,
                    "lock_type": match.lock_type,
                    "map_name": match.map_name,
                    "map_type": match.map_type,
                },
            )
        )
    return findings


def _find_batch_saveall_without_partial_failure_guard_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_batch_or_scheduler_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_batch_saveall_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java batch-oriented method "
                    f"'{match.batch_method}' mutates '{match.collection_name}' and then calls "
                    f"'{match.access_pattern}' without a visible partial-failure guard."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Wrap the saveAll boundary with explicit failure handling or persist in "
                    "smaller guarded units so a batch write does not fail without per-item "
                    "recovery visibility."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "repository_type": match.repository_type,
                    "collection_name": match.collection_name,
                    "batch_method": match.batch_method,
                    "guard_kind": match.guard_kind,
                },
            )
        )
    return findings


def _find_critical_path_exception_swallowing_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not (
        _is_java_batch_or_scheduler_path(relative_path, source)
        or _is_java_service_or_workflow_path(relative_path, source)
    ):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_critical_path_exception_swallowing_matches(
        source, relative_path=relative_path
    ):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java critical-path method "
                    f"`{match.critical_method}` catches broad `{match.catch_type}` and "
                    "suppresses the failure without durable surfacing."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Re-throw the failure or record/publish a durable failure outcome "
                    "(status/audit/incident/dead-letter) before suppressing the exception."
                ),
                metadata={
                    "catch_type": match.catch_type,
                    "critical_method": match.critical_method,
                    "suppression_kind": match.suppression_kind,
                },
            )
        )
    return findings


def _find_web_layer_response_lifecycle_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_response_lifecycle_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java web/filter code writes terminal HTTP response via "
                    f"'{match.access_pattern}' but can still fall through to later request flow."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Return/throw immediately after writing the terminal response, or structure "
                    "the branch so no later filter/interceptor/controller logic can continue on "
                    "that path."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "lifecycle_kind": match.lifecycle_kind,
                },
            )
        )
    return findings


def _find_auth_filter_fail_open_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_auth_filter_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_auth_filter_fail_open_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java auth filter catches broad exceptions but still continues request flow "
                    "via "
                    f"'{match.continuation_call}(...)'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Fail closed on the auth exception path: return/throw after handling the "
                    "error, or send an auth failure response instead of continuing the filter "
                    "chain."
                ),
                metadata={
                    "catch_type": match.catch_type,
                    "continuation_call": match.continuation_call,
                    "filter_method": match.filter_method,
                },
            )
        )
    return findings


def _find_service_layer_detached_async_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_detached_async_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow code launches detached async work via "
                    f"'{match.access_pattern}' without an explicit cancellation boundary."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Return a caller-visible future/handle or route the work through an "
                    "explicit lifecycle boundary instead of fire-and-forget async launch "
                    "from service/workflow code."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "launch_kind": match.launch_kind,
                },
            )
        )
    return findings


def _find_service_layer_async_tenant_context_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_async_tenant_context_gap_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow async work has tenant-bearing input but "
                    f"'{match.access_pattern}' does not bind TenantContext before execution."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Set and clear TenantContext explicitly inside the async method, or route the "
                    "tenant identity through an explicit wrapper before repository/service code "
                    "runs on the async thread."
                ),
                metadata={
                    "access_pattern": match.access_pattern,
                    "propagation_kind": match.propagation_kind,
                },
            )
        )
    return findings


def _find_service_layer_async_observability_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_background_observability_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service/workflow async work surfaces outcomes only through local logs "
                    f"via '{match.access_pattern}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Emit a durable failure/status surface (for example a tracked status record, "
                    "incident/audit event, or metric) instead of relying only on logs inside the "
                    "async boundary."
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
    for match in _SECRET_FALLBACK_PATTERN.finditer(source):
        default_value = match.group("default").strip()
        if "${" in default_value or "#{" in default_value:
            continue
        if not default_value or _shared_looks_like_placeholder(default_value):
            continue
        key = match.group("key").strip()
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
                    "Java @Value placeholder for secret-like property "
                    f"'{key}' embeds a literal fallback value."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Remove the literal secret fallback and source the value from runtime "
                    "configuration or a secret manager."
                ),
                metadata={"property_key": key},
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
    for execution_call in _iter_java_execution_calls(source):
        argument_name = _simple_identifier(execution_call.argument_text)
        source_line_range = execution_call.line_range
        source_line_number = execution_call.line_number
        construction_kind = _dynamic_java_sql_construction_kind(execution_call.argument_text)
        if argument_name is not None:
            assignment = _latest_java_assignment_before(
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
                    "Java SQL execution surface "
                    f"'{execution_call.method}' receives dynamically constructed SQL "
                    f"via {construction_kind}."
                ),
                location=FindingLocation(path=relative_path, line=source_line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
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
    if any(part.lower() in {"test", "tests"} for part in Path(relative_path).parts):
        return []
    findings: list[NormalizedFinding] = []
    for match in _iter_java_external_literal_matches(source):
        if changed_lines is not None and not any(
            line in changed_lines for line in match.line_range
        ):
            continue
        context_label = match.context_name or "literal"
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java config/default surface hardcodes "
                    f"{match.literal_kind} literal via '{context_label}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
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
    if not _is_runtime_java_path(relative_path):
        return []

    findings: list[NormalizedFinding] = []
    for match in _iter_java_sensitive_logging_matches(source):
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
                    f"Java runtime log statement emits raw {descriptor} via "
                    f"'{match.identifier_name}'."
                ),
                location=FindingLocation(path=relative_path, line=match.line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
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


def _collect_dynamic_sql_assignments(source: str) -> dict[str, list[_JavaDynamicSqlSource]]:
    scannable_source = _strip_java_comments(source)
    assignments: dict[str, list[_JavaDynamicSqlSource]] = {}
    for match in _SQL_ASSIGNMENT_PATTERN.finditer(scannable_source):
        name = match.group("decl_name") or match.group("assign_name")
        if name is None:
            continue
        expression_text, expression_end = _scan_java_expression(
            scannable_source,
            match.end(),
            stop_chars=frozenset({";"}),
        )
        if _SQL_KEYWORD_PATTERN.search(_strip_java_comments(expression_text)) is None:
            continue
        construction_kind = _dynamic_java_sql_construction_kind(expression_text)
        name_start = (
            match.start("decl_name")
            if match.group("decl_name") is not None
            else match.start("assign_name")
        )
        line_range = _line_range_for_offsets(scannable_source, name_start, expression_end)
        assignments.setdefault(name, []).append(
            _JavaDynamicSqlSource(
                line_range=line_range,
                line_number=line_range.start,
                construction_kind=construction_kind,
            )
        )
    return assignments


def _iter_java_sensitive_logging_matches(source: str) -> tuple[_JavaSensitiveLoggingMatch, ...]:
    matches: list[_JavaSensitiveLoggingMatch] = []
    for call in _iter_java_log_calls(source):
        if len(call.arguments) <= 1:
            arguments = (
                ()
                if not call.arguments or _is_plain_java_string_literal(call.arguments[0])
                else call.arguments
            )
        else:
            arguments = call.arguments[1:]
        for argument_text in arguments:
            identifier_name, sensitivity_kind = _java_sensitive_logging_identity(argument_text)
            if identifier_name is None or sensitivity_kind is None:
                continue
            matches.append(
                _JavaSensitiveLoggingMatch(
                    log_method=call.method,
                    identifier_name=identifier_name,
                    sensitivity_kind=sensitivity_kind,
                    line_range=call.line_range,
                    line_number=call.line_number,
                )
            )
    return tuple(matches)


def _iter_java_log_calls(source: str) -> tuple[_JavaLogCall, ...]:
    scannable_source = _strip_java_comments(source)
    calls: list[_JavaLogCall] = []
    for match in _JAVA_LOG_CALL_PATTERN.finditer(scannable_source):
        if not _looks_like_java_log_receiver(match.group("receiver")):
            continue
        arguments, call_end = _extract_java_call_arguments(scannable_source, match.end())
        if not arguments:
            continue
        line_range = _match_line_range(scannable_source, match.start("method"), call_end)
        calls.append(
            _JavaLogCall(
                method=match.group("method"),
                arguments=arguments,
                line_range=line_range,
                line_number=line_range.start,
            )
        )
    return tuple(calls)


def _iter_java_execution_calls(source: str) -> tuple[_JavaExecutionCall, ...]:
    scannable_source = _strip_java_comments(source)
    calls: list[_JavaExecutionCall] = []
    for match in _SQL_EXECUTION_PATTERN.finditer(scannable_source):
        argument_text, argument_end = _scan_java_expression(
            scannable_source,
            match.end(),
            stop_chars=frozenset({",", ")"}),
        )
        stripped_argument = argument_text.strip()
        if not stripped_argument:
            continue
        line_range = _line_range_for_offsets(scannable_source, match.start("method"), argument_end)
        calls.append(
            _JavaExecutionCall(
                method=match.group("method"),
                argument_text=stripped_argument,
                line_range=line_range,
                line_number=line_range.start,
            )
        )
    return tuple(calls)


def _dynamic_java_sql_construction_kind(expression_text: str) -> str | None:
    normalized = _strip_java_comments(expression_text)
    if _SQL_KEYWORD_PATTERN.search(normalized) is None:
        return None
    if ".formatted(" in normalized:
        return "String.formatted"
    if "String.format(" in normalized:
        return "String.format"
    stripped = _strip_java_string_literals(normalized)
    if _has_dynamic_java_concatenation(stripped):
        return "string concatenation"
    return None


def _iter_java_external_literal_matches(source: str) -> tuple[_JavaExternalLiteralMatch, ...]:
    matches: list[_JavaExternalLiteralMatch] = []
    for literal_start, literal_end, literal_value in _iter_java_string_literals(source):
        if "${" not in literal_value and "#{" not in literal_value:
            context_name = _java_literal_context_name(source, literal_start - 1)
            literal_kind = _java_external_literal_kind(literal_value, context_name)
            if literal_kind is not None:
                line_range = _match_line_range(source, literal_start, literal_end)
                matches.append(
                    _JavaExternalLiteralMatch(
                        line_range=line_range,
                        line_number=line_range.start,
                        context_name=context_name,
                        literal_kind=literal_kind,
                        literal_value=literal_value,
                    )
                )
    return tuple(matches)


def _java_literal_context_name(source: str, literal_offset: int) -> str | None:
    snippet = source[max(0, literal_offset - 160) : literal_offset]
    assignment_match = re.search(
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*$",
        snippet,
        re.DOTALL,
    )
    if assignment_match is not None:
        return assignment_match.group("name")
    method_match = re.search(r"\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\(\s*$", snippet, re.DOTALL)
    if method_match is not None:
        return method_match.group("name")
    return None


def _java_external_literal_kind(literal_value: str, context_name: str | None) -> str | None:
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


def _iter_java_string_literals(source: str) -> Iterator[tuple[int, int, str]]:
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
        if source.startswith('"""', index):
            index = _advance_java_text_block(source, index + 3)
            continue
        if source[index] == "'":
            index = _advance_java_quoted_literal(source, index + 1, quote="'")
            continue
        if source[index] != '"':
            index += 1
            continue
        literal_start = index + 1
        literal_end = _advance_java_quoted_literal(source, literal_start, quote='"')
        yield literal_start, literal_end, source[literal_start : literal_end - 1]
        index = literal_end


def _normalize_external_context_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _has_dynamic_java_concatenation(expression_text: str) -> bool:
    return bool(
        re.search(r"[A-Za-z0-9_)\]]\s*\+", expression_text)
        or re.search(r"\+\s*[A-Za-z_(]", expression_text)
    )


def _strip_java_comments(source: str) -> str:
    return re.sub(
        r"//.*?$|/\*.*?\*/",
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        source,
        flags=re.MULTILINE | re.DOTALL,
    )


def _strip_java_string_literals(source: str) -> str:
    chunks: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith('"""', index):
            index = _advance_java_text_block(source, index + 3)
            chunks.append(" ")
            continue
        char = source[index]
        if char == '"':
            index = _advance_java_quoted_literal(source, index + 1, quote='"')
            chunks.append(" ")
            continue
        if char == "'":
            index = _advance_java_quoted_literal(source, index + 1, quote="'")
            chunks.append(" ")
            continue
        chunks.append(char)
        index += 1
    return "".join(chunks)


def _scan_java_expression(
    source: str, start_offset: int, *, stop_chars: frozenset[str]
) -> tuple[str, int]:
    index = start_offset
    depth = 0
    while index < len(source):
        if source.startswith('"""', index):
            index = _advance_java_text_block(source, index + 3)
            continue
        char = source[index]
        if char == '"':
            index = _advance_java_quoted_literal(source, index + 1, quote='"')
            continue
        if char == "'":
            index = _advance_java_quoted_literal(source, index + 1, quote="'")
            continue
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


def _extract_java_call_arguments(source: str, start_offset: int) -> tuple[tuple[str, ...], int]:
    current_offset = _skip_java_argument_whitespace(source, start_offset)
    if current_offset < len(source) and source[current_offset] == ")":
        return (), current_offset + 1

    arguments: list[str] = []
    while current_offset < len(source):
        argument_text, argument_end = _scan_java_expression(
            source,
            current_offset,
            stop_chars=frozenset({",", ")"}),
        )
        stripped_argument = argument_text.strip()
        if stripped_argument:
            arguments.append(stripped_argument)
        separator = source[argument_end] if argument_end < len(source) else ""
        if separator == ",":
            current_offset = _skip_java_argument_whitespace(source, argument_end + 1)
            continue
        if separator == ")":
            return tuple(arguments), argument_end + 1
        return tuple(arguments), argument_end
    return tuple(arguments), current_offset


def _skip_java_argument_whitespace(source: str, start_offset: int) -> int:
    index = start_offset
    while index < len(source) and source[index].isspace():
        index += 1
    return index


def _advance_java_text_block(source: str, start_offset: int) -> int:
    end_offset = source.find('"""', start_offset)
    if end_offset == -1:
        return len(source)
    return end_offset + 3


def _advance_java_quoted_literal(source: str, start_offset: int, *, quote: str) -> int:
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


def _is_runtime_java_path(relative_path: str) -> bool:
    path = Path(relative_path)
    if _is_test_java_path(relative_path):
        return False
    markers = {part.lower() for part in path.parts}
    markers.add(path.stem.lower())
    return not any(marker in _RUNTIME_EXCLUDED_PATH_MARKERS for marker in markers)


def _looks_like_java_log_receiver(receiver: str) -> bool:
    tokens = _shared_split_identifier_tokens(receiver.split(".")[-1])
    return any(token in {"log", "logger"} for token in tokens)


def _java_sensitive_logging_identity(expression_text: str) -> tuple[str | None, str | None]:
    if _java_expression_is_masked(expression_text):
        return None, None
    for identifier_name in _iter_java_sensitive_candidate_names(expression_text):
        sensitivity_kind = _shared_sensitive_logging_name_kind(identifier_name)
        if sensitivity_kind is None:
            continue
        return identifier_name, sensitivity_kind
    return None, None


def _iter_java_sensitive_candidate_names(expression_text: str) -> tuple[str, ...]:
    candidates: list[str] = []
    seen: set[str] = set()
    stripped = _strip_java_string_literals(expression_text)
    for identifier in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped):
        if identifier not in seen:
            seen.add(identifier)
            candidates.append(identifier)
    for literal_value in re.findall(r'"([^"\n]+)"', expression_text):
        normalized = literal_value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)
    return tuple(candidates)


def _java_expression_is_masked(expression_text: str) -> bool:
    if re.search(r"\.\s*substring\s*\(", expression_text):
        return True
    stripped = _strip_java_string_literals(expression_text)
    return any(
        _shared_is_masked_sensitive_logging_name(identifier)
        for identifier in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", stripped)
    )


def _is_plain_java_string_literal(expression_text: str) -> bool:
    stripped = expression_text.strip()
    if stripped.startswith('"""'):
        return _advance_java_text_block(stripped, 3) == len(stripped)
    if stripped.startswith('"'):
        return _advance_java_quoted_literal(stripped, 1, quote='"') == len(stripped)
    return False


def _java_primary_type_name(source: str, relative_path: str) -> tuple[str, int]:
    scannable_source = _strip_java_comments(source)
    match = _JAVA_PRIMARY_TYPE_PATTERN.search(scannable_source)
    if match is None:
        return Path(relative_path).stem, 1
    line_number = _match_line_range(scannable_source, match.start("name"), match.end("name")).start
    return match.group("name"), line_number


def _line_range_for_offsets(source: str, start_offset: int, end_offset: int) -> range:
    start_line = source.count("\n", 0, start_offset) + 1
    end_line = source.count("\n", 0, end_offset) + 1
    return range(start_line, end_line + 1)


def _combine_line_ranges(first: range, second: range) -> range:
    start_line = min(first.start, second.start)
    end_line = max(first.stop, second.stop) - 1
    return range(start_line, end_line + 1)


def _latest_java_assignment_before(
    assignments: Sequence[_JavaDynamicSqlSource], line_number: int
) -> _JavaDynamicSqlSource | None:
    candidates = [assignment for assignment in assignments if assignment.line_number <= line_number]
    if not candidates:
        return None
    return max(candidates, key=lambda assignment: assignment.line_number)


def _discover_java_repository_contracts(repo_root: Path) -> _JavaRepositoryContractIndex:
    contracts: list[_JavaRepositoryContract] = []
    for file_path in sorted(repo_root.rglob("*Repository.java")):
        try:
            relative_path = file_path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path) or _is_test_java_path(relative_path):
            continue
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        contract = _java_repository_contract(source, expected_simple_name=file_path.stem)
        if contract is not None:
            contracts.append(contract)

    by_fqcn = {contract.fqcn: contract for contract in contracts}
    by_simple_name: dict[str, list[_JavaRepositoryContract]] = {}
    for contract in contracts:
        by_simple_name.setdefault(contract.simple_name, []).append(contract)
    return _JavaRepositoryContractIndex(
        by_fqcn=by_fqcn,
        by_simple_name={
            simple_name: tuple(resolved_contracts)
            for simple_name, resolved_contracts in by_simple_name.items()
        },
    )


def _discover_java_entity_index(repo_root: Path) -> _JavaEntityIndex:
    by_fqcn: dict[str, str] = {}
    by_simple_name: dict[str, list[str]] = {}
    for file_path in sorted(repo_root.rglob("*.java")):
        try:
            relative_path = file_path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path) or _is_test_java_path(relative_path):
            continue
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scannable_source = _strip_java_comments(source)
        if _JAVA_ENTITY_ANNOTATION_PATTERN.search(scannable_source) is None:
            continue
        simple_name, fqcn = _java_primary_type_name(scannable_source, relative_path)
        by_fqcn[fqcn] = simple_name
        by_simple_name.setdefault(simple_name, []).append(simple_name)
    return _JavaEntityIndex(
        by_fqcn=by_fqcn,
        by_simple_name={
            simple_name: tuple(values) for simple_name, values in by_simple_name.items()
        },
    )


def _expected_java_controller_test_patterns(controller_name: str) -> tuple[str, ...]:
    return tuple(
        f"{controller_name}{suffix}.java" for suffix in _JAVA_CONTROLLER_TEST_CLASS_SUFFIXES
    )


def _expected_java_scheduler_test_patterns(type_name: str) -> tuple[str, ...]:
    candidates = [
        f"{type_name}SchedulingTest.java",
        f"{type_name}SchedulerTest.java",
        f"{type_name}ScheduledTest.java",
        f"{type_name}CronTest.java",
        f"{type_name}TriggerTest.java",
    ]
    if type_name.endswith(("Job", "Processor", "Relay", "Scheduler", "Worker")):
        candidates.extend(
            [f"{type_name}Test.java", f"{type_name}IT.java", f"{type_name}IntegrationTest.java"]
        )
    return tuple(dict.fromkeys(candidates))


def _java_test_stem_without_suffix(stem: str) -> str | None:
    for suffix in ("IntegrationTest", "Test", "IT"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return None


def _java_controller_name_from_test_stem(stem: str) -> str | None:
    base_name = _java_test_stem_without_suffix(stem)
    if base_name is None or not base_name.endswith("Controller"):
        return None
    return base_name


def _java_test_has_scheduler_focus(stem: str, source: str) -> bool:
    return _JAVA_SCHEDULER_TEST_FOCUS_PATTERN.search(f"{stem}\n{source}") is not None


def _java_scheduler_test_subjects(stem: str, source: str) -> tuple[str, ...]:
    base_name = _java_test_stem_without_suffix(stem)
    if base_name is None:
        return ()

    subjects: list[str] = []
    for suffix in _JAVA_SCHEDULER_TEST_FOCUS_SUFFIXES:
        if base_name.endswith(suffix):
            subject_name = base_name[: -len(suffix)]
            if subject_name:
                subjects.append(subject_name)
    if not subjects and _java_test_has_scheduler_focus(stem, source):
        subjects.append(base_name)
    return tuple(dict.fromkeys(subjects))


def _discover_java_controller_test_index(repo_root: Path) -> dict[str, tuple[str, ...]]:
    discovered: dict[str, list[str]] = {}
    for file_path in sorted(repo_root.rglob("*Controller*.java")):
        try:
            relative_path = file_path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path) or not _is_java_test_or_integration_path(relative_path):
            continue
        controller_name = _java_controller_name_from_test_stem(file_path.stem)
        if controller_name is None:
            continue
        discovered.setdefault(controller_name, []).append(relative_path)
    return {
        controller_name: tuple(paths)
        for controller_name, paths in sorted(discovered.items(), key=lambda item: item[0])
    }


def _discover_java_scheduler_test_index(repo_root: Path) -> dict[str, tuple[str, ...]]:
    discovered: dict[str, list[str]] = {}
    for file_path in sorted(repo_root.rglob("*.java")):
        try:
            relative_path = file_path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path) or not _is_java_test_or_integration_path(relative_path):
            continue
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for subject_name in _java_scheduler_test_subjects(file_path.stem, source):
            discovered.setdefault(subject_name, []).append(relative_path)
    return {
        subject_name: tuple(paths)
        for subject_name, paths in sorted(discovered.items(), key=lambda item: item[0])
    }


def _java_repository_contract(
    source: str, *, expected_simple_name: str | None = None
) -> _JavaRepositoryContract | None:
    scannable_source = _strip_java_comments(source)
    package_match = re.search(
        r"^\s*package\s+(?P<name>[A-Za-z0-9_.]+)\s*;",
        scannable_source,
        re.MULTILINE,
    )
    interface_match = None
    for candidate in _JAVA_REPOSITORY_INTERFACE_PATTERN.finditer(scannable_source):
        candidate_name = candidate.group("name")
        if expected_simple_name is not None and candidate_name == expected_simple_name:
            interface_match = candidate
            break
        if interface_match is None and candidate_name.endswith("Repository"):
            interface_match = candidate
    if interface_match is None:
        return None
    tenant_lookup_methods = tuple(
        dict.fromkeys(
            match.group("method")
            for match in _JAVA_TENANT_SCOPED_ID_LOOKUP_PATTERN.finditer(scannable_source)
        )
    )
    if not tenant_lookup_methods:
        return None
    simple_name = interface_match.group("name")
    package_name = package_match.group("name") if package_match is not None else ""
    fqcn = f"{package_name}.{simple_name}" if package_name else simple_name
    return _JavaRepositoryContract(
        simple_name=simple_name,
        fqcn=fqcn,
        tenant_lookup_methods=tenant_lookup_methods,
    )


def _java_repository_field_contracts(
    source: str, *, repository_contract_index: _JavaRepositoryContractIndex
) -> dict[str, _JavaRepositoryContract]:
    import_map = _java_import_map(source)
    field_contracts: dict[str, _JavaRepositoryContract] = {}
    for match in _JAVA_REPOSITORY_FIELD_PATTERN.finditer(source):
        type_text = match.group("type")
        contract = _resolve_java_repository_contract(
            type_text,
            import_map=import_map,
            repository_contract_index=repository_contract_index,
        )
        if contract is None:
            continue
        field_contracts[match.group("name")] = contract
    return field_contracts


def _resolve_java_repository_contract(
    type_text: str,
    *,
    import_map: dict[str, str],
    repository_contract_index: _JavaRepositoryContractIndex,
) -> _JavaRepositoryContract | None:
    simple_name = type_text.rsplit(".", 1)[-1]
    fqcn = type_text if "." in type_text else import_map.get(simple_name)
    if fqcn is not None:
        contract = repository_contract_index.by_fqcn.get(fqcn)
        if contract is not None:
            return contract
    simple_name_matches = repository_contract_index.by_simple_name.get(simple_name, ())
    if len(simple_name_matches) == 1:
        return simple_name_matches[0]
    return None


def _java_import_map(source: str) -> dict[str, str]:
    import_map: dict[str, str] = {}
    for match in _JAVA_IMPORT_PATTERN.finditer(source):
        fqcn = match.group("fqcn")
        simple_name = fqcn.rsplit(".", 1)[-1]
        import_map.setdefault(simple_name, fqcn)
    return import_map


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


def _find_n_plus_one_without_entity_graph_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_repository_path(relative_path):
        return []
    scannable_source = _strip_java_comments(source)
    if not _JAVA_LAZY_ASSOCIATION_PATTERN.search(scannable_source):
        return []
    if _JAVA_ENTITY_GRAPH_PATTERN.search(scannable_source):
        return []
    findings: list[NormalizedFinding] = []
    for method_match in _JAVA_ASYNC_METHOD_PATTERN.finditer(scannable_source):
        search_start = method_match.end()
        brace_index = scannable_source.find("{", search_start, search_start + 800)
        if brace_index == -1:
            continue
        signature = scannable_source[method_match.start() : brace_index]
        if not (
            _JAVA_PAGE_RETURN_PATTERN.search(signature)
            or _JAVA_PAGEABLE_PARAM_PATTERN.search(signature)
        ):
            continue
        line_range = _match_line_range(scannable_source, method_match.start(), method_match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Paginated repository method lacks @EntityGraph or JOIN FETCH "
                    "for lazy associations, risking N+1 queries."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Add @EntityGraph or JOIN FETCH to eagerly load lazy "
                    "associations in paginated queries."
                ),
                metadata={
                    "method_name": method_match.group("name"),
                },
            )
        )
    return findings


def _find_lazy_collection_touch_in_dto_mapping_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        if not _JAVA_DTO_MAPPING_METHOD_PATTERN.search(context.name):
            continue
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_LAZY_COLLECTION_TOUCH_PATTERN.finditer(scannable_body):
            absolute_line_range = _java_absolute_body_line_range(
                context,
                _match_line_range(scannable_body, match.start(), match.end()),
            )
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "DTO mapper touches a lazy-loaded collection, "
                        "which can trigger N+1 or session errors."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Hydrate the collection before mapping or use a "
                        "dedicated fetch query with JOIN FETCH."
                    ),
                    metadata={
                        "access_pattern": match.group(0).strip(),
                        "method_name": context.name,
                    },
                )
            )
    return findings


def _find_cascade_redundant_save_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        added_vars: set[str] = set()
        for add_match in _JAVA_ADD_TO_COLLECTION_PATTERN.finditer(scannable_body):
            added_vars.add(add_match.group(1))
        for save_match in _JAVA_REPOSITORY_SAVE_PATTERN.finditer(scannable_body):
            saved_var = save_match.group(1)
            if saved_var not in added_vars:
                continue
            line_range = _match_line_range(scannable_body, save_match.start(), save_match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Redundant repository.save() on a child already managed by CascadeType.ALL."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Remove the redundant save(); the cascade will "
                        "persist the child automatically."
                    ),
                    metadata={
                        "saved_variable": saved_var,
                        "method_name": context.name,
                    },
                )
            )
    return findings


def _find_requery_uncommitted_state_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        preamble = scannable_source[
            max(0, context.line_range.start - 10) : context.line_range.start
        ]
        has_boundary = _JAVA_TRANSACTIONAL_EVENT_LISTENER_PATTERN.search(
            preamble
        ) or _JAVA_REQUIRES_NEW_PROPAGATION_PATTERN.search(preamble)
        if not has_boundary:
            continue
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_REPOSITORY_QUERY_PATTERN.finditer(scannable_body):
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Re-querying inside a REQUIRES_NEW or "
                        "@TransactionalEventListener boundary may not see "
                        "uncommitted outer state."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Pass the required state from the outer transaction "
                        "instead of re-querying across the boundary."
                    ),
                    metadata={
                        "access_pattern": match.group(0).strip(),
                        "method_name": context.name,
                    },
                )
            )
    return findings


def _find_rollback_only_poisoning_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        if not _JAVA_REQUIRES_NEW_PROPAGATION_PATTERN.search(
            scannable_source[max(0, context.line_range.start - 10) : context.line_range.start]
        ):
            continue
        if not _JAVA_ENHANCED_FOR_LOOP_PATTERN.search(scannable_body):
            continue
        if _JAVA_TRY_PATTERN.search(scannable_body):
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in context.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "REQUIRES_NEW sub-transaction inside a loop without "
                    "try/catch can poison the outer transaction on failure."
                ),
                location=FindingLocation(path=relative_path, line=context.line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Wrap each sub-transaction in a try/catch or move the "
                    "loop body to a separate method with its own boundary."
                ),
                metadata={
                    "method_name": context.name,
                },
            )
        )
    return findings


def _find_async_self_invocation_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    async_methods: set[str] = set()
    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is not None:
            async_methods.add(context_info[0].name)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        if context.name in async_methods:
            continue
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_ASYNC_SELF_INVOCATION_PATTERN.finditer(scannable_body):
            callee = match.group(1)
            if callee not in async_methods:
                continue
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Self-invocation of @Async method `{callee}` "
                        "bypasses the Spring AOP proxy."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Inject the bean or use AopContext to route the call through the proxy."
                    ),
                    metadata={
                        "callee": callee,
                        "caller": context.name,
                    },
                )
            )
    return findings


def _find_payload_build_after_async_boundary_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        context, _ = context_info
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_ENTITY_LAZY_TOUCH_PATTERN.finditer(scannable_body):
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Building a JPA-dependent payload inside @Async "
                        "can access detached or uninitialized entities."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Hydrate the payload before crossing the async "
                        "boundary or reload entities inside the async method."
                    ),
                    metadata={
                        "access_pattern": match.group(0).strip(),
                        "method_name": context.name,
                    },
                )
            )
    for match in _JAVA_DETACHED_ASYNC_PATTERN.finditer(scannable_source):
        lambda_body, line_range = _java_async_lambda_context(scannable_source, match)
        if lambda_body is None or line_range is None:
            continue
        sanitized = _strip_java_string_literals(lambda_body)
        for touch in _JAVA_ENTITY_LAZY_TOUCH_PATTERN.finditer(sanitized):
            touch_range = _match_line_range(sanitized, touch.start(), touch.end())
            absolute_start = line_range.start + touch_range.start - 1
            if changed_lines is not None and absolute_start not in changed_lines:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Building a JPA-dependent payload inside runAsync "
                        "can access detached or uninitialized entities."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Hydrate the payload before crossing the async "
                        "boundary or reload entities inside the async method."
                    ),
                    metadata={
                        "access_pattern": touch.group(0).strip(),
                        "launch_kind": "runAsync",
                    },
                )
            )
    return findings


def _find_async_read_before_commit_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    has_after_commit = _JAVA_AFTER_COMMIT_PATTERN.search(scannable_source)
    for annotation_match in _ASYNC_ANNOTATION_PATTERN.finditer(scannable_source):
        context_info = _java_method_context_for_annotation(scannable_source, annotation_match)
        if context_info is None:
            continue
        context, _ = context_info
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_REPOSITORY_QUERY_PATTERN.finditer(scannable_body):
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            if has_after_commit:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Async work reads DB state before the owning "
                        "transaction commits without afterCommit safety."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Schedule the async read via TransactionSynchronization.afterCommit()."
                    ),
                    metadata={
                        "access_pattern": match.group(0).strip(),
                        "method_name": context.name,
                    },
                )
            )
    for match in _JAVA_DETACHED_ASYNC_PATTERN.finditer(scannable_source):
        lambda_body, line_range = _java_async_lambda_context(scannable_source, match)
        if lambda_body is None or line_range is None:
            continue
        sanitized = _strip_java_string_literals(lambda_body)
        for query in _JAVA_REPOSITORY_QUERY_PATTERN.finditer(sanitized):
            query_range = _match_line_range(sanitized, query.start(), query.end())
            absolute_start = line_range.start + query_range.start - 1
            if changed_lines is not None and absolute_start not in changed_lines:
                continue
            if has_after_commit:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "runAsync reads DB state before the owning "
                        "transaction commits without afterCommit safety."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Schedule the async read via TransactionSynchronization.afterCommit()."
                    ),
                    metadata={
                        "access_pattern": query.group(0).strip(),
                        "launch_kind": "runAsync",
                    },
                )
            )
    return findings


def _find_state_transition_without_pessimistic_lock_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_transactional_method_contexts(scannable_source):
        if not _JAVA_STATE_TRANSITION_METHOD_PATTERN.search(context.name):
            continue
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_FIND_BY_ID_PATTERN.finditer(scannable_body):
            if _JAVA_LOCK_MODE_PATTERN.search(scannable_body):
                continue
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "State transition method loads an aggregate without "
                        "a pessimistic lock, risking lost updates."
                    ),
                    location=FindingLocation(path=relative_path, line=absolute_line_range.start),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Use findByIdForUpdate or add LockModeType.PESSIMISTIC_WRITE to the query."
                    ),
                    metadata={
                        "access_pattern": match.group(0).strip(),
                        "method_name": context.name,
                    },
                )
            )
    return findings


def _find_auth_fallback_to_privileged_user_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if changed_lines is not None and line_number not in changed_lines:
            continue
        match = _JAVA_AUTH_FALLBACK_PATTERN.search(line)
        if match is None:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Auth fallback defaults to a privileged/system user without explicit scoping."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Remove the privileged fallback or gate it behind "
                    "explicit role checks and audit logging."
                ),
                metadata={
                    "access_pattern": match.group(0).strip(),
                },
            )
        )
    return findings


def _find_notification_channel_split_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        if not _JAVA_PUSH_NOTIFICATION_PATTERN.search(scannable_body):
            continue
        if _JAVA_IN_APP_NOTIFICATION_PATTERN.search(scannable_body):
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in context.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "PUSH notification is sent without a corresponding "
                    "IN_APP copy, breaking channel parity."
                ),
                location=FindingLocation(path=relative_path, line=context.line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Also save an in-app notification or send the in-app copy alongside the push."
                ),
                metadata={
                    "method_name": context.name,
                },
            )
        )
    return findings


def _find_retry_without_reexecution_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        if not _JAVA_RETRY_LOOP_PATTERN.search(scannable_body):
            continue
        if not _JAVA_STATUS_SETTER_PATTERN.search(scannable_body):
            continue
        has_external_call = bool(
            re.search(
                r"\b(?:restTemplate|webClient|httpClient|kafkaTemplate|"
                r"feignClient|grpc)\b",
                scannable_body,
                re.IGNORECASE,
            )
        )
        if has_external_call:
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in context.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Retry loop only resets status without re-executing the target operation."
                ),
                location=FindingLocation(path=relative_path, line=context.line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Re-invoke the external or internal operation inside "
                    "the retry loop, not just the status setter."
                ),
                metadata={
                    "method_name": context.name,
                },
            )
        )
    return findings


def _find_lob_bytea_mismatch_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for match in _JAVA_LOB_BYTEA_PATTERN.finditer(source):
        line_range = _match_line_range(source, match.start(), match.end())
        if changed_lines is not None and not any(line in changed_lines for line in line_range):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "@Lob on byte[] without @JdbcTypeCode(Types.VARBINARY) "
                    "risks OID vs bytea mismatch on PostgreSQL."
                ),
                location=FindingLocation(path=relative_path, line=line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Add @JdbcTypeCode(Types.VARBINARY) to the byte[] field "
                    "or verify the target column type."
                ),
                metadata={
                    "access_pattern": "@Lob byte[]",
                },
            )
        )
    return findings


def _find_duplicate_flyway_migration_version_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    context: AdapterContext,
) -> list[NormalizedFinding]:
    if not _is_flyway_migration_path(relative_path):
        return []
    java_match = _JAVA_FLYWAY_VERSION_PATTERN.match(Path(relative_path).name)
    if java_match is None:
        return []
    version = java_match.group(1)
    findings: list[NormalizedFinding] = []
    for other_path in _candidate_java_files(context, requested_rule_ids=()):
        if other_path == relative_path:
            continue
        if not other_path.endswith(".sql"):
            continue
        sql_match = _JAVA_FLYWAY_VERSION_PATTERN.match(Path(other_path).name)
        if sql_match is None:
            continue
        if sql_match.group(1) == version:
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Flyway version V{version} is used by both a Java and SQL migration."
                    ),
                    location=FindingLocation(path=relative_path, line=1),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Use distinct version numbers for Java and SQL "
                        "migrations to avoid Flyway collisions."
                    ),
                    metadata={
                        "version": version,
                        "collision_with": other_path,
                    },
                )
            )
    return findings


def _find_file_upload_without_validation_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_web_layer_path(relative_path, source) or _is_test_java_path(relative_path):
        return []
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for context in _iter_java_endpoint_method_contexts(scannable_source):
        signature = scannable_source[context.line_range.start : context.line_range.start + 400]
        if not _JAVA_MULTIPART_FILE_PATTERN.search(signature):
            continue
        scannable_body = _strip_java_string_literals(context.body)
        if _JAVA_FILE_VALIDATION_PATTERN.search(scannable_body):
            continue
        if changed_lines is not None and not any(
            line in changed_lines for line in context.line_range
        ):
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=("Multipart upload endpoint lacks size or MIME type validation."),
                location=FindingLocation(path=relative_path, line=context.line_range.start),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Add @Size/maxSize constraints and validate the "
                    "MediaType before processing the file."
                ),
                metadata={
                    "method_name": context.name,
                },
            )
        )
    return findings


def _skip_java_whitespace(source: str, index: int) -> int:
    length = len(source)
    while index < length and source[index] in " \t\n\r":
        index += 1
    return index


def _read_java_string_literal(source: str, index: int) -> tuple[str, int] | None:
    """Read a Java string or text block starting at index. Returns (body, next_index)."""

    if index >= len(source):
        return None
    if source.startswith('"""', index):
        end = source.find('"""', index + 3)
        if end < 0:
            return None
        return source[index + 3 : end], end + 3
    quote = source[index]
    if quote not in {'"', "'"}:
        return None
    chars: list[str] = []
    cursor = index + 1
    while cursor < len(source):
        char = source[cursor]
        if char == "\\":
            if cursor + 1 >= len(source):
                break
            chars.append(source[cursor + 1])
            cursor += 2
            continue
        if char == quote:
            return "".join(chars), cursor + 1
        chars.append(char)
        cursor += 1
    return None


def _read_java_identifier_name(source: str, index: int) -> tuple[str, str, int] | None:
    match = _JAVA_IDENTIFIER_PATTERN.match(source, index)
    if match is None:
        return None
    parts = [match.group(0)]
    cursor = match.end()
    while True:
        dotted = _skip_java_whitespace(source, cursor)
        if dotted >= len(source) or source[dotted] != ".":
            break
        dotted = _skip_java_whitespace(source, dotted + 1)
        nxt = _JAVA_IDENTIFIER_PATTERN.match(source, dotted)
        if nxt is None:
            break
        parts.append(nxt.group(0))
        cursor = nxt.end()
    return parts[-1], ".".join(parts), cursor


def _read_concat_string_expr(
    source: str, index: int, constants: dict[str, str]
) -> tuple[str, int] | None:
    pieces: list[str] = []
    position = _skip_java_whitespace(source, index)
    while True:
        position = _skip_java_whitespace(source, position)
        lit = _read_java_string_literal(source, position)
        if lit is not None:
            chunk, position = lit
            pieces.append(chunk)
        else:
            ident = _read_java_identifier_name(source, position)
            if ident is None:
                break
            simple, dotted, position = ident
            if simple in _JAVA_QUERY_EXPRESSION_KEYWORDS:
                break
            resolved = constants.get(dotted) or constants.get(simple)
            if resolved is not None:
                pieces.append(resolved)
        position = _skip_java_whitespace(source, position)
        if position < len(source) and source[position] == "+":
            position += 1
            continue
        break
    if not pieces:
        return None
    return "".join(pieces), position


def _collect_java_string_constants(source: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    matches = list(_JAVA_STRING_CONSTANT_PREFIX.finditer(source))
    for _ in range(len(matches) + 1):
        changed = False
        for match in matches:
            expr = _read_concat_string_expr(source, match.end(), constants)
            if expr is None:
                continue
            body, _ = expr
            name = match.group(1)
            if constants.get(name) != body:
                constants[name] = body
                changed = True
        if not changed:
            break
    return constants


def _discover_java_string_constants(repo_root: Path) -> dict[str, str]:
    constants: dict[str, str] = {}
    for file_path in sorted(repo_root.rglob("*.java")):
        try:
            relative_path = file_path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if _should_skip_path(relative_path):
            continue
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scannable_source = _strip_java_comments(source)
        local = _collect_java_string_constants(scannable_source)
        if not local:
            continue
        type_name, _ = _java_primary_type_name(scannable_source, relative_path)
        for name, body in local.items():
            constants[name] = body
            constants[f"{type_name}.{name}"] = body
    return constants


def _iter_java_query_literal_bodies(
    source: str, extra_constants: dict[str, str] | None = None
) -> tuple[tuple[str, int], ...]:
    """Yield concatenated @Query bodies, including same-file and repo string constants."""

    constants = dict(extra_constants or {})
    constants.update(_collect_java_string_constants(source))
    bodies: list[tuple[str, int]] = []
    for match in _JAVA_QUERY_ANNOTATION_PREFIX.finditer(source):
        expr = _read_concat_string_expr(source, match.end(), constants)
        if expr is None:
            continue
        body, _ = expr
        if body:
            bodies.append((body, match.start()))
    return tuple(bodies)


def _find_jpql_null_or_lower_on_optional_filter_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
    extra_constants: dict[str, str] | None = None,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    seen_lines: set[int] = set()
    for query_body, start in _iter_java_query_literal_bodies(
        scannable_source, extra_constants
    ):
        if not _JAVA_JPQL_NULL_OR_LOWER_PATTERN.search(query_body):
            continue
        line_number = scannable_source.count("\n", 0, start) + 1
        if line_number in seen_lines:
            continue
        if changed_lines is not None and line_number not in changed_lines:
            continue
        seen_lines.add(line_number)
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "JPQL optional filter combines `:param IS NULL OR` with LOWER; "
                    "prefer empty-string sentinels (`:param = ''`)."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Replace NULL checks with empty-string sentinels and avoid "
                    "LOWER on nullable optional parameters."
                ),
                metadata={"matched_pattern": "jpql-null-or-lower-optional-filter"},
            )
        )
    return findings


def _find_readonly_transactional_on_composite_read_service_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    scannable_source = _strip_java_comments(source)
    if not _JAVA_REPOSITORY_WRITE_CALL_PATTERN.search(scannable_source):
        return []

    findings: list[NormalizedFinding] = []
    for annotation_match in _TRANSACTIONAL_ANNOTATION_PATTERN.finditer(scannable_source):
        annotation_args = annotation_match.group("args") or ""
        if not _JAVA_TRANSACTIONAL_READ_ONLY_PATTERN.search(annotation_args):
            continue
        line_number = scannable_source.count("\n", 0, annotation_match.start()) + 1
        if changed_lines is not None and line_number not in changed_lines:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java service uses @Transactional(readOnly=true) while also performing "
                    "repository write operations in the same file."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Split read-only and write paths into separate transactional boundaries, or "
                    "remove readOnly=true from methods/classes that mutate persisted state."
                ),
                metadata={"matched_pattern": "readonly-transactional-with-repository-writes"},
            )
        )
    return findings


def _find_transactional_event_listener_requires_phase_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if _is_test_java_path(relative_path):
        return []

    scannable_source = _strip_java_comments(source)
    findings: list[NormalizedFinding] = []
    for annotation_match in _TRANSACTIONAL_EVENT_LISTENER_WITH_ARGS_PATTERN.finditer(
        scannable_source
    ):
        annotation_args = annotation_match.group("args") or ""
        if re.search(r"\bphase\s*=", annotation_args):
            continue
        line_number = scannable_source.count("\n", 0, annotation_match.start()) + 1
        if changed_lines is not None and line_number not in changed_lines:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Java @TransactionalEventListener is missing an explicit phase= attribute."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Set phase explicitly, typically TransactionPhase.AFTER_COMMIT, so listener "
                    "timing is deliberate and reviewable."
                ),
                metadata={"matched_pattern": "transactional-event-listener-missing-phase"},
            )
        )
    return findings


def _find_requires_new_self_invocation_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    if not _is_java_service_or_workflow_path(relative_path, source):
        return []

    scannable_source = _strip_java_comments(source)
    transactional_methods: dict[str, bool] = {}
    for annotation_match in _TRANSACTIONAL_ANNOTATION_PATTERN.finditer(scannable_source):
        method_context = _java_transactional_method_context(scannable_source, annotation_match)
        if method_context is None:
            continue
        annotation_args = annotation_match.group("args") or ""
        transactional_methods[method_context.name] = bool(
            _JAVA_REQUIRES_NEW_PROPAGATION_PATTERN.search(annotation_args)
        )

    if len(transactional_methods) < 2:
        return []
    if not any(is_requires_new for is_requires_new in transactional_methods.values()):
        return []

    findings: list[NormalizedFinding] = []
    for context in _iter_java_method_contexts(scannable_source):
        scannable_body = _strip_java_string_literals(context.body)
        for match in _JAVA_ASYNC_SELF_INVOCATION_PATTERN.finditer(scannable_body):
            callee = match.group(1)
            if callee not in transactional_methods:
                continue
            line_range = _match_line_range(scannable_body, match.start(), match.end())
            absolute_line_range = _java_absolute_body_line_range(context, line_range)
            if changed_lines is not None and not any(
                line in changed_lines for line in absolute_line_range
            ):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Self-invocation of @Transactional method `{callee}` bypasses the "
                        "Spring proxy in a class that also uses REQUIRES_NEW boundaries."
                    ),
                    location=FindingLocation(
                        path=relative_path, line=absolute_line_range.start
                    ),
                    adapter_id=adapter_id,
                    language=RepoLanguage.JAVA,
                    suggestion=(
                        "Inject the bean or route calls through a collaborator so "
                        "REQUIRES_NEW and other transactional attributes are honored."
                    ),
                    metadata={
                        "matched_pattern": "requires-new-transactional-self-invocation",
                        "caller": context.name,
                        "callee": callee,
                        "callee_requires_new": str(transactional_methods[callee]),
                    },
                )
            )
    return findings


def _find_transactional_coalescing_for_long_running_work_findings(
    *,
    source: str,
    relative_path: str,
    changed_lines: frozenset[int] | None,
    rule,
    adapter_id: str,
) -> list[NormalizedFinding]:
    scannable_source = _strip_java_comments(source)
    if not _JAVA_DISPATCH_COALESCING_TRANSACTIONAL_PATTERN.search(scannable_source):
        return []
    if not _JAVA_EVENT_LISTENER_CONTEXT_PATTERN.search(scannable_source):
        return []
    findings: list[NormalizedFinding] = []
    for match in _JAVA_DISPATCH_COALESCING_TRANSACTIONAL_PATTERN.finditer(scannable_source):
        line_number = scannable_source.count("\n", 0, match.start()) + 1
        if changed_lines is not None and line_number not in changed_lines:
            continue
        findings.append(
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Transactional event listener uses dispatchCoalescingTransactional for work "
                    "that may include long IO; prefer dispatchCoalescing outside the transaction."
                ),
                location=FindingLocation(path=relative_path, line=line_number),
                adapter_id=adapter_id,
                language=RepoLanguage.JAVA,
                suggestion=(
                    "Switch to dispatchCoalescing(...) in after-commit handlers for OCR or "
                    "other long-running external work."
                ),
                metadata={"matched_pattern": "transactional-coalescing-long-running-work"},
            )
        )
    return findings


DEFAULT_ADAPTERS = (JavaAdapter(),)
