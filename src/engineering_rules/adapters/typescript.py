"""TypeScript / React adapter for high-confidence diff-first rules."""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import FindingLocation, NormalizedFinding, RepoLanguage
from ..registry import create_default_registry

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from ..engine import AdapterContext
    from ..registry import RuleDefinition

_TS_RULE_IDS = (
    "typescript.correctness.no-unsafe-any-boundary",
    "typescript.correctness.no-falsy-default-for-numeric-zero",
    "typescript.correctness.no-unvalidated-numeric-precision",
    "typescript.correctness.no-unvalidated-url-tab-param",
    "typescript.maintainability.unused-exported-surface",
    "typescript.maintainability.no-oversized-ui-module",
    "typescript.maintainability.no-oversized-support-module",
    "typescript.maintainability.no-console-in-production-browser-code",
    "typescript.react.no-use-effect",
    "typescript.react.no-unstable-sync-external-store-snapshot",
    "typescript.react.no-mixed-controlled-uncontrolled",
    "typescript.react.query-key-registry",
    "typescript.react.mutation-requires-cache-invalidation",
    "typescript.react.polled-query-requires-placeholder-data",
    "typescript.react.no-websocket-reconnect-after-unmount",
    "typescript.testing.no-interactive-page-without-tests",
    "typescript.accessibility.no-icon-only-button-without-accessible-name",
    "typescript.accessibility.modal-focus-trap",
    "typescript.accessibility.no-number-input-without-wheel-blur",
    "typescript.web.no-raw-transport-calls",
    "typescript.web.no-direct-response-casting",
    "typescript.web.route-manifest-centralization",
    "typescript.web.route-access-policy-centralization",
    "typescript.web.route-family-literal-consistency",
    "typescript.web.route-query-codec-centralization",
    "typescript.web.no-window-confirm",
    "typescript.web.no-hard-browser-navigation",
    "typescript.web.no-direct-browser-storage",
    "typescript.web.no-modal-controller-bypass",
    "typescript.web.no-query-cache-mutation-outside-cache-module",
    "typescript.web.no-unguarded-async-mutation-ui",
    "typescript.web.no-local-status-variant-map",
    "typescript.web.no-raw-semantic-tailwind-status-classes",
    "typescript.web.no-semantic-status-hex-literals",
    "typescript.web.no-manual-multipart-headers",
    "typescript.web.no-ephemeral-ids-for-deep-linking",
    "typescript.web.no-unauthenticated-image-blob-urls",
    "typescript.web.no-client-api-url-in-server-backend-fetch",
    "typescript.security.no-raw-error-in-error-boundary",
    "typescript.security.no-unvalidated-external-href",
    "typescript.reliability.no-concurrent-token-refresh",
    "typescript.reliability.no-module-level-throwing-side-effect",
    "typescript.reliability.no-formdata-for-raw-binary-upload",
    "typescript.reliability.no-unbounded-buffer-without-chunking",
    "typescript.performance.no-eager-heavy-dependency-import",
    "typescript.architecture.no-inline-filter-logic-in-components",
    "typescript.ui.no-raw-color-literals",
    "typescript.ui.avoid-fixed-tokenless-layout-values",
    "typescript.ui.no-orphaned-effect-intervals",
    "typescript.ui.no-orphaned-effect-timeouts",
    "typescript.ui.avoid-raw-readability-colors",
    "typescript.ui.no-low-contrast-readability-pairings",
    "typescript.ui.risky-status-badge-contrast",
)
_TS_SUFFIXES = {".ts", ".tsx"}
_SKIP_DIRS = {
    ".git",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
}
_SKIP_UNUSED_EXPORT_BASENAMES = {
    "default.tsx",
    "error.tsx",
    "index.ts",
    "index.tsx",
    "layout.tsx",
    "loading.tsx",
    "middleware.ts",
    "not-found.tsx",
    "page.tsx",
    "route.ts",
    "route.tsx",
    "template.tsx",
}
_EXPORT_PATTERN = re.compile(
    r"(?m)^export\s+(?:(?P<default>default)\s+)?"
    r"(?P<kind>async\s+function|function|const|class|interface|type|enum)\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
)
_ANY_CAST_PATTERN = re.compile(r"\bas\s+any\b")
_DOUBLE_CAST_PATTERN = re.compile(r"\bas\s+unknown\s+as\s+[A-Za-z_$({\[]")
_ANY_BOUNDARY_PATTERN = re.compile(r"(:\s*any\b|\([^)]*\bany\b[^)]*\)|=>\s*any\b)")
_RECORD_UNKNOWN_PATTERN = re.compile(r"\bRecord\s*<\s*string\s*,\s*unknown\s*>\b")
_RECORD_BOUNDARY_PATTERN = re.compile(
    r"(:\s*Record\s*<\s*string\s*,\s*unknown\s*>"
    r"(?![A-Za-z0-9_$])"
    r"|\([^)]*Record\s*<\s*string\s*,\s*unknown\s*>(?![A-Za-z0-9_$])[^)]*\)"
    r"|=>\s*Record\s*<\s*string\s*,\s*unknown\s*>(?![A-Za-z0-9_$]))"
)
_STYLE_SHEET_CREATE_PATTERN = re.compile(r"\bStyleSheet\.create\s*\(")
_INLINE_STYLE_OBJECT_PATTERN = re.compile(r"\b(?:style|[A-Za-z0-9_]*Style)\s*=\s*\{\s*(\{)")
_STYLE_OBJECT_KEY_PATTERN = re.compile(r"\b(?:style|[A-Za-z0-9_]*Style)\s*:\s*(\{)")
_INLINE_STYLE_ARRAY_PATTERN = re.compile(r"\b(?:style|[A-Za-z0-9_]*Style)\s*=\s*\{\s*(\[)")
_STYLE_OBJECT_VALUE_PATTERN = re.compile(r":\s*(\{)")
_STYLE_ARRAY_OBJECT_PATTERN = re.compile(r"(?:\[\s*|,\s*|&&\s*|\?\s*|:\s*)(\{)")
_RAW_COLOR_LITERAL_PATTERN = re.compile(
    r"(?P<property>\b(?:color|[A-Za-z0-9_]*Color)\b)\s*:\s*"
    r"(?P<quote>['\"])(?P<value>(?:#[0-9A-Fa-f]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)))(?P=quote)"
)
_COLOR_LITERAL_VALUE_PATTERN = r"(?:#[0-9A-Fa-f]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\))"
_STYLE_COLOR_ASSIGNMENT_PATTERN = re.compile(
    rf"(?P<property>\b(?:color|tintColor|backgroundColor)\b)\s*:\s*"
    rf"(?P<value>(?:['\"]{_COLOR_LITERAL_VALUE_PATTERN}['\"]|"
    r"colors(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+(?:\s*\+\s*['\"][0-9A-Fa-f]{2}['\"])?|"
    r"[A-Z_][A-Z0-9_]*(?:\s*\+\s*['\"][0-9A-Fa-f]{2}['\"])?))"
)
_LOCAL_COLOR_CONSTANT_PATTERN = re.compile(
    rf"(?m)^(?:export\s+)?const\s+(?P<name>[A-Z_][A-Z0-9_]*)\s*=\s*"
    rf"(?P<quote>['\"])(?P<value>{_COLOR_LITERAL_VALUE_PATTERN})(?P=quote)\s*;?"
)
_THEME_COLORS_EXPORT_PATTERN = re.compile(r"\bexport\s+const\s+colors\s*=\s*\{")
_THEME_OBJECT_START_PATTERN = re.compile(r"(?P<key>[A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*\{\s*,?\s*$")
_THEME_VALUE_PATTERN = re.compile(
    rf"(?P<key>[A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*"
    rf"(?P<quote>['\"])(?P<value>{_COLOR_LITERAL_VALUE_PATTERN})(?P=quote)\s*,?\s*$"
)
_UI_LAYOUT_PROPERTY_NAMES = (
    "padding",
    "paddingTop",
    "paddingRight",
    "paddingBottom",
    "paddingLeft",
    "paddingHorizontal",
    "paddingVertical",
    "margin",
    "marginTop",
    "marginRight",
    "marginBottom",
    "marginLeft",
    "marginHorizontal",
    "marginVertical",
    "gap",
    "rowGap",
    "columnGap",
    "borderRadius",
    "fontSize",
    "lineHeight",
    "letterSpacing",
    "width",
    "height",
    "minWidth",
    "maxWidth",
    "minHeight",
    "maxHeight",
    "shadowRadius",
    "elevation",
)
_FIXED_LAYOUT_LITERAL_PATTERN = re.compile(
    rf"(?P<property>\b(?:{'|'.join(re.escape(name) for name in _UI_LAYOUT_PROPERTY_NAMES)})\b)"
    r"\s*:\s*(?P<value>-?\d+(?:\.\d+)?)\b"
)
_LIFECYCLE_HOOK_PATTERN = re.compile(r"\b(?P<hook>useEffect|useFocusEffect)\s*\(")
_LIFECYCLE_CALLBACK_BODY_PATTERN = re.compile(
    r"(?:\buseCallback\s*\(\s*)?"
    r"(?:(?:async\s*)?\([^)]*\)\s*=>|function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\))"
    r"\s*(?P<body>\{)"
)
_LIFECYCLE_CLEANUP_RETURN_PATTERN = re.compile(
    r"\breturn\s+"
    r"(?:(?:async\s*)?\([^)]*\)\s*=>|function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\))\s*"
)
_LIFECYCLE_CLEANUP_IDENTIFIER_RETURN_PATTERN = re.compile(
    r"\breturn\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*;?"
)
_LIFECYCLE_TIMER_ASSIGNMENT_PATTERN = re.compile(
    r"(?:(?:const|let|var)\s+)?(?P<handle>[A-Za-z_$][A-Za-z0-9_$]*(?:\.current)?)\s*=\s*"
    r"(?P<call>setInterval|setTimeout)\s*\("
)
_RAW_FETCH_CALL_PATTERN = re.compile(r"(?<![A-Za-z0-9_$.])fetch\s*\(")
_RAW_AXIOS_CALL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$.])axios(?:\.(?:request|get|post|put|patch|delete|head|options|create))?\s*\("
)
_DIRECT_RESPONSE_JSON_CAST_PATTERN = re.compile(
    r"\.json\s*\(\s*\)\s+as\s+(?P<type>[A-Z][A-Za-z0-9_$<>,. \t\[\]|&?(){}:]*)"
)
_TYPED_RESPONSE_JSON_ASSIGNMENT_PATTERN = re.compile(
    r"(?m)^\s*(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*"
    r"(?P<type>[A-Z][A-Za-z0-9_$<>,.\s\[\]|&?(){}:]*)\s*=\s*"
    r"(?:await\s+)?[A-Za-z_$][A-Za-z0-9_$.()]*\.json\s*\(\s*\)"
)
_WINDOW_CONFIRM_CALL_PATTERN = re.compile(r"\bwindow\.confirm\s*\(")
_GLOBAL_CONFIRM_CALL_PATTERN = re.compile(r"(?<![A-Za-z0-9_$.])confirm\s*\(")
_CONFIRM_SHADOW_SIGNAL_PATTERN = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var|function|class|interface|type|enum)\s+confirm\b"
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+\{[^}]*\bconfirm\b[^}]*\}\s*="
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+\[[^\]]*\bconfirm\b[^\]]*\]\s*="
    r"|^\s*import\s+(?:type\s+)?\{[^}]*\bconfirm\b[^}]*\}\s+from\b"
    r"|^\s*import\s+confirm\b"
    r"|\bfunction(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\bconfirm\b[^)]*\)"
    r"|\([^)]*\bconfirm\b[^)]*\)\s*=>",
    re.MULTILINE,
)
_WINDOW_LOCATION_CALL_PATTERN = re.compile(
    r"\bwindow\.location\.(?P<method>reload|replace|assign)\s*\("
)
_WINDOW_LOCATION_ASSIGNMENT_PATTERN = re.compile(
    r"\bwindow\.location(?P<property>\.href)?\s*=\s*(?![=])"
)
_DIRECT_BROWSER_STORAGE_PATTERN = re.compile(
    r"\b(?:(?:window\.)?(?P<storage>localStorage|sessionStorage))\s*\.\s*"
    r"(?P<operation>getItem|setItem|removeItem|clear|key)\s*\("
)
_MODAL_DOCUMENT_KEYDOWN_PATTERN = re.compile(
    r"\bdocument\.(?:addEventListener|removeEventListener)\s*\(\s*['\"]keydown['\"]"
)
_BODY_SCROLL_LOCK_ASSIGNMENT_PATTERN = re.compile(
    r"\bdocument\.body\.style\.overflow\s*=\s*['\"]hidden['\"]"
)
_QUERY_CACHE_MUTATION_PATTERN = re.compile(
    r"\b(?P<receiver>"
    r"useQueryClient\s*\(\s*\)"
    r"|(?:this\.)?(?:[A-Za-z_$][A-Za-z0-9_$]*QueryClient|queryClient)"
    r")\s*(?:\?\.|\.)\s*(?P<method>setQueryData|setQueriesData)\s*\("
)
_QUERY_HOOK_CALL_PATTERN = re.compile(
    r"\b(?P<hook>use(?:Query|Queries|SuspenseQuery|InfiniteQuery|SuspenseInfiniteQuery))\s*\("
)
_QUERY_CACHE_KEY_OPERATION_PATTERN = re.compile(
    r"\b(?P<receiver>"
    r"useQueryClient\s*\(\s*\)"
    r"|(?:this\.)?(?:[A-Za-z_$][A-Za-z0-9_$]*QueryClient|queryClient)"
    r")\s*(?:\?\.|\.)\s*(?P<method>"
    r"setQueryData|setQueriesData|invalidateQueries|refetchQueries|removeQueries|"
    r"resetQueries|cancelQueries"
    r")\s*\("
)
_QUERY_KEY_PROPERTY_PATTERN = re.compile(r"\bqueryKey\s*:\s*")
_INLINE_QUERY_KEY_ARRAY_PATTERN = re.compile(r"\bqueryKey\s*:\s*\[")
_MUTATION_KEY_PROPERTY_PATTERN = re.compile(r"\bmutationKey\s*:\s*\[")
_MUTATION_DECLARATION_PATTERN = re.compile(
    r"(?m)^\s*(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*useMutation\s*\("
)
_MUTATION_CACHE_INVALIDATION_PATTERN = re.compile(
    r"\b(?:invalidateQueries|setQueryData|setQueriesData|refetchQueries)\s*\("
    r"|(?:queryClient|useQueryClient\s*\(\s*\))\s*(?:\?\.|\.)\s*"
    r"(?:invalidateQueries|setQueryData|setQueriesData|refetchQueries)\s*\("
)
_REFETCH_INTERVAL_PATTERN = re.compile(r"\brefetchInterval\s*:")
_PLACEHOLDER_DATA_PATTERN = re.compile(r"\b(?:placeholderData|keepPreviousData)\s*:")
_CANARY_HEADING_ROLE_SELECTOR_PATTERN = re.compile(
    r"\bgetByRole\s*\(\s*['\"]heading['\"]"
)
_CANARY_HEADING_LOCATOR_PATTERN = re.compile(
    r"\blocator\s*\(\s*['\"]h[12][^'\"]*['\"]"
)
_ENCLOSING_FUNCTION_PATTERN = re.compile(
    r"(?m)(?:^|\n)\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{"
    r"|(?:^|\n)\s*(?:export\s+)?const\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"
)
_SEMANTIC_STATUS_HELPER_DECLARATION_PATTERN = re.compile(
    r"(?m)^\s*(?:export\s+)?(?:const|let|var|function)\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
)
_SEMANTIC_STATUS_COLOR_LITERAL_PATTERN = re.compile(
    r"(?P<quote>['\"])(?P<value>(?:#[0-9A-Fa-f]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)))(?P=quote)"
)
_SEMANTIC_TAILWIND_STATUS_CLASS_TOKEN_PATTERN = re.compile(
    r"\b(?:bg|text|border|ring|fill|stroke|from|to)-"
    r"(?:red|rose|orange|amber|yellow|green|emerald|lime|blue|sky)-"
    r"\d{2,3}\b"
)
_SEMANTIC_TAILWIND_STATUS_CLASS_PATTERN = re.compile(
    r"(?P<quote>['\"`])(?P<classes>[^'\"`\n]*"
    r"\b(?:bg|text|border|ring|fill|stroke|from|to)-"
    r"(?:red|rose|orange|amber|yellow|green|emerald|lime|blue|sky)-"
    r"\d{2,3}\b[^'\"`\n]*)(?P=quote)"
)
_INTERACTIVE_PAGE_STATE_SIGNAL_PATTERN = re.compile(
    r"\buse(?:State|Reducer|Transition|Optimistic|FormState)\s*\("
)
_INTERACTIVE_PAGE_QUERY_SIGNAL_PATTERN = re.compile(
    r"\buse(?:Query|Queries|SuspenseQuery|InfiniteQuery|SuspenseInfiniteQuery)\s*\("
)
_INTERACTIVE_PAGE_MUTATION_SIGNAL_PATTERN = re.compile(r"\buseMutation\s*\(")
_INTERACTIVE_PAGE_EVENT_SIGNAL_PATTERN = re.compile(r"\bon[A-Z][A-Za-z0-9_]*\s*=")
_NEARBY_PAGE_IMPORT_PATTERN = re.compile(r"from\s+['\"](?:\./|\.\./)+page(?:\.tsx)?['\"]")
_IMPORT_STATEMENT_PATTERN = re.compile(
    r"(?ms)^\s*import\s+(?P<clause>.+?)\s+from\s+['\"](?P<source>[^'\"\n]+)['\"]\s*;?"
)
_HOOK_CALL_PATTERN = re.compile(r"\b(?P<hook>use[A-Z][A-Za-z0-9_]*)\s*\(")
_REACT_MEMBER_USE_EFFECT_PATTERN_TEMPLATE = r"\b{alias}\s*\.\s*useEffect\s*\("
_REACT_DIRECT_USE_EFFECT_PATTERN_TEMPLATE = r"(?<![A-Za-z0-9_$.]){alias}\s*\("
_REACT_MEMBER_USE_SYNC_EXTERNAL_STORE_PATTERN_TEMPLATE = (
    r"\b{alias}\s*\.\s*useSyncExternalStore\s*\("
)
_REACT_DIRECT_USE_SYNC_EXTERNAL_STORE_PATTERN_TEMPLATE = r"(?<![A-Za-z0-9_$.]){alias}\s*\("
_ICON_LIBRARY_IMPORT_PATTERN = re.compile(
    r"(?ms)^\s*import\s+(?P<clause>.+?)\s+from\s+['\"](?P<source>"
    r"(?:lucide-react|@heroicons/[^'\"]+|react-icons(?:/[^'\"]+)?|phosphor-react|"
    r"@radix-ui/react-icons|@mui/icons-material(?:/[^'\"]+)?)"
    r")['\"]\s*;?"
)
_DIRECT_API_IMPORT_PATTERN = re.compile(
    r"(?ms)^\s*import\s+(?:type\s+)?(?:[^;]|\n)+?\s+from\s+['\"]"
    r"(?P<source>@/lib/(?:(?:api(?:/[^'\"\n]+)?)|(?:[^'\"\n]+/)*client))['\"]\s*;?"
)
_BUTTON_ELEMENT_PATTERN = re.compile(
    r"<button(?P<attrs>[^>]*)>(?P<body>.*?)</button>",
    re.DOTALL,
)
_ACCESSIBLE_NAME_ATTRIBUTE_PATTERN = re.compile(r"\baria-label(?:ledby)?\s*=")
_HIDDEN_ELEMENT_ATTRIBUTE_PATTERN = re.compile(
    r"\b(?:hidden\b|aria-hidden\s*=\s*(?:\{?\s*)?['\"]?true['\"]?)"
)
_GENERIC_ICON_COMPONENT_PATTERN = re.compile(r"<\s*[A-Z][A-Za-z0-9_$]*Icon\b")
_UI_RULE_EXCLUDED_PARTS = {"__mocks__", "__tests__", "theme"}
_UI_RULE_EXCLUDED_SUFFIXES = (".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")
_LIFECYCLE_RULE_EXCLUDED_PARTS = {*_UI_RULE_EXCLUDED_PARTS, "services"}
_UI_MODULE_SURFACE_PARTS = {"app", "components", "features", "pages", "screen", "screens"}
_UI_MODULE_ROUTE_BASENAMES = {
    "default.tsx",
    "error.tsx",
    "layout.tsx",
    "loading.tsx",
    "page.tsx",
    "template.tsx",
}
_UI_MODULE_CODE_LINE_THRESHOLD = 300
_UI_ROUTE_MODULE_CODE_LINE_THRESHOLD = 350
_SUPPORT_MODULE_SURFACE_PARTS = {
    "helper",
    "helpers",
    "lib",
    "libs",
    "type",
    "types",
    "util",
    "utils",
}
_SUPPORT_MODULE_FILENAME_TOKENS = ("helper", "helpers", "type", "types", "util", "utils")
_SUPPORT_MODULE_CODE_LINE_THRESHOLD = 350
_SUPPORT_TYPE_MODULE_CODE_LINE_THRESHOLD = 450
_INTERACTIVE_PAGE_CODE_LINE_THRESHOLD = 120
_HOOK_HEAVY_PAGE_HOOK_COUNT_THRESHOLD = 12
_HOOK_HEAVY_PAGE_DISTINCT_HOOK_THRESHOLD = 6
_PAGE_DIRECT_API_IMPORT_THRESHOLD = 3
_ALLOWED_LAYOUT_LITERALS = {"0", "0.0"}
_READABILITY_FOREGROUND_PROPERTIES = {"color", "tintColor"}
_LOW_CONTRAST_BLOCKING_THRESHOLD = 3.0
_RISKY_STATUS_ALPHA_THRESHOLD = 0.4
_WEB_BOUNDARY_EXCLUDED_PARTS = {
    "__mocks__",
    "__tests__",
    "cypress",
    "e2e",
    "fixtures",
    "mocks",
    "storybook",
    "test",
    "tests",
}
_WEB_BOUNDARY_EXCLUDED_SUFFIXES = (
    ".stories.ts",
    ".stories.tsx",
    ".test.ts",
    ".test.tsx",
    ".spec.ts",
    ".spec.tsx",
)
_REACT_STACK_EXCLUDED_PARTS = {
    "__mocks__",
    "__tests__",
    "cypress",
    "e2e",
    "fixtures",
    "mocks",
    "storybook",
    "test",
    "tests",
}
_REACT_STACK_EXCLUDED_SUFFIXES = (
    ".stories.ts",
    ".stories.tsx",
    ".test.ts",
    ".test.tsx",
    ".spec.ts",
    ".spec.tsx",
)
_WEB_BOUNDARY_SURFACE_PARTS = {"app", "components", "features", "hooks", "pages", "store", "stores"}
_WEB_BOUNDARY_SURFACE_BASENAMES = {
    "default.tsx",
    "error.tsx",
    "layout.tsx",
    "loading.tsx",
    "page.tsx",
    "page.ts",
}
_WEB_TRANSPORT_LAYER_PARTS = {"api", "apis", "http", "network", "transport"}
_WEB_TRANSPORT_SERVICE_PARTS = {"service", "services"}
_WEB_TRANSPORT_FILENAME_TOKENS = ("client", "fetcher", "http", "request", "transport")
_WEB_TRANSPORT_CLIENT_CO_TOKENS = {"api", "fetch", "http", "request", "transport"}
_WEB_NORMALIZATION_LAYER_PARTS = {
    "codec",
    "codecs",
    "decoder",
    "decoders",
    "mapper",
    "mappers",
    "normalizer",
    "normalizers",
    "parser",
    "parsers",
    "schema",
    "schemas",
    "validation",
    "validator",
    "validators",
}
_WEB_NORMALIZATION_FILENAME_TOKENS = (
    "codec",
    "decode",
    "mapper",
    "normalize",
    "parser",
    "schema",
    "validator",
)
_DIALOG_BOUNDARY_REQUIRED_TOKENS = (
    frozenset({"confirm", "dialog"}),
    frozenset({"alert", "dialog"}),
    frozenset({"modal"}),
)
_DIALOG_BOUNDARY_COMPONENT_SIGNAL_PATTERN = re.compile(
    r"\b(?:AlertDialog|ConfirmDialog|Dialog(?:Content|Description|Footer|Header|Title|Trigger)?|Modal)\b"
)
_WEB_HELPER_CONTAINER_PARTS = {"lib", "libs", "service", "services", "util", "utils"}
_NAVIGATION_BOUNDARY_HELPER_TOKENS = {
    "api",
    "auth",
    "guard",
    "navigation",
    "redirect",
    "router",
    "session",
}
_ROUTER_IMPORT_SIGNAL_PATTERN = re.compile(
    r"from\s+['\"](?:next/navigation|next/router|react-router|react-router-dom)['\"]"
)
_ROUTER_USAGE_SIGNAL_PATTERN = re.compile(
    r"\b(?:useRouter|useNavigate|usePathname|router\.(?:push|replace)|navigate\s*\(|"
    r"history\.(?:push|replace)\s*\(|redirect\s*\()"
)
_STORAGE_BOUNDARY_HELPER_TOKENS = {"api", "auth", "session", "storage", "token"}
_WEB_QUERY_CACHE_SURFACE_PARTS = {"app", "components", "pages"}
_QUERY_CACHE_BOUNDARY_CONTAINER_PARTS = {"cache", "caches"}
_QUERY_CACHE_BOUNDARY_FILENAME_HINTS = ("cache", "invalidation", "invalidate")
_WEB_SEMANTIC_HELPER_CONTAINER_PARTS = {
    "design-system",
    "lib",
    "libs",
    "util",
    "utils",
}
_WEB_SEMANTIC_HELPER_FILENAME_TOKENS = {
    "alert",
    "badge",
    "severity",
    "status",
    "tone",
    "variant",
    "variants",
}
_WEB_SEMANTIC_TOKEN_CONTAINER_PARTS = {
    "design-system",
    "styles",
    "theme",
    "themes",
    "token",
    "tokens",
}
_SEMANTIC_STATUS_PATH_TOKENS = {"alert", "badge", "severity", "status", "tone"}
_SEMANTIC_STATUS_SUBJECT_TOKENS = {"alert", "badge", "severity", "status"}
_SEMANTIC_STATUS_DESCRIPTOR_TOKENS = {
    "class",
    "classes",
    "color",
    "colors",
    "lookup",
    "map",
    "palette",
    "tone",
    "tones",
    "variant",
    "variants",
}
_SEMANTIC_STATUS_CONTEXT_PATTERN = re.compile(
    r"\b(?:status|badge|alert|severity|tone)\b"
    r"|\b(?:status|badge|alert|severity|tone)(?=[A-Z])"
    r"|[A-Za-z_$][A-Za-z0-9_$]*(?:Status|Badge|Alert|Severity|Tone)[A-Za-z0-9_$]*"
    r"|<(?:Badge|Alert)\b"
)
_ROUTE_CONTRACT_EXCLUDED_PARTS = _WEB_BOUNDARY_EXCLUDED_PARTS
_ROUTE_CONTRACT_EXCLUDED_SUFFIXES = _WEB_BOUNDARY_EXCLUDED_SUFFIXES
_ROUTE_CONTRACT_SURFACE_PARTS = _WEB_BOUNDARY_SURFACE_PARTS
_ROUTE_CONTRACT_SURFACE_BASENAMES = {
    *_WEB_BOUNDARY_SURFACE_BASENAMES,
    "middleware.ts",
    "middleware.tsx",
}
_ROUTE_MANIFEST_PATH_PARTS = {"nav", "navigation", "routing", "routes"}
_ROUTE_MANIFEST_FILENAME_TOKENS = ("manifest", "nav", "navigation", "route", "routes")
_ROUTE_MANIFEST_SHARED_NAV_TOKENS = {"layout", "sidebar"}
_ROUTE_ACCESS_POLICY_FILENAME_TOKENS = (
    "access",
    "auth",
    "paths",
    "policy",
    "protected",
    "public",
    "route",
    "routes",
)
_ROUTE_ACCESS_POLICY_REQUIRED_TOKENS = (
    frozenset({"public", "path"}),
    frozenset({"public", "paths"}),
    frozenset({"public", "route"}),
    frozenset({"public", "routes"}),
    frozenset({"access", "policy"}),
    frozenset({"route", "policy"}),
    frozenset({"auth", "path"}),
    frozenset({"auth", "paths"}),
    frozenset({"auth", "route"}),
    frozenset({"auth", "routes"}),
)
_ROUTE_MANIFEST_ENTRY_PATTERN = re.compile(
    r"\b(?:href|path|pathname|to)\s*:\s*(?P<quote>['\"`])(?P<route>/[^'\"`\n]+)(?P=quote)"
)
_EXPORTED_ROUTE_COLLECTION_PATTERN = re.compile(
    r"\bexport\s+const\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*\["
)
_ROOT_ROUTE_LITERAL_PATTERN = re.compile(r"(?P<quote>['\"`])(?P<route>/[^'\"`\n]+)(?P=quote)")
_ROUTE_QUERY_CODEC_REQUIRED_TOKENS = (
    frozenset({"codec", "route"}),
    frozenset({"codec", "query"}),
    frozenset({"codec", "search"}),
    frozenset({"codec", "param"}),
)
_ROUTE_QUERY_CODEC_SIGNAL_PATTERN = re.compile(
    r"\b(?:safeParse|parse)\s*\(|\bz\s*\.\s*object\s*\(",
    re.IGNORECASE,
)
_ROUTE_PARAM_ACCESS_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$.])(?P<source>params|context\.params)\s*\??\.\s*"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
)
_SEARCH_PARAM_ACCESS_PATTERN = re.compile(
    r"\b(?P<source>useSearchParams\s*\(\s*\)|searchParams|request\.nextUrl\.searchParams)"
    r"\s*\??\.\s*get\s*\(",
    re.IGNORECASE,
)
_INLINE_ROUTE_POLICY_COLLECTION_PATTERN = re.compile(
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+Set\s*\()?\["
)
_PATHNAME_ROUTE_CHECK_PATTERN = re.compile(
    r"(?:pathname|location\.pathname|router\.pathname|request\.nextUrl\.pathname)"
    r"[^;\n]{0,80}?(?:===|!==|startsWith\s*\()\s*"
    r"(?:\(?\s*)?(?P<quote>['\"`])(?P<route>/[^'\"`\n]+)(?P=quote)"
)
_SCOPE_ROUTE_CONTEXT_PATTERN = re.compile(r"\b(?:href|push|replace|redirect|pathname|route)\b")
_ROUTE_CONTRACT_SCOPE_TOKENS = {
    "branch",
    "branches",
    "org",
    "orgs",
    "organization",
    "organizations",
    "owner",
    "owners",
    "scope",
    "scopes",
    "tenant",
    "tenants",
    "workspace",
    "workspaces",
}
_SCOPE_GUARD_TOKENS = {"branch", "owner", "scope", "tenant", "workspace"}
_ROUTE_GUARD_FILENAME_TOKENS = ("guard", "scope", "branch", "tenant", "owner")
_ROUTE_GUARD_SIGNAL_PATTERN = re.compile(
    r"\b(?:pathname|usePathname|router\.(?:push|replace)|redirect|unauthorized|forbidden)\b"
)
_SERVER_ROUTE_BASENAMES = {"route.ts", "route.tsx"}
_TENANT_CONTEXT_ALLOWED_BASENAMES = {
    "middleware.ts",
    "middleware.tsx",
    "provider.tsx",
    "providers.tsx",
}
_TENANT_CONTEXT_ALLOWED_CONTAINER_PARTS = {
    "bootstrap",
    "context",
    "contexts",
    "provider",
    "providers",
}
_TENANT_ROUTE_HELPER_PATTERN = re.compile(
    r"\b(?P<name>(?:resolve|get|derive|extract|load|parse)[A-Za-z0-9_$]*"
    r"Tenant(?:Id|Slug)[A-Za-z0-9_$]*)\s*\("
)
_TENANT_REQUEST_HEADER_PATTERN = re.compile(
    r"(?P<expr>(?:\bheaders\s*\(\)|\b(?:request|req)\.headers)\s*\.\s*get\s*\(\s*"
    r"(?P<quote>['\"`])(?:x[-_])?tenant(?:[-_ ]?(?:id|slug))?(?P=quote)\s*\))",
    re.IGNORECASE,
)
_TENANT_SEARCH_PARAM_PATTERN = re.compile(
    r"(?P<expr>(?:\b(?:request|req)\.nextUrl\.searchParams|\bsearchParams)\s*\.\s*get\s*\(\s*"
    r"(?P<quote>['\"`])tenant(?:[-_ ]?(?:id|slug))?(?P=quote)\s*\))",
    re.IGNORECASE,
)
_TENANT_ROUTE_PARAM_PATTERN = re.compile(
    r"(?P<expr>\b(?:params|context\.params)\s*\??\.\s*tenant(?:Id|Slug)?)",
    re.IGNORECASE,
)
_AUTHENTICATED_TENANT_EXPRESSION = (
    r"(?:session|auth|claims|current(?:Tenant|User)|user|viewer|identity|account|tenantContext)"
    r"(?:\s*\??\.\s*[A-Za-z_$][A-Za-z0-9_$]*){0,4}\s*\??\.\s*tenant(?:Id|Slug)?"
)
_ROUTE_TENANT_VALUE_EXPRESSION = r"(?:[A-Za-z_$][A-Za-z0-9_$]*Tenant(?:Id|Slug)|tenant(?:Id|Slug)?)"
_AUTHENTICATED_TENANT_SIGNAL_PATTERN = re.compile(
    _AUTHENTICATED_TENANT_EXPRESSION,
    re.IGNORECASE,
)
_AUTHENTICATED_TENANT_CROSSCHECK_PATTERN = re.compile(
    rf"(?:{_AUTHENTICATED_TENANT_EXPRESSION}[^;\n]{{0,120}}(?:===|!==)[^;\n]{{0,120}}"
    rf"{_ROUTE_TENANT_VALUE_EXPRESSION}|{_ROUTE_TENANT_VALUE_EXPRESSION}"
    rf"[^;\n]{{0,120}}(?:===|!==)[^;\n]{{0,120}}{_AUTHENTICATED_TENANT_EXPRESSION})",
    re.IGNORECASE,
)
_TENANT_ACCESS_GUARD_CALL_PATTERN = re.compile(
    r"\b(?:assert|authorize|check|ensure|guard|require|validate|verify)"
    r"[A-Za-z0-9_$]*(?:Tenant|Isolation|Access|Scope)[A-Za-z0-9_$]*\s*\(",
    re.IGNORECASE,
)
_TENANT_ACCESS_GUARD_WITH_AUTH_AND_ROUTE_PATTERN = re.compile(
    r"\b(?:assert|authorize|check|ensure|guard|require|validate|verify)"
    r"[A-Za-z0-9_$]*(?:Tenant|Isolation|Access|Scope)[A-Za-z0-9_$]*\s*\("
    r"(?=[^)\n;]{0,240}\b(?:session|auth|claims|currentTenant|currentUser|user|viewer|identity|"
    r"account|tenantContext)\b)"
    r"(?=[^)\n;]{0,240}\b(?:[A-Za-z_$][A-Za-z0-9_$]*Tenant(?:Id|Slug)|tenant(?:Id|Slug)?)\b)"
    r"[^)\n;]{0,240}\)",
    re.IGNORECASE,
)
_DIRECT_JWT_LIBRARY_CALL_PATTERN = re.compile(
    r"\b(?P<receiver>jwt|jsonwebtoken)\s*\.\s*(?P<method>decode|verify)\s*\(",
    re.IGNORECASE,
)
_ATOB_JWT_PAYLOAD_PATTERN = re.compile(
    r"\batob\s*\(\s*[^)\n;]*\.split\s*\(\s*(?P<quote>['\"`])\.(?P=quote)\s*\)\s*"
    r"\[\s*1\s*\][^)\n;]*\)",
    re.IGNORECASE,
)
_DIRECT_JWT_TENANT_DESTRUCTURE_PATTERN = re.compile(
    r"\b(?:const|let|var)\s*\{\s*tenant(?:Id|Slug)?\s*(?::\s*[A-Za-z_$][A-Za-z0-9_$]*)?\s*\}"
    r"\s*=\s*[^;\n]*(?:\b(?:jwt|jsonwebtoken)\s*\.\s*(?:decode|verify)\s*\(|"
    r"\bJSON\.parse\s*\(\s*atob\s*\()",
    re.IGNORECASE,
)
_DIRECT_JWT_TENANT_INLINE_ACCESS_PATTERN = re.compile(
    r"(?:\b(?:jwt|jsonwebtoken)\s*\.\s*(?:decode|verify)\s*\(|"
    r"\bJSON\.parse\s*\(\s*atob\s*\()[^;\n]{0,160}\.tenant(?:Id|Slug)?\b",
    re.IGNORECASE,
)
_DIRECT_JWT_PAYLOAD_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r"[^;\n]*(?:\b(?:jwt|jsonwebtoken)\s*\.\s*(?:decode|verify)\s*\(|"
    r"\bJSON\.parse\s*\(\s*atob\s*\()",
    re.IGNORECASE,
)
_AUTH_COOKIE_READ_PATTERN = re.compile(
    r"\b(?:cookies\s*\(\)|(?:request|req)\.cookies)\s*\.\s*get\s*\(\s*"
    r"(?P<quote>['\"`])(?:auth|access|id|jwt|session|token)[^'\"`\n]*(?P=quote)\s*\)",
    re.IGNORECASE,
)
_TENANT_BOOTSTRAP_GLOBAL_PATTERN = re.compile(
    r"\b(?:window|globalThis)\s*\.\s*__[_A-Za-z0-9$]*tenant[_A-Za-z0-9$]*\b",
    re.IGNORECASE,
)
_HOST_TENANT_RESOLUTION_SIGNAL_PATTERN = re.compile(
    r"\b(?:window|location)\.hostname\b"
    r"|\b(?:headers\s*\(\)|(?:request|req)\.headers)\s*\.\s*get\s*\(\s*['\"`]host['\"`]\s*\)"
    r"|\bnew\s+URL\s*\([^)]*\)\.hostname\b",
    re.IGNORECASE,
)
_TENANT_FROM_HOST_HELPER_PATTERN = re.compile(
    r"\b(?:resolve|get|derive|extract|load|parse|read)[A-Za-z0-9_$]*Tenant"
    r"[A-Za-z0-9_$]*FromHost\b|\btenant[A-Za-z0-9_$]*FromHost\b",
    re.IGNORECASE,
)
_TENANT_SNAPSHOT_IDENTIFIER_PATTERN = re.compile(
    r"\b[_A-Za-z0-9$]*tenant[_A-Za-z0-9$]*(?:snapshot|bootstrap|initial)[_A-Za-z0-9$]*\b",
    re.IGNORECASE,
)
_FALSY_NUMERIC_DEFAULT_PATTERN = re.compile(r"\|\|\s*(?P<default>0|-?\d+(?:\.\d+)?)\b")
_MIXED_CONTROLLED_DEFAULT_EDGES_PATTERN = re.compile(r"\bdefaultEdges\b")
_MIXED_CONTROLLED_SET_EDGES_PATTERN = re.compile(r"\bsetEdges\b")
_MIXED_CONTROLLED_DEFAULT_VALUE_PATTERN = re.compile(r"\bdefaultValue\b")
_MIXED_CONTROLLED_VALUE_ONCHANGE_PATTERN = re.compile(
    r"\bvalue\b.*\bonChange\b|\bonChange\b.*\bvalue\b"
)
_MIXED_CONTROLLED_DEFAULT_CHECKED_PATTERN = re.compile(r"\bdefaultChecked\b")
_MIXED_CONTROLLED_CHECKED_ONCHANGE_PATTERN = re.compile(
    r"\bchecked\b.*\bonChange\b|\bonChange\b.*\bchecked\b"
)
_MANUAL_MULTIPART_HEADER_PATTERN = re.compile(
    r"['\"]Content-Type['\"]\s*:\s*['\"]multipart/form-data['\"]",
    re.IGNORECASE,
)
_FORMDATA_CONSTRUCT_PATTERN = re.compile(r"\bnew\s+FormData\s*\(")
_MODAL_COMPONENT_NAME_PATTERN = re.compile(
    r"(?:Modal|Dialog|Drawer|Popover)",
    re.IGNORECASE,
)
_FOCUS_TRAP_SIGNAL_PATTERN = re.compile(
    r"\buseFocusTrap\b|\bfocusable\b|\bhandleKeyDown\b|\bonKeyDown\b.*\bTab\b|\bTab\b.*\bonKeyDown\b",
    re.IGNORECASE,
)
_ERROR_BOUNDARY_FILE_PATTERN = re.compile(r"(?:error(?:[-_]?boundary)?|global[-_]?error)")
_RAW_ERROR_EXPRESSION_PATTERN = re.compile(r"\{\s*error\s*\.\s*(?:message|stack)\s*\}")
_UNVALIDATED_EXTERNAL_HREF_PATTERN = re.compile(
    r"<a\b[^>]*\bhref\s*=\s*\{(?![^}]*(?:validate|sanitize|isAllowed|whitelist|ensureHttp))[^}]*\}"
)
_REFRESH_TOKEN_CALL_PATTERN = re.compile(r"\brefreshToken\s*\(")
_AXIOS_INTERCEPTOR_SIGNAL_PATTERN = re.compile(
    r"\baxios\b.*\binterceptors\b|\binterceptors\b.*\baxios\b"
)
_IS_REFRESHING_GUARD_PATTERN = re.compile(r"\bisRefreshing\b")
_HEAVY_DEPENDENCY_IMPORT_PATTERN = re.compile(
    r"(?ms)^\s*import\s+(?P<clause>.+?)\s+from\s+['\"](?P<source>"
    r"jsqr|pdf-lib|chart\.js|@react-pdf/[^'\"]*|xlsx|jspdf|html2canvas|mammoth|"
    r"fabric|konva|three|lodash|moment|date-fns|@date-io/[^'\"]*|"
    r"recharts|echarts|plotly\.js|d3|@d3/[^'\"]*|"
    r"zxcvbn|bcryptjs|argon2|crypto-js|"
    r"tensorflow|@tensorflow/[^'\"]*|onnxruntime|"
    r"opencv|tesseract\.js|sharp|ffmpeg|"
    r"@ffmpeg/[^'\"]*|wavesurfer\.js|howler|tone"
    r")['\"]\s*;?"
)
_GRAND_TOTAL_SUBTRACTION_PATTERN = re.compile(
    r"\b(?:grandTotal|grand_total|total|totalAmount|total_amount)\s*-\s*[^;\n]+",
    re.IGNORECASE,
)
_INVOICE_ESTIMATE_FILE_PATTERN = re.compile(r"(?:invoice|estimate|quote|billing|breakdown|totals)")
_EPHEMERAL_ID_PATTERN = re.compile(r"\b(?:uid\s*\(|crypto\.randomUUID\s*\(\)|useId\s*\(\))")
_DEEP_LINK_FILE_PATTERN = re.compile(
    r"(?:link|deeplink|deep-link|url|query|param|router|navigation)"
)
_CONSOLE_CALL_PATTERN = re.compile(r"\bconsole\s*\.\s*(?:log|warn|error|info|debug|trace)\s*\(")
_SHARED_INPUT_COMPONENT_PATTERN = re.compile(
    r"\b(?:React\s*\.\s*)?forwardRef\s*<|\b(?:function|const)\s+Input\b|\bexport\s+\{\s*Input\s*\}"
)
_HTML_INPUT_ELEMENT_PATTERN = re.compile(r"<\s*input\b")
_NUMBER_INPUT_TYPE_LITERAL_PATTERN = re.compile(
    r"""type\s*=\s*(?:\{\s*['"]number['"]\s*\}|['"]number['"])""",
    re.IGNORECASE,
)
_NUMBER_INPUT_DYNAMIC_TYPE_PATTERN = re.compile(r"""type\s*=\s*\{\s*type\s*\}""")
_NUMBER_INPUT_WHEEL_BLUR_GUARD_PATTERN = re.compile(
    r"shouldBlurNumberInputOnWheel|onWheel\s*=|onWheel\s*\{|onWheel\s*\(|\.blur\s*\("
)
_SERVER_API_CLIENT_URL_PATTERN = re.compile(
    r"\bbuildClientApiUrl\b|\bprocess\.env\.NEXT_PUBLIC_API_URL\b|\bNEXT_PUBLIC_API_URL\b"
)
_SERVER_BACKEND_URL_HELPER_DEFINITION_PATTERN = re.compile(
    r"\bfunction\s+getServerBackendApiBaseUrl\b|\bfunction\s+buildServerBackendApiUrl\b"
)
_NUMERIC_INPUT_PATTERN = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]number['\"][^>]*>",
    re.IGNORECASE,
)
_NUMERIC_PRECISION_VALIDATION_PATTERN = re.compile(
    r"\btoFixed\b|\bprecision\b|\bstep\b|\bmaxDecimals\b|\bdecimalPlaces\b",
    re.IGNORECASE,
)
_IMAGE_SRC_INTERPOLATION_PATTERN = re.compile(
    r"<(?:img|Image)\b[^>]*\bsrc\s*=\s*\{[`'\"][^`'\"]*\$\{[^}]+\}[^`'\"]*[`'\"]\}"
)
_USEMEMO_FILTER_PATTERN = re.compile(r"\buseMemo\s*\(\s*\(\s*\)\s*=>\s*[^\n]*\.\s*filter\s*\(")
_TAB_PARAM_READ_PATTERN = re.compile(
    r"(?:searchParams|params|router\.query|query)\s*\??\.\s*(?:get\s*\(\s*['\"]tab['\"]\s*\)|tab)",
    re.IGNORECASE,
)
_TAB_ALLOWLIST_CHECK_PATTERN = re.compile(
    r"VALID_TABS\b.*\bincludes\b|\bincludes\s*\(\s*.*tab|\btab\b.*\bincludes",
    re.IGNORECASE,
)
_MODULE_LEVEL_THROWING_PATTERN = re.compile(
    r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*(?:new\s+[A-Z][A-Za-z0-9_$]*\s*\(|(?:loadConfig|loadEnv|initClient|createClient|bootstrap|initialize)\s*\()"
)
_S3_UPLOAD_URL_PATTERN = re.compile(
    r"['\"]https?://[^'\"]*s3[.-][^'\"]*['\"]|['\"]https?://[^'\"]*amazonaws\.com[^'\"]*['\"]",
    re.IGNORECASE,
)
_PUT_METHOD_PATTERN = re.compile(
    r"\.(?:put|upload)\s*\(",
    re.IGNORECASE,
)
_UNBOUNDED_BUFFER_PUSH_PATTERN = re.compile(
    r"\b(?:telemetry|audio|video|metrics|events|logs|records|items|chunks)[\s\S]{0,240}\.\s*push\s*\("
)
_WEBSOCKET_ONCLOSE_PATTERN = re.compile(
    r"\bws\b.*\b\.onclose\b|\bonclose\b.*\bws\b|\bsocket\b.*\bonclose\b|\bonclose\b.*\bsocket\b"
)
_MOUNTED_REF_GUARD_PATTERN = re.compile(r"\bmountedRef\b|\bisMounted\b|\bmounted\b")


@dataclass(frozen=True)
class _SourceDocument:
    path: str
    text: str
    masked_text: str
    comment_masked_text: str


@dataclass(frozen=True)
class _ExportedSymbol:
    name: str
    kind: str
    line: int
    is_default: bool
    declaration: str


@dataclass(frozen=True)
class _StyleRegion:
    start: int
    end: int


@dataclass(frozen=True)
class _LifecycleRegion:
    hook: str
    body_start: int
    body_end: int
    cleanup_regions: tuple[_StyleRegion, ...]


@dataclass(frozen=True)
class _LifecycleTimer:
    timer_kind: str
    timer_call: str
    handle: str | None
    line: int


@dataclass(frozen=True)
class _QueryKeyReference:
    segments: tuple[str, ...]
    line: int
    source: str


@dataclass(frozen=True)
class _InlineQueryKeyViolation:
    line: int
    source: str
    rendered_key: str


@dataclass(frozen=True)
class _ReactUseEffectImports:
    direct_names: tuple[str, ...]
    namespace_names: tuple[str, ...]


@dataclass(frozen=True)
class _ReactUseEffectCall:
    offset: int
    pattern: str


@dataclass(frozen=True)
class _ReactUseSyncExternalStoreImports:
    direct_names: tuple[str, ...]
    namespace_names: tuple[str, ...]


@dataclass(frozen=True)
class _ReactUseSyncExternalStoreCall:
    offset: int
    opening_paren_offset: int
    pattern: str


@dataclass(frozen=True)
class _ResolvedColor:
    expression: str
    source: str
    literal: str | None
    rgba: tuple[float, float, float, float] | None
    token_path: str | None = None


@dataclass(frozen=True)
class _ColorAssignment:
    property: str
    line: int
    resolved: _ResolvedColor


@dataclass(frozen=True)
class _WebBoundarySignals:
    transport_layer_paths: tuple[str, ...]
    normalization_layer_paths: tuple[str, ...]


@dataclass(frozen=True)
class _WebBrowserSideEffectSignals:
    dialog_boundary_paths: tuple[str, ...]
    navigation_boundary_paths: tuple[str, ...]
    storage_boundary_paths: tuple[str, ...]
    modal_controller_paths: tuple[str, ...]
    scroll_lock_boundary_paths: tuple[str, ...]
    has_router_api_surface: bool


@dataclass(frozen=True)
class _WebQueryCacheSignals:
    boundary_paths: tuple[str, ...]


@dataclass(frozen=True)
class _WebSemanticTokenSignals:
    helper_paths: tuple[str, ...]
    token_paths: tuple[str, ...]


@dataclass(frozen=True)
class _RouteContractSignals:
    manifest_paths: tuple[str, ...]
    access_policy_paths: tuple[str, ...]
    codec_paths: tuple[str, ...]
    scope_guard_paths: tuple[str, ...]
    route_families: tuple[str, ...]


@dataclass(frozen=True)
class _TenantBoundarySignals:
    auth_boundary_paths: tuple[str, ...]
    context_surface_paths: tuple[str, ...]


class TypeScriptAdapter:
    adapter_key = "typescript"

    def __init__(self) -> None:
        registry = create_default_registry()
        self._rules = {rule_id: registry.get(rule_id) for rule_id in _TS_RULE_IDS}

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> tuple[NormalizedFinding, ...]:
        requested_rule_ids = tuple(rule_id for rule_id in rule_ids if rule_id in self._rules)
        if not requested_rule_ids:
            return ()

        target_documents = tuple(self._iter_target_documents(context))
        if not target_documents:
            return ()

        findings: list[NormalizedFinding] = []
        repo_documents: tuple[_SourceDocument, ...] | None = None
        supports_ui_rules = "react-native" in context.repo_profile.frameworks
        supports_web_boundary_rules = _supports_web_boundary_rules(context.repo_profile)
        theme_color_tokens: dict[str, str] | None = None
        web_boundary_signals: _WebBoundarySignals | None = None
        web_browser_sideeffect_signals: _WebBrowserSideEffectSignals | None = None
        web_query_cache_signals: _WebQueryCacheSignals | None = None
        web_semantic_token_signals: _WebSemanticTokenSignals | None = None
        route_contract_signals: _RouteContractSignals | None = None
        tenant_boundary_signals: _TenantBoundarySignals | None = None

        for rule_id in requested_rule_ids:
            if rule_id == "typescript.correctness.no-unsafe-any-boundary":
                findings.extend(self._run_unsafe_any_rule(target_documents))
            elif rule_id == "typescript.maintainability.unused-exported-surface":
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                findings.extend(self._run_unused_export_rule(target_documents, repo_documents))
            elif rule_id == "typescript.maintainability.no-oversized-ui-module":
                findings.extend(self._run_oversized_ui_module_rule(target_documents))
            elif rule_id == "typescript.maintainability.no-oversized-support-module":
                findings.extend(self._run_oversized_support_module_rule(target_documents))
            elif (
                rule_id == "typescript.maintainability.no-hook-heavy-page-module"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_hook_heavy_page_rule(target_documents))
            elif (
                rule_id == "typescript.architecture.no-page-direct-api-import-sprawl"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_page_direct_api_import_sprawl_rule(target_documents))
            elif rule_id == "typescript.react.no-use-effect" and _supports_react_stack_rules(
                context.repo_profile
            ):
                findings.extend(self._run_no_use_effect_rule(target_documents))
            elif (
                rule_id == "typescript.react.no-unstable-sync-external-store-snapshot"
                and _supports_react_stack_rules(context.repo_profile)
            ):
                findings.extend(
                    self._run_unstable_sync_external_store_snapshot_rule(target_documents)
                )
            elif (
                rule_id == "typescript.testing.no-interactive-page-without-tests"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                findings.extend(
                    self._run_interactive_page_without_tests_rule(target_documents, repo_documents)
                )
            elif (
                rule_id == "typescript.accessibility.no-icon-only-button-without-accessible-name"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_icon_only_button_without_name_rule(target_documents))
            elif rule_id == "typescript.web.no-raw-transport-calls" and supports_web_boundary_rules:
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_boundary_signals is None:
                    web_boundary_signals = _collect_web_boundary_signals(repo_documents)
                findings.extend(
                    self._run_raw_transport_boundary_rule(target_documents, web_boundary_signals)
                )
            elif (
                rule_id == "typescript.web.no-direct-response-casting"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_boundary_signals is None:
                    web_boundary_signals = _collect_web_boundary_signals(repo_documents)
                findings.extend(
                    self._run_direct_response_casting_rule(target_documents, web_boundary_signals)
                )
            elif (
                rule_id == "typescript.web.route-manifest-centralization"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if route_contract_signals is None:
                    route_contract_signals = _collect_route_contract_signals(repo_documents)
                findings.extend(
                    self._run_route_manifest_centralization_rule(
                        target_documents, route_contract_signals
                    )
                )
            elif (
                rule_id == "typescript.web.route-access-policy-centralization"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if route_contract_signals is None:
                    route_contract_signals = _collect_route_contract_signals(repo_documents)
                findings.extend(
                    self._run_route_access_policy_centralization_rule(
                        target_documents, route_contract_signals
                    )
                )
            elif (
                rule_id == "typescript.web.route-family-literal-consistency"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if route_contract_signals is None:
                    route_contract_signals = _collect_route_contract_signals(repo_documents)
                findings.extend(
                    self._run_route_family_literal_consistency_rule(
                        target_documents, route_contract_signals
                    )
                )
            elif (
                rule_id == "typescript.web.route-query-codec-centralization"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if route_contract_signals is None:
                    route_contract_signals = _collect_route_contract_signals(repo_documents)
                findings.extend(
                    self._run_route_query_codec_centralization_rule(
                        target_documents, route_contract_signals
                    )
                )
            elif (
                rule_id == "typescript.web.no-server-api-tenant-isolation-bypass"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if tenant_boundary_signals is None:
                    tenant_boundary_signals = _collect_tenant_boundary_signals(repo_documents)
                findings.extend(
                    self._run_server_api_tenant_isolation_bypass_rule(
                        target_documents, tenant_boundary_signals
                    )
                )
            elif rule_id == "typescript.web.no-window-confirm" and supports_web_boundary_rules:
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_browser_sideeffect_signals is None:
                    web_browser_sideeffect_signals = _collect_web_browser_sideeffect_signals(
                        repo_documents
                    )
                findings.extend(
                    self._run_window_confirm_rule(target_documents, web_browser_sideeffect_signals)
                )
            elif (
                rule_id == "typescript.web.no-hard-browser-navigation"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_browser_sideeffect_signals is None:
                    web_browser_sideeffect_signals = _collect_web_browser_sideeffect_signals(
                        repo_documents
                    )
                findings.extend(
                    self._run_hard_browser_navigation_rule(
                        target_documents, web_browser_sideeffect_signals
                    )
                )
            elif (
                rule_id == "typescript.web.no-direct-browser-storage"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_browser_sideeffect_signals is None:
                    web_browser_sideeffect_signals = _collect_web_browser_sideeffect_signals(
                        repo_documents
                    )
                findings.extend(
                    self._run_direct_browser_storage_rule(
                        target_documents, web_browser_sideeffect_signals
                    )
                )
            elif (
                rule_id == "typescript.web.no-modal-controller-bypass"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_browser_sideeffect_signals is None:
                    web_browser_sideeffect_signals = _collect_web_browser_sideeffect_signals(
                        repo_documents
                    )
                findings.extend(
                    self._run_modal_controller_bypass_rule(
                        target_documents, web_browser_sideeffect_signals
                    )
                )
            elif (
                rule_id == "typescript.web.no-query-cache-mutation-outside-cache-module"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_query_cache_signals is None:
                    web_query_cache_signals = _collect_web_query_cache_signals(repo_documents)
                findings.extend(
                    self._run_query_cache_mutation_rule(target_documents, web_query_cache_signals)
                )
            elif (
                rule_id == "typescript.web.no-unguarded-async-mutation-ui"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_async_mutation_ui_guard_rule(target_documents))
            elif (
                rule_id == "typescript.web.no-inconsistent-query-key-mutation"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_inconsistent_query_key_mutation_rule(target_documents))
            elif (
                rule_id == "typescript.react.query-key-registry"
                and _supports_react_stack_rules(context.repo_profile)
            ):
                findings.extend(self._run_query_key_registry_rule(target_documents))
            elif (
                rule_id == "typescript.web.no-local-status-variant-map"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_semantic_token_signals is None:
                    web_semantic_token_signals = _collect_web_semantic_token_signals(repo_documents)
                findings.extend(
                    self._run_local_status_variant_map_rule(
                        target_documents, web_semantic_token_signals
                    )
                )
            elif (
                rule_id == "typescript.web.no-raw-semantic-tailwind-status-classes"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_semantic_token_signals is None:
                    web_semantic_token_signals = _collect_web_semantic_token_signals(repo_documents)
                findings.extend(
                    self._run_raw_semantic_tailwind_status_class_rule(
                        target_documents, web_semantic_token_signals
                    )
                )
            elif (
                rule_id == "typescript.web.no-semantic-status-hex-literals"
                and supports_web_boundary_rules
            ):
                if repo_documents is None:
                    repo_documents = self._load_repo_documents(context.repo_root)
                if web_semantic_token_signals is None:
                    web_semantic_token_signals = _collect_web_semantic_token_signals(repo_documents)
                findings.extend(
                    self._run_semantic_status_hex_literal_rule(
                        target_documents, web_semantic_token_signals
                    )
                )
            elif rule_id == "typescript.ui.no-raw-color-literals" and supports_ui_rules:
                findings.extend(self._run_raw_color_literal_rule(target_documents))
            elif (
                rule_id == "typescript.ui.avoid-fixed-tokenless-layout-values" and supports_ui_rules
            ):
                findings.extend(self._run_fixed_layout_rule(target_documents))
            elif rule_id == "typescript.ui.no-orphaned-effect-intervals" and supports_ui_rules:
                findings.extend(
                    self._run_lifecycle_timer_rule(
                        target_documents,
                        rule_id="typescript.ui.no-orphaned-effect-intervals",
                        timer_kind="interval",
                    )
                )
            elif rule_id == "typescript.ui.no-orphaned-effect-timeouts" and supports_ui_rules:
                findings.extend(
                    self._run_lifecycle_timer_rule(
                        target_documents,
                        rule_id="typescript.ui.no-orphaned-effect-timeouts",
                        timer_kind="timeout",
                    )
                )
            elif rule_id == "typescript.ui.avoid-raw-readability-colors" and supports_ui_rules:
                if theme_color_tokens is None:
                    theme_color_tokens = _load_theme_color_tokens(context.repo_root)
                findings.extend(
                    self._run_raw_readability_color_rule(target_documents, theme_color_tokens)
                )
            elif (
                rule_id == "typescript.ui.no-low-contrast-readability-pairings"
                and supports_ui_rules
            ):
                if theme_color_tokens is None:
                    theme_color_tokens = _load_theme_color_tokens(context.repo_root)
                findings.extend(
                    self._run_low_contrast_readability_rule(target_documents, theme_color_tokens)
                )
            elif rule_id == "typescript.ui.risky-status-badge-contrast" and supports_ui_rules:
                if theme_color_tokens is None:
                    theme_color_tokens = _load_theme_color_tokens(context.repo_root)
                findings.extend(
                    self._run_risky_status_badge_contrast_rule(target_documents, theme_color_tokens)
                )
            elif rule_id == "typescript.correctness.no-falsy-default-for-numeric-zero":
                findings.extend(self._run_falsy_numeric_default_rule(target_documents))
            elif rule_id == "typescript.react.no-mixed-controlled-uncontrolled":
                findings.extend(self._run_mixed_controlled_uncontrolled_rule(target_documents))
            elif (
                rule_id == "typescript.web.no-manual-multipart-headers"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_manual_multipart_headers_rule(target_documents))
            elif (
                rule_id == "typescript.accessibility.modal-focus-trap"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_modal_focus_trap_rule(target_documents))
            elif (
                rule_id == "typescript.security.no-raw-error-in-error-boundary"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_raw_error_in_error_boundary_rule(target_documents))
            elif (
                rule_id == "typescript.security.no-unvalidated-external-href"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_unvalidated_external_href_rule(target_documents))
            elif (
                rule_id == "typescript.reliability.no-concurrent-token-refresh"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_concurrent_token_refresh_rule(target_documents))
            elif (
                rule_id == "typescript.performance.no-eager-heavy-dependency-import"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_eager_heavy_dependency_import_rule(target_documents))
            elif (
                rule_id == "typescript.web.no-ephemeral-ids-for-deep-linking"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_ephemeral_ids_for_deep_linking_rule(target_documents))
            elif (
                rule_id == "typescript.maintainability.no-console-in-production-browser-code"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_console_in_production_browser_code_rule(target_documents))
            elif (
                rule_id == "typescript.correctness.no-unvalidated-numeric-precision"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_unvalidated_numeric_precision_rule(target_documents))
            elif (
                rule_id == "typescript.web.no-unauthenticated-image-blob-urls"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_unauthenticated_image_blob_urls_rule(target_documents))
            elif (
                rule_id == "typescript.architecture.no-inline-filter-logic-in-components"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_inline_filter_logic_in_components_rule(target_documents))
            elif (
                rule_id == "typescript.correctness.no-unvalidated-url-tab-param"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_unvalidated_url_tab_param_rule(target_documents))
            elif (
                rule_id == "typescript.accessibility.no-number-input-without-wheel-blur"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_number_input_without_wheel_blur_rule(target_documents))
            elif (
                rule_id == "typescript.web.no-client-api-url-in-server-backend-fetch"
                and supports_web_boundary_rules
            ):
                findings.extend(
                    self._run_client_api_url_in_server_backend_fetch_rule(target_documents)
                )
            elif rule_id == "typescript.reliability.no-module-level-throwing-side-effect":
                findings.extend(self._run_module_level_throwing_side_effect_rule(target_documents))
            elif (
                rule_id == "typescript.reliability.no-formdata-for-raw-binary-upload"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_formdata_for_raw_binary_upload_rule(target_documents))
            elif rule_id == "typescript.reliability.no-unbounded-buffer-without-chunking":
                findings.extend(self._run_unbounded_buffer_without_chunking_rule(target_documents))
            elif (
                rule_id == "typescript.react.no-websocket-reconnect-after-unmount"
                and supports_web_boundary_rules
            ):
                findings.extend(self._run_websocket_reconnect_after_unmount_rule(target_documents))
            elif (
                rule_id == "typescript.react.mutation-requires-cache-invalidation"
                and _supports_react_stack_rules(context.repo_profile)
            ):
                findings.extend(self._run_mutation_requires_cache_invalidation_rule(target_documents))
            elif (
                rule_id == "typescript.react.polled-query-requires-placeholder-data"
                and _supports_react_stack_rules(context.repo_profile)
            ):
                findings.extend(
                    self._run_polled_query_requires_placeholder_data_rule(target_documents)
                )
        return tuple(findings)

    def _run_unsafe_any_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.correctness.no-unsafe-any-boundary")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            for match in _ANY_CAST_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, "as-any")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="`as any` bypasses type safety in changed TypeScript code.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "as-any"},
                    )
                )

            for match in _DOUBLE_CAST_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, "double-cast")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "`as unknown as ...` double-cast bypasses TypeScript boundary checks."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"pattern": "as-unknown-as"},
                    )
                )

            for symbol in _collect_exported_symbols(document.masked_text):
                declaration = symbol.declaration
                if not self._looks_like_unsafe_boundary(declaration):
                    continue

                pattern = (
                    "record-string-unknown"
                    if _RECORD_BOUNDARY_PATTERN.search(declaration)
                    else "any"
                )
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Exported {symbol.kind} `{symbol.name}` exposes an unsafe "
                            "TypeScript boundary."
                        ),
                        path=document.path,
                        line=symbol.line,
                        metadata={"pattern": pattern, "symbol": symbol.name},
                    )
                )

        return tuple(findings)

    def _run_unused_export_rule(
        self,
        target_documents: Sequence[_SourceDocument],
        repo_documents: Sequence[_SourceDocument],
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.maintainability.unused-exported-surface")
        findings: list[NormalizedFinding] = []

        for document in target_documents:
            if _should_skip_unused_export_path(document.path):
                continue

            for symbol in _collect_exported_symbols(document.masked_text):
                if symbol.is_default:
                    continue
                if self._has_external_symbol_reference(
                    symbol_name=symbol.name,
                    owner_path=document.path,
                    repo_documents=repo_documents,
                ):
                    continue

                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Exported {symbol.kind} `{symbol.name}` has no detected references "
                            "outside its defining file."
                        ),
                        path=document.path,
                        line=symbol.line,
                        metadata={"symbol": symbol.name, "kind": symbol.kind},
                    )
                )

        return tuple(findings)

    def _run_oversized_ui_module_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.maintainability.no-oversized-ui-module")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _is_ui_module_surface_path(document.path):
                continue
            module_kind = _ui_module_kind(document.path)
            threshold = _ui_module_line_threshold(module_kind)
            code_lines = _effective_ts_code_line_count(document.masked_text)
            if code_lines <= threshold:
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        f"TypeScript {module_kind.replace('-', ' ')} module exceeds {threshold} "
                        f"code lines ({code_lines}); split rendering, state, and data hooks into "
                        "smaller files."
                    ),
                    path=document.path,
                    line=1,
                    metadata={
                        "module_kind": module_kind,
                        "code_lines": str(code_lines),
                        "line_threshold": str(threshold),
                    },
                )
            )

        return tuple(findings)

    def _run_oversized_support_module_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.maintainability.no-oversized-support-module")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _is_support_module_surface_path(document.path):
                continue
            module_kind = _support_module_kind(document.path)
            threshold = _support_module_line_threshold(module_kind)
            code_lines = _effective_ts_code_line_count(document.masked_text)
            if code_lines <= threshold:
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        f"TypeScript {module_kind.replace('-', ' ')} exceeds {threshold} code "
                        f"lines ({code_lines}); split helpers, utilities, and type surfaces into "
                        "smaller modules."
                    ),
                    path=document.path,
                    line=1,
                    metadata={
                        "module_kind": module_kind,
                        "code_lines": str(code_lines),
                        "line_threshold": str(threshold),
                    },
                )
            )

        return tuple(findings)

    def _run_hook_heavy_page_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.maintainability.no-hook-heavy-page-module")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _is_interactive_page_surface_path(document.path):
                continue
            hook_names = _collect_hook_call_names(document.masked_text)
            if len(hook_names) < _HOOK_HEAVY_PAGE_HOOK_COUNT_THRESHOLD:
                continue
            distinct_hook_names = tuple(dict.fromkeys(hook_names))
            if len(distinct_hook_names) < _HOOK_HEAVY_PAGE_DISTINCT_HOOK_THRESHOLD:
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        "Page module orchestrates an unusually high hook load "
                        f"({len(hook_names)} calls across {len(distinct_hook_names)} hook types); "
                        "extract domain hooks or page-specific helpers before the page turns into "
                        "a coordination hub."
                    ),
                    path=document.path,
                    line=1,
                    metadata={
                        "hook_count": str(len(hook_names)),
                        "hook_threshold": str(_HOOK_HEAVY_PAGE_HOOK_COUNT_THRESHOLD),
                        "distinct_hook_count": str(len(distinct_hook_names)),
                        "distinct_hook_threshold": str(_HOOK_HEAVY_PAGE_DISTINCT_HOOK_THRESHOLD),
                        "sample_hooks": ",".join(distinct_hook_names[:6]),
                    },
                )
            )

        return tuple(findings)

    def _run_interactive_page_without_tests_rule(
        self,
        target_documents: Sequence[_SourceDocument],
        repo_documents: Sequence[_SourceDocument],
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.testing.no-interactive-page-without-tests")
        findings: list[NormalizedFinding] = []

        for document in target_documents:
            if not _is_interactive_page_surface_path(document.path):
                continue
            code_lines = _effective_ts_code_line_count(document.masked_text)
            if code_lines <= _INTERACTIVE_PAGE_CODE_LINE_THRESHOLD:
                continue
            signal_categories = _collect_interactive_page_signal_categories(document.masked_text)
            if len(signal_categories) < 2:
                continue
            if _has_nearby_page_test(document.path, repo_documents):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        "Interactive page module carries substantial state/query/mutation/event "
                        "behavior without a nearby page-focused test."
                    ),
                    path=document.path,
                    line=1,
                    metadata={
                        "code_lines": str(code_lines),
                        "line_threshold": str(_INTERACTIVE_PAGE_CODE_LINE_THRESHOLD),
                        "signal_categories": ",".join(signal_categories),
                    },
                )
            )

        return tuple(findings)

    def _run_page_direct_api_import_sprawl_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.architecture.no-page-direct-api-import-sprawl")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _is_interactive_page_surface_path(document.path):
                continue
            direct_api_imports = _collect_direct_api_imports(document.comment_masked_text)
            if len(direct_api_imports) <= _PAGE_DIRECT_API_IMPORT_THRESHOLD:
                continue
            first_import_line = min(line for _, line in direct_api_imports)
            api_modules = tuple(source for source, _ in direct_api_imports)
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        "Page module directly imports too many `@/lib/api` modules "
                        f"({len(api_modules)} distinct imports); prefer domain hooks or helpers "
                        "instead of wiring API surfaces in the page."
                    ),
                    path=document.path,
                    line=first_import_line,
                    metadata={
                        "api_module_count": str(len(api_modules)),
                        "import_threshold": str(_PAGE_DIRECT_API_IMPORT_THRESHOLD),
                        "api_modules": ",".join(api_modules[:4]),
                    },
                )
            )

        return tuple(findings)

    def _run_icon_only_button_without_name_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule(
            "typescript.accessibility.no-icon-only-button-without-accessible-name"
        )
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int]] = set()

        for document in documents:
            if not _should_scan_icon_button_accessibility_path(document.path):
                continue
            icon_names = _collect_icon_import_names(document.comment_masked_text)
            shared_button_names = _collect_shared_ui_button_component_names(
                document.comment_masked_text
            )
            for control, match in _iter_button_like_matches(
                document.comment_masked_text, shared_button_names
            ):
                attrs = match.group("attrs")
                if _HIDDEN_ELEMENT_ATTRIBUTE_PATTERN.search(attrs):
                    continue
                if _ACCESSIBLE_NAME_ATTRIBUTE_PATTERN.search(attrs):
                    continue
                body = match.group("body")
                if _button_body_has_accessible_text(body):
                    continue
                if not _button_body_looks_icon_only(body, icon_names):
                    continue
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Icon-only button is missing an accessible name such as aria-label, "
                            "aria-labelledby, or visually hidden text."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"control": control},
                    )
                )

        return tuple(findings)

    def _run_raw_color_literal_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.ui.no-raw-color-literals")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()

        for document in documents:
            if not _should_scan_ui_rule_path(document.path):
                continue
            for region in _iter_style_regions(document.masked_text):
                region_text = document.comment_masked_text[region.start : region.end + 1]
                for match in _RAW_COLOR_LITERAL_PATTERN.finditer(region_text):
                    property_name = match.group("property")
                    color_value = match.group("value")
                    offset = region.start + match.start()
                    line = _line_for_offset(document.comment_masked_text, offset)
                    key = (document.path, line, property_name, color_value)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        self._build_finding(
                            rule,
                            message=(
                                f"Use theme tokens instead of raw color literal "
                                f"`{color_value}` on `{property_name}`."
                            ),
                            path=document.path,
                            line=line,
                            metadata={"property": property_name, "value": color_value},
                        )
                    )

        return tuple(findings)

    def _run_raw_transport_boundary_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebBoundarySignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.transport_layer_paths:
            return ()

        rule = self._require_rule("typescript.web.no-raw-transport-calls")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.transport_layer_paths[0]

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match, pattern in _iter_raw_transport_matches(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, pattern)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                raw_call = "raw fetch" if pattern == "fetch" else "raw axios"
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"{raw_call} call bypasses the repo transport boundary; route this "
                            f"through an approved client layer such as `{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"pattern": pattern, "boundary_layer": boundary_hint},
                    )
                )

        return tuple(findings)

    def _run_direct_response_casting_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebBoundarySignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.transport_layer_paths and not signals.normalization_layer_paths:
            return ()

        rule = self._require_rule("typescript.web.no-direct-response-casting")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()
        boundary_hint = (
            signals.normalization_layer_paths[0]
            if signals.normalization_layer_paths
            else signals.transport_layer_paths[0]
        )

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match, pattern in _iter_direct_response_cast_matches(document.masked_text):
                type_name = _normalize_response_type(match.group("type"))
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, pattern, type_name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Normalize backend payloads before exposing `{type_name}` in web "
                            f"UI code; keep response parsing in client/schema layers such as "
                            f"`{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": pattern,
                            "response_type": type_name,
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_window_confirm_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebBrowserSideEffectSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.dialog_boundary_paths:
            return ()

        rule = self._require_rule("typescript.web.no-window-confirm")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.dialog_boundary_paths[0]

        for document in documents:
            if not _should_scan_web_sideeffect_surface_path(
                document.path, signals.dialog_boundary_paths
            ):
                continue

            for match in _WINDOW_CONFIRM_CALL_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, "window.confirm")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Browser confirm dialogs bypass the repo dialog boundary; route "
                            f"confirmations through an approved surface such as `{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"pattern": "window.confirm", "boundary_layer": boundary_hint},
                    )
                )

            if _has_shadowed_confirm_binding(document.masked_text):
                continue
            for match in _GLOBAL_CONFIRM_CALL_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, "confirm")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Global browser confirm dialogs bypass the repo dialog boundary; "
                            f"use an approved surface such as `{boundary_hint}` instead."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"pattern": "confirm", "boundary_layer": boundary_hint},
                    )
                )

        return tuple(findings)

    def _run_hard_browser_navigation_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebBrowserSideEffectSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.has_router_api_surface or not signals.navigation_boundary_paths:
            return ()

        rule = self._require_rule("typescript.web.no-hard-browser-navigation")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.navigation_boundary_paths[0]

        for document in documents:
            if not _should_scan_web_sideeffect_surface_path(
                document.path, signals.navigation_boundary_paths
            ):
                continue

            for match in _WINDOW_LOCATION_CALL_PATTERN.finditer(document.masked_text):
                method = match.group("method")
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, method)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Hard browser navigation bypasses router-aware flows; keep "
                            f"`window.location.{method}` inside approved helpers such as "
                            f"`{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": f"window.location.{method}",
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

            for match in _WINDOW_LOCATION_ASSIGNMENT_PATTERN.finditer(document.masked_text):
                property_name = ".href" if match.group("property") else ""
                line = _line_for_offset(document.masked_text, match.start())
                pattern = f"window.location{property_name}="
                key = (document.path, line, pattern)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Direct browser location mutation bypasses router-aware flows; keep "
                            f"`window.location{property_name}` redirects inside approved helpers "
                            f"such as `{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"pattern": pattern, "boundary_layer": boundary_hint},
                    )
                )

        return tuple(findings)

    def _run_direct_browser_storage_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebBrowserSideEffectSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.storage_boundary_paths:
            return ()

        rule = self._require_rule("typescript.web.no-direct-browser-storage")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.storage_boundary_paths[0]

        for document in documents:
            if not _should_scan_web_sideeffect_surface_path(
                document.path, signals.storage_boundary_paths
            ):
                continue

            for match in _DIRECT_BROWSER_STORAGE_PATTERN.finditer(document.masked_text):
                storage = match.group("storage")
                operation = match.group("operation")
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, f"{storage}.{operation}")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Direct browser storage bypasses the repo auth/storage boundary; "
                            f"use a helper such as `{boundary_hint}` for `{storage}.{operation}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "storage": storage,
                            "operation": operation,
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_local_status_variant_map_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebSemanticTokenSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.helper_paths:
            return ()

        rule = self._require_rule("typescript.web.no-local-status-variant-map")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.helper_paths[0]
        approved_paths = {*signals.helper_paths, *signals.token_paths}

        for document in documents:
            if not _should_scan_web_semantic_path(document.path, approved_paths):
                continue

            for match in _SEMANTIC_STATUS_HELPER_DECLARATION_PATTERN.finditer(document.masked_text):
                helper_name = match.group("name")
                if not _is_semantic_status_helper_name(helper_name):
                    continue
                line = _line_for_offset(document.masked_text, match.start("name"))
                key = (document.path, line, helper_name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Semantic status variant maps should stay behind a shared helper "
                            f"boundary such as `{boundary_hint}` instead of local helper "
                            f"`{helper_name}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"helper_name": helper_name, "boundary_layer": boundary_hint},
                    )
                )

        return tuple(findings)

    def _run_modal_controller_bypass_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebBrowserSideEffectSignals,
    ) -> tuple[NormalizedFinding, ...]:
        approved_paths = {
            *signals.modal_controller_paths,
            *signals.scroll_lock_boundary_paths,
        }
        if not approved_paths:
            return ()

        rule = self._require_rule("typescript.web.no-modal-controller-bypass")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_web_sideeffect_surface_path(document.path, tuple(approved_paths)):
                continue

            if signals.modal_controller_paths:
                boundary_hint = signals.modal_controller_paths[0]
                match = _MODAL_DOCUMENT_KEYDOWN_PATTERN.search(document.text)
                if match is not None:
                    line = _line_for_offset(document.text, match.start())
                    key = (document.path, 0, "document-keydown-listener")
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(
                            self._build_finding(
                                rule,
                                message=(
                                    "Modal keyboard trapping should stay inside shared controllers; "
                                    f"route document keydown wiring through `{boundary_hint}`."
                                ),
                                path=document.path,
                                line=line,
                                metadata={
                                    "pattern": "document-keydown-listener",
                                    "boundary_layer": boundary_hint,
                                },
                            )
                        )

            if signals.scroll_lock_boundary_paths:
                boundary_hint = signals.scroll_lock_boundary_paths[0]
                match = _BODY_SCROLL_LOCK_ASSIGNMENT_PATTERN.search(document.text)
                if match is not None:
                    line = _line_for_offset(document.text, match.start())
                    key = (document.path, 0, "body-scroll-lock")
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(
                            self._build_finding(
                                rule,
                                message=(
                                    "Modal scroll locking should stay behind shared helpers; route "
                                    f"body overflow changes through `{boundary_hint}`."
                                ),
                                path=document.path,
                                line=line,
                                metadata={
                                    "pattern": "body-scroll-lock",
                                    "boundary_layer": boundary_hint,
                                },
                            )
                        )

        return tuple(findings)

    def _run_query_cache_mutation_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebQueryCacheSignals,
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-query-cache-mutation-outside-cache-module")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        approved_paths = set(signals.boundary_paths)
        boundary_hint = _query_cache_boundary_hint(signals)

        for document in documents:
            if not _should_scan_web_query_cache_surface_path(document.path, approved_paths):
                continue

            for match in _QUERY_CACHE_MUTATION_PATTERN.finditer(document.masked_text):
                method = match.group("method")
                receiver = re.sub(r"\s+", "", match.group("receiver"))
                line = _line_for_offset(document.masked_text, match.start("method"))
                key = (document.path, line, method)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Shared query cache mutation should stay inside dedicated cache "
                            f"helpers; move `{receiver}.{method}` into a cache module such as "
                            f"`{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "method": method,
                            "receiver": receiver,
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_async_mutation_ui_guard_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-unguarded-async-mutation-ui")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue

            for mutation_name, line in _collect_mutation_declarations(document.comment_masked_text):
                call_line = _find_mutation_trigger_line(document.comment_masked_text, mutation_name)
                if call_line is None or _document_has_mutation_pending_guard(
                    document.comment_masked_text, mutation_name
                ):
                    continue
                key = (document.path, call_line, mutation_name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Async mutation UI should expose a pending guard before it can be "
                            f"re-triggered; wire `{mutation_name}.isPending` into button or form "
                            "state."
                        ),
                        path=document.path,
                        line=call_line,
                        metadata={
                            "mutation_name": mutation_name,
                            "guard_expression": f"{mutation_name}.isPending",
                            "declaration_line": str(line),
                        },
                    )
                )

        return tuple(findings)

    def _run_no_use_effect_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.no-use-effect")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _should_scan_react_stack_effect_path(document.path):
                continue

            imported_aliases = _collect_react_use_effect_import_aliases(
                document.comment_masked_text
            )
            if not imported_aliases.direct_names and not imported_aliases.namespace_names:
                continue

            call = _find_first_react_use_effect_call(document.masked_text, imported_aliases)
            if call is None:
                continue

            line = _line_for_offset(document.masked_text, call.offset)
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        "New `useEffect` usage is banned in React runtime code; move this flow "
                        "behind explicit events, derived state, query callbacks, or a dedicated "
                        "boundary helper."
                    ),
                    path=document.path,
                    line=line,
                    metadata={"pattern": call.pattern},
                )
            )

        return tuple(findings)

    def _run_unstable_sync_external_store_snapshot_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.no-unstable-sync-external-store-snapshot")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_react_stack_effect_path(document.path):
                continue

            imported_aliases = _collect_react_use_sync_external_store_import_aliases(
                document.comment_masked_text
            )
            if not imported_aliases.direct_names and not imported_aliases.namespace_names:
                continue

            calls = _collect_react_use_sync_external_store_calls(
                document.masked_text, imported_aliases
            )
            if not calls:
                continue

            for call in calls:
                closing_paren = _find_matching_delimiter(
                    document.masked_text, call.opening_paren_offset, "(", ")"
                )
                arguments_text = document.masked_text[call.opening_paren_offset + 1 : closing_paren]
                for (
                    snapshot_argument,
                    expression_text,
                ) in _collect_external_store_snapshot_arguments(arguments_text):
                    if not _snapshot_expression_is_unstable(
                        full_text=document.masked_text,
                        expression_text=expression_text,
                        seen=frozenset(),
                    ):
                        continue

                    line = _line_for_offset(document.masked_text, call.offset)
                    key = (document.path, line, snapshot_argument)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        self._build_finding(
                            rule,
                            message=(
                                "`useSyncExternalStore` "
                                f"`{snapshot_argument}` must return a stable reference; cache "
                                "snapshot objects/arrays instead of rebuilding them on every read."
                            ),
                            path=document.path,
                            line=line,
                            metadata={
                                "pattern": call.pattern,
                                "snapshot_argument": snapshot_argument,
                            },
                        )
                    )

        return tuple(findings)

    def _run_inconsistent_query_key_mutation_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-inconsistent-query-key-mutation")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _INTERACTIVE_PAGE_MUTATION_SIGNAL_PATTERN.search(document.masked_text):
                continue

            query_key_references = _collect_query_hook_key_references(document.comment_masked_text)
            if not query_key_references:
                continue
            query_roots = {
                reference.segments[0] for reference in query_key_references if reference.segments
            }
            if len(query_roots) != 1:
                continue

            mutation_key_references = _collect_query_cache_key_references(
                document.comment_masked_text
            )
            if not mutation_key_references:
                continue

            query_key_segments = tuple(
                dict.fromkeys(reference.segments for reference in query_key_references)
            )
            for mutation_reference in mutation_key_references:
                if any(
                    _query_key_segments_are_prefix_compatible(
                        mutation_reference.segments,
                        query_segments,
                    )
                    for query_segments in query_key_segments
                ):
                    continue
                rendered_query_keys = ", ".join(
                    _render_query_key_segments(segments) for segments in query_key_segments[:2]
                )
                rendered_mutation_key = _render_query_key_segments(mutation_reference.segments)
                key = (document.path, mutation_reference.line, rendered_mutation_key)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Mutation-side cache updates should use the same query-key family as "
                            f"the queries in this file; `{mutation_reference.source}` targets "
                            f"`{rendered_mutation_key}` while query usage reads "
                            f"`{rendered_query_keys}`."
                        ),
                        path=document.path,
                        line=mutation_reference.line,
                        metadata={
                            "cache_method": mutation_reference.source,
                            "cache_query_key": rendered_mutation_key,
                            "query_keys": rendered_query_keys,
                        },
                    )
                )

        return tuple(findings)

    def _run_mutation_requires_cache_invalidation_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.mutation-requires-cache-invalidation")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_react_stack_effect_path(document.path):
                continue

            for match in _MUTATION_DECLARATION_PATTERN.finditer(document.comment_masked_text):
                opening_paren = document.comment_masked_text.find("(", match.start())
                if opening_paren < 0:
                    continue
                function_scope = _extract_enclosing_function_scope(
                    document.comment_masked_text, match.start()
                )
                if function_scope is None:
                    continue
                if _MUTATION_CACHE_INVALIDATION_PATTERN.search(function_scope):
                    continue
                line = _line_for_offset(document.comment_masked_text, match.start("name"))
                key = (document.path, line, match.group("name"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "useMutation should invalidate or update React Query cache in the "
                            f"same function; `{match.group('name')}` has no visible cache sync."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": "mutation-without-cache-invalidation",
                            "mutation_name": match.group("name"),
                        },
                    )
                )

        return tuple(findings)

    def _run_polled_query_requires_placeholder_data_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.polled-query-requires-placeholder-data")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_react_stack_effect_path(document.path):
                continue

            for match in _QUERY_HOOK_CALL_PATTERN.finditer(document.comment_masked_text):
                opening_paren = match.end() - 1
                closing_paren = _find_matching_delimiter(
                    document.comment_masked_text, opening_paren, "(", ")"
                )
                hook_args = document.comment_masked_text[opening_paren + 1 : closing_paren]
                if not _REFETCH_INTERVAL_PATTERN.search(hook_args):
                    continue
                if _PLACEHOLDER_DATA_PATTERN.search(hook_args):
                    continue
                line = _line_for_offset(document.comment_masked_text, opening_paren + 1)
                key = (document.path, line, match.group("hook"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"{match.group('hook')} uses refetchInterval without placeholderData "
                            "or keepPreviousData, which can flicker polled UI updates."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": "polled-query-without-placeholder-data",
                            "hook": match.group("hook"),
                        },
                    )
                )

        return tuple(findings)

    def _run_query_key_registry_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.query-key-registry")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if _is_query_key_registry_path(document.path):
                continue
            if not document.path.endswith(tuple(_TS_SUFFIXES)):
                continue

            for violation in _collect_inline_query_key_violations(document.comment_masked_text):
                key = (document.path, violation.line, violation.source)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "React Query keys should live in a dedicated query-key "
                            "registry module (`query-keys.ts` / `queryKeys.ts`); "
                            f"inline key `{violation.rendered_key}` in "
                            f"`{violation.source}` should be centralized."
                        ),
                        path=document.path,
                        line=violation.line,
                        metadata={
                            "source": violation.source,
                            "query_key": violation.rendered_key,
                        },
                    )
                )

        return tuple(findings)

    def _run_raw_semantic_tailwind_status_class_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebSemanticTokenSignals,
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-raw-semantic-tailwind-status-classes")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        approved_paths = {*signals.helper_paths, *signals.token_paths}
        boundary_hint = _semantic_boundary_hint(signals)

        for document in documents:
            if not _should_scan_web_semantic_path(document.path, approved_paths):
                continue

            for match in _SEMANTIC_TAILWIND_STATUS_CLASS_PATTERN.finditer(
                document.comment_masked_text
            ):
                classes = tuple(_extract_semantic_tailwind_status_classes(match.group("classes")))
                if not classes:
                    continue
                offset = match.start("classes")
                if not _has_semantic_status_context(
                    document.path, document.comment_masked_text, offset
                ):
                    continue
                line = _line_for_offset(document.comment_masked_text, offset)
                rendered_classes = ", ".join(classes[:3])
                key = (document.path, line, rendered_classes)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                message = (
                    "Semantic status styling should avoid raw Tailwind palette classes "
                    f"({rendered_classes})."
                )
                if boundary_hint is not None:
                    message = (
                        f"{message} Prefer the shared helper/token boundary `{boundary_hint}`."
                    )
                findings.append(
                    self._build_finding(
                        rule,
                        message=message,
                        path=document.path,
                        line=line,
                        metadata={
                            "semantic_classes": rendered_classes,
                            "boundary_layer": boundary_hint or "",
                        },
                    )
                )

        return tuple(findings)

    def _run_semantic_status_hex_literal_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _WebSemanticTokenSignals,
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-semantic-status-hex-literals")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        approved_paths = {*signals.helper_paths, *signals.token_paths}
        boundary_hint = _semantic_boundary_hint(signals)

        for document in documents:
            if not _should_scan_web_semantic_path(document.path, approved_paths):
                continue

            for match in _SEMANTIC_STATUS_COLOR_LITERAL_PATTERN.finditer(
                document.comment_masked_text
            ):
                color_value = match.group("value")
                offset = match.start("value")
                if not _has_semantic_status_context(
                    document.path, document.comment_masked_text, offset
                ):
                    continue
                line = _line_for_offset(document.comment_masked_text, offset)
                key = (document.path, line, color_value)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                message = f"Semantic status styling should avoid raw color literal `{color_value}`."
                if boundary_hint is not None:
                    message = (
                        f"{message} Prefer the shared helper/token boundary `{boundary_hint}`."
                    )
                findings.append(
                    self._build_finding(
                        rule,
                        message=message,
                        path=document.path,
                        line=line,
                        metadata={
                            "color_literal": color_value,
                            "boundary_layer": boundary_hint or "",
                        },
                    )
                )

        return tuple(findings)

    def _run_route_manifest_centralization_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _RouteContractSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.manifest_paths:
            return ()

        rule = self._require_rule("typescript.web.route-manifest-centralization")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.manifest_paths[0]

        for document in documents:
            if not _should_scan_route_contract_surface_path(document.path, signals):
                continue
            matches = tuple(_iter_manifest_route_matches(document.comment_masked_text))
            if len(matches) < 2:
                continue
            for match, route in matches:
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line, route)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Shared web route manifests should stay centralized; move `{route}` "
                            f"into an approved manifest such as `{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"route": route, "boundary_layer": boundary_hint},
                    )
                )

        return tuple(findings)

    def _run_route_access_policy_centralization_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _RouteContractSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.access_policy_paths:
            return ()

        rule = self._require_rule("typescript.web.route-access-policy-centralization")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()
        boundary_hint = signals.access_policy_paths[0]

        for document in documents:
            if not _should_scan_route_contract_surface_path(document.path, signals):
                continue
            for offset, route, pattern in _iter_route_access_policy_matches(
                document.comment_masked_text
            ):
                line = _line_for_offset(document.comment_masked_text, offset)
                key = (document.path, line, route, pattern)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Inline route access checks should defer to a shared policy such as "
                            f"`{boundary_hint}` instead of duplicating `{route}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "route": route,
                            "pattern": pattern,
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_route_family_literal_consistency_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _RouteContractSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.manifest_paths or not signals.route_families:
            return ()

        rule = self._require_rule("typescript.web.route-family-literal-consistency")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()
        canonical_families_by_stem = _index_route_families_by_stem(signals.route_families)
        boundary_hint = signals.manifest_paths[0]

        for document in documents:
            if not _should_scan_route_contract_surface_path(document.path, signals):
                continue
            for match, route in _iter_root_route_literal_matches(document.comment_masked_text):
                family = _extract_route_family(route)
                if family is None:
                    continue
                canonical_family = _resolve_canonical_route_family(
                    family, canonical_families_by_stem
                )
                if canonical_family is None or canonical_family == family:
                    continue
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line, family, canonical_family)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Route family literal `{family}` drifts from repo-approved "
                            f"`{canonical_family}`; prefer the shared manifest in "
                            f"`{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "route": route,
                            "family": family,
                            "canonical_family": canonical_family,
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_route_query_codec_centralization_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _RouteContractSignals,
    ) -> tuple[NormalizedFinding, ...]:
        if not signals.codec_paths:
            return ()

        rule = self._require_rule("typescript.web.route-query-codec-centralization")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = signals.codec_paths[0]

        for document in documents:
            if not _should_scan_route_contract_surface_path(document.path, signals):
                continue

            for match in _ROUTE_PARAM_ACCESS_PATTERN.finditer(document.comment_masked_text):
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line, "route-param-access")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Route params should be decoded through shared codecs; move raw "
                            f"`{match.group('source')}.{match.group('name')}` reads behind "
                            f"`{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": "route-param-access",
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

            for match in _SEARCH_PARAM_ACCESS_PATTERN.finditer(document.comment_masked_text):
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line, "search-param-access")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                normalized_source = re.sub(r"\s+", "", match.group("source"))
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "Query/search params should be decoded through shared codecs; move "
                            f"raw `{normalized_source}.get(...)` reads "
                            f"behind `{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": "search-param-access",
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_server_api_tenant_isolation_bypass_rule(
        self,
        documents: Sequence[_SourceDocument],
        signals: _TenantBoundarySignals,
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-server-api-tenant-isolation-bypass")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()
        boundary_hint = _tenant_auth_boundary_hint(signals)

        for document in documents:
            if not _looks_like_server_route_module_path(document.path):
                continue
            if _has_authenticated_tenant_cross_check(document.masked_text):
                continue
            for line, pattern, source in _iter_server_tenant_resolution_matches(
                document.comment_masked_text
            ):
                key = (document.path, line, pattern)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Server route resolves tenant input through `{source}` without "
                            f"cross-checking authenticated tenant context; compare it against "
                            f"session/auth tenant state or move the boundary into "
                            f"`{boundary_hint}`."
                        ),
                        path=document.path,
                        line=line,
                        metadata={
                            "pattern": pattern,
                            "source": source,
                            "boundary_layer": boundary_hint,
                        },
                    )
                )

        return tuple(findings)

    def _run_fixed_layout_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.ui.avoid-fixed-tokenless-layout-values")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()

        for document in documents:
            if not _should_scan_ui_rule_path(document.path):
                continue
            for region in _iter_style_regions(document.masked_text):
                region_text = document.comment_masked_text[region.start : region.end + 1]
                for match in _FIXED_LAYOUT_LITERAL_PATTERN.finditer(region_text):
                    property_name = match.group("property")
                    literal_value = match.group("value")
                    offset = region.start + match.start()
                    if literal_value in _ALLOWED_LAYOUT_LITERALS:
                        continue
                    if _should_skip_layout_literal(
                        document.comment_masked_text, property_name, offset
                    ):
                        continue
                    line = _line_for_offset(document.comment_masked_text, offset)
                    key = (document.path, line, property_name, literal_value)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        self._build_finding(
                            rule,
                            message=(
                                f"Prefer shared layout tokens over raw `{property_name}: "
                                f"{literal_value}` in React Native styles."
                            ),
                            path=document.path,
                            line=line,
                            metadata={"property": property_name, "value": literal_value},
                        )
                    )

        return tuple(findings)

    def _run_lifecycle_timer_rule(
        self,
        documents: Sequence[_SourceDocument],
        *,
        rule_id: str,
        timer_kind: str,
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule(rule_id)
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str, str]] = set()

        for document in documents:
            if not _should_scan_lifecycle_rule_path(document.path):
                continue
            for region in _iter_lifecycle_regions(document.masked_text):
                cleanup_texts = tuple(
                    document.masked_text[cleanup.start : cleanup.end + 1]
                    for cleanup in region.cleanup_regions
                )
                for timer in _collect_lifecycle_timers(
                    region_text=document.masked_text[region.body_start : region.body_end + 1],
                    region_start=region.body_start,
                    full_text=document.masked_text,
                ):
                    if timer.timer_kind != timer_kind:
                        continue
                    cleanup_status = _classify_lifecycle_timer_cleanup(cleanup_texts, timer)
                    if cleanup_status == "cleared":
                        continue
                    key = (
                        document.path,
                        timer.line,
                        timer.timer_kind,
                        timer.handle or "<untracked>",
                        cleanup_status,
                    )
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        self._build_finding(
                            rule,
                            message=_build_lifecycle_timer_message(
                                timer, region.hook, cleanup_status
                            ),
                            path=document.path,
                            line=timer.line,
                            metadata={
                                "hook": region.hook,
                                "timer_kind": timer.timer_kind,
                                "timer_call": timer.timer_call,
                                "handle": timer.handle or "<untracked>",
                                "cleanup_status": cleanup_status,
                            },
                        )
                    )

        return tuple(findings)

    def _run_raw_readability_color_rule(
        self, documents: Sequence[_SourceDocument], theme_color_tokens: dict[str, str]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.ui.avoid-raw-readability-colors")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()

        for document in documents:
            if not _should_scan_ui_rule_path(document.path):
                continue
            local_constants = _collect_local_color_constants(document.comment_masked_text)
            for region in _iter_readability_regions(document.masked_text):
                region_text = document.comment_masked_text[region.start : region.end + 1]
                for assignment in _collect_color_assignments(
                    region_text=region_text,
                    region_start=region.start,
                    full_text=document.comment_masked_text,
                    theme_color_tokens=theme_color_tokens,
                    local_constants=local_constants,
                ):
                    if assignment.property not in _READABILITY_FOREGROUND_PROPERTIES:
                        continue
                    if assignment.resolved.source not in {"literal", "local-const"}:
                        continue
                    key = (
                        document.path,
                        assignment.line,
                        assignment.property,
                        assignment.resolved.expression,
                    )
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    value_label = assignment.resolved.literal or assignment.resolved.expression
                    source_label = (
                        "raw color literal"
                        if assignment.resolved.source == "literal"
                        else f"local color constant `{assignment.resolved.expression}`"
                    )
                    findings.append(
                        self._build_finding(
                            rule,
                            message=(
                                f"Prefer theme readability tokens instead of {source_label} "
                                f"for `{assignment.property}` (`{value_label}`)."
                            ),
                            path=document.path,
                            line=assignment.line,
                            metadata={
                                "property": assignment.property,
                                "value": value_label,
                                "source": assignment.resolved.source,
                            },
                        )
                    )

        return tuple(findings)

    def _run_low_contrast_readability_rule(
        self, documents: Sequence[_SourceDocument], theme_color_tokens: dict[str, str]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.ui.no-low-contrast-readability-pairings")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()

        for document in documents:
            if not _should_scan_ui_rule_path(document.path):
                continue
            local_constants = _collect_local_color_constants(document.comment_masked_text)
            for region in _iter_readability_regions(document.masked_text):
                region_text = document.comment_masked_text[region.start : region.end + 1]
                assignments = _collect_color_assignments(
                    region_text=region_text,
                    region_start=region.start,
                    full_text=document.comment_masked_text,
                    theme_color_tokens=theme_color_tokens,
                    local_constants=local_constants,
                )
                background = _latest_assignment(assignments, "backgroundColor")
                if background is None or background.resolved.rgba is None:
                    continue
                if background.resolved.rgba[3] != 1.0:
                    continue
                for property_name in _READABILITY_FOREGROUND_PROPERTIES:
                    foreground = _latest_assignment(assignments, property_name)
                    if foreground is None or foreground.resolved.rgba is None:
                        continue
                    if foreground.resolved.rgba[3] != 1.0:
                        continue
                    ratio = _contrast_ratio(foreground.resolved.rgba, background.resolved.rgba)
                    if ratio >= _LOW_CONTRAST_BLOCKING_THRESHOLD:
                        continue
                    rendered_ratio = f"{ratio:.2f}"
                    key = (
                        document.path,
                        foreground.line,
                        foreground.resolved.expression,
                        rendered_ratio,
                    )
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        self._build_finding(
                            rule,
                            message=(
                                f"`{foreground.property}` uses a low-contrast readability pairing "
                                f"against `{background.property}` (ratio {rendered_ratio}:1)."
                            ),
                            path=document.path,
                            line=foreground.line,
                            metadata={
                                "property": foreground.property,
                                "value": foreground.resolved.literal
                                or foreground.resolved.expression,
                                "background": background.resolved.literal
                                or background.resolved.expression,
                                "contrast_ratio": rendered_ratio,
                            },
                        )
                    )

        return tuple(findings)

    def _run_risky_status_badge_contrast_rule(
        self, documents: Sequence[_SourceDocument], theme_color_tokens: dict[str, str]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.ui.risky-status-badge-contrast")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str, str]] = set()

        for document in documents:
            if not _should_scan_ui_rule_path(document.path):
                continue
            local_constants = _collect_local_color_constants(document.comment_masked_text)
            for region in _iter_readability_regions(document.masked_text):
                region_text = document.comment_masked_text[region.start : region.end + 1]
                assignments = _collect_color_assignments(
                    region_text=region_text,
                    region_start=region.start,
                    full_text=document.comment_masked_text,
                    theme_color_tokens=theme_color_tokens,
                    local_constants=local_constants,
                )
                background = _latest_assignment(assignments, "backgroundColor")
                if background is None:
                    continue
                for property_name in _READABILITY_FOREGROUND_PROPERTIES:
                    foreground = _latest_assignment(assignments, property_name)
                    if foreground is None:
                        continue
                    if not _is_risky_status_pair(background.resolved, foreground.resolved):
                        continue
                    key = (
                        document.path,
                        foreground.line,
                        foreground.resolved.expression,
                        background.resolved.expression,
                    )
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        self._build_finding(
                            rule,
                            message=(
                                "Status badge readability relies on a same-hue muted background "
                                "and foreground pairing that often under-contrasts."
                            ),
                            path=document.path,
                            line=foreground.line,
                            metadata={
                                "property": foreground.property,
                                "value": foreground.resolved.literal
                                or foreground.resolved.expression,
                                "background": background.resolved.literal
                                or background.resolved.expression,
                            },
                        )
                    )

        return tuple(findings)

    def _run_falsy_numeric_default_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.correctness.no-falsy-default-for-numeric-zero")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            for match in _FALSY_NUMERIC_DEFAULT_PATTERN.finditer(document.masked_text):
                default_value = match.group("default")
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, default_value)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            f"Logical OR (`||`) used to default numeric value with `{default_value}`; "
                            "use nullish coalescing (`??`) so explicit zero is preserved."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"default_value": default_value},
                    )
                )

        return tuple(findings)

    def _run_mixed_controlled_uncontrolled_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.no-mixed-controlled-uncontrolled")
        findings: list[NormalizedFinding] = []

        for document in documents:
            text = document.masked_text
            has_default_edges = _MIXED_CONTROLLED_DEFAULT_EDGES_PATTERN.search(text)
            has_set_edges = _MIXED_CONTROLLED_SET_EDGES_PATTERN.search(text)
            if has_default_edges and has_set_edges:
                findings.append(
                    self._build_finding(
                        rule,
                        message="Simultaneous use of `defaultEdges` and `setEdges` mixes controlled and uncontrolled APIs.",
                        path=document.path,
                        line=_line_for_offset(text, has_default_edges.start()),
                        metadata={"pattern": "defaultEdges+setEdges"},
                    )
                )

            has_default_value = _MIXED_CONTROLLED_DEFAULT_VALUE_PATTERN.search(text)
            has_value_onchange = _MIXED_CONTROLLED_VALUE_ONCHANGE_PATTERN.search(text)
            if has_default_value and has_value_onchange:
                findings.append(
                    self._build_finding(
                        rule,
                        message="Simultaneous use of `defaultValue` and `value/onChange` mixes controlled and uncontrolled APIs.",
                        path=document.path,
                        line=_line_for_offset(text, has_default_value.start()),
                        metadata={"pattern": "defaultValue+value/onChange"},
                    )
                )

            has_default_checked = _MIXED_CONTROLLED_DEFAULT_CHECKED_PATTERN.search(text)
            has_checked_onchange = _MIXED_CONTROLLED_CHECKED_ONCHANGE_PATTERN.search(text)
            if has_default_checked and has_checked_onchange:
                findings.append(
                    self._build_finding(
                        rule,
                        message="Simultaneous use of `defaultChecked` and `checked/onChange` mixes controlled and uncontrolled APIs.",
                        path=document.path,
                        line=_line_for_offset(text, has_default_checked.start()),
                        metadata={"pattern": "defaultChecked+checked/onChange"},
                    )
                )

        return tuple(findings)

    def _run_manual_multipart_headers_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-manual-multipart-headers")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _FORMDATA_CONSTRUCT_PATTERN.search(document.comment_masked_text):
                continue
            for match in _MANUAL_MULTIPART_HEADER_PATTERN.finditer(document.comment_masked_text):
                line = _line_for_offset(document.comment_masked_text, match.start())
                findings.append(
                    self._build_finding(
                        rule,
                        message="Manual `Content-Type: multipart/form-data` header blocks browser boundary generation; remove it when sending FormData.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "manual-multipart-header"},
                    )
                )

        return tuple(findings)

    def _run_modal_focus_trap_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.accessibility.modal-focus-trap")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _MODAL_COMPONENT_NAME_PATTERN.search(document.masked_text):
                continue
            if _FOCUS_TRAP_SIGNAL_PATTERN.search(document.masked_text):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message="Modal/dialog component is missing focus-trap logic (`useFocusTrap`, `focusable` query, or Tab keydown handler).",
                    path=document.path,
                    line=1,
                    metadata={"pattern": "missing-focus-trap"},
                )
            )

        return tuple(findings)

    def _run_raw_error_in_error_boundary_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.security.no-raw-error-in-error-boundary")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _ERROR_BOUNDARY_FILE_PATTERN.search(document.path):
                continue
            for match in _RAW_ERROR_EXPRESSION_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, match.group(0))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="Rendering raw `error.message` or `error.stack` in an error boundary leaks potentially sensitive details to users.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "raw-error-expression"},
                    )
                )

        return tuple(findings)

    def _run_unvalidated_external_href_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.security.no-unvalidated-external-href")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match in _UNVALIDATED_EXTERNAL_HREF_PATTERN.finditer(document.comment_masked_text):
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="`href` interpolated from external data without scheme validation; wrap through a validation helper.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "unvalidated-external-href"},
                    )
                )

        return tuple(findings)

    def _run_concurrent_token_refresh_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.reliability.no-concurrent-token-refresh")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _AXIOS_INTERCEPTOR_SIGNAL_PATTERN.search(document.masked_text):
                continue
            if not _REFRESH_TOKEN_CALL_PATTERN.search(document.masked_text):
                continue
            if _IS_REFRESHING_GUARD_PATTERN.search(document.masked_text):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message="Auth interceptor calls `refreshToken` without an `isRefreshing` mutex or in-flight promise deduplication guard.",
                    path=document.path,
                    line=1,
                    metadata={"pattern": "concurrent-token-refresh"},
                )
            )

        return tuple(findings)

    def _run_eager_heavy_dependency_import_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.performance.no-eager-heavy-dependency-import")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match in _HEAVY_DEPENDENCY_IMPORT_PATTERN.finditer(document.comment_masked_text):
                source = match.group("source")
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line, source)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=f"Static import of heavy dependency `{source}` can bloat the initial bundle; prefer dynamic `import()` or `next/dynamic`.",
                        path=document.path,
                        line=line,
                        metadata={"source": source},
                    )
                )

        return tuple(findings)

    def _run_ephemeral_ids_for_deep_linking_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-ephemeral-ids-for-deep-linking")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _DEEP_LINK_FILE_PATTERN.search(document.path):
                continue
            for match in _EPHEMERAL_ID_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, match.group(0))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="Deep-link query param uses an ephemeral ID (`uid()`, `crypto.randomUUID()`, or `useId()`); use a stable key instead.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "ephemeral-id"},
                    )
                )

        return tuple(findings)

    def _run_console_in_production_browser_code_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule(
            "typescript.maintainability.no-console-in-production-browser-code"
        )
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if document.path.endswith(".test.ts") or document.path.endswith(".test.tsx"):
                continue
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match in _CONSOLE_CALL_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, match.group(0))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="`console` call left in production browser code; remove or replace with a structured logger.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "console-call"},
                    )
                )

        return tuple(findings)

    def _run_unvalidated_numeric_precision_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.correctness.no-unvalidated-numeric-precision")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _NUMERIC_INPUT_PATTERN.search(document.comment_masked_text):
                continue
            if _NUMERIC_PRECISION_VALIDATION_PATTERN.search(document.masked_text):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message="Numeric input lacks precision validation (`toFixed`, `precision`, `step`, or `decimalPlaces`); add an explicit bound.",
                    path=document.path,
                    line=1,
                    metadata={"pattern": "missing-numeric-precision"},
                )
            )

        return tuple(findings)

    def _run_unauthenticated_image_blob_urls_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-unauthenticated-image-blob-urls")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match in _IMAGE_SRC_INTERPOLATION_PATTERN.finditer(document.comment_masked_text):
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="Image URL built from raw filename interpolation without auth params; append tenant-scoped or signed query parameters.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "unauthenticated-image-src"},
                    )
                )

        return tuple(findings)

    def _run_inline_filter_logic_in_components_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.architecture.no-inline-filter-logic-in-components")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match in _USEMEMO_FILTER_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="Non-trivial `useMemo` filter logic inside a component should be extracted to a named helper module with tests.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "inline-usememo-filter"},
                    )
                )

        return tuple(findings)

    def _run_unvalidated_url_tab_param_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.correctness.no-unvalidated-url-tab-param")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int]] = set()

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            for match in _TAB_PARAM_READ_PATTERN.finditer(document.comment_masked_text):
                line = _line_for_offset(document.comment_masked_text, match.start())
                key = (document.path, line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                if _TAB_ALLOWLIST_CHECK_PATTERN.search(document.comment_masked_text):
                    continue
                findings.append(
                    self._build_finding(
                        rule,
                        message="URL `tab` parameter is read without an explicit allowlist validation; add `VALID_TABS.includes(...)` before use.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "unvalidated-tab-param"},
                    )
                )

        return tuple(findings)

    def _run_number_input_without_wheel_blur_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.accessibility.no-number-input-without-wheel-blur")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if document.path.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
                continue
            if not _looks_like_shared_input_component_path(document.path):
                continue
            if not _HTML_INPUT_ELEMENT_PATTERN.search(document.masked_text):
                continue
            has_number_type = bool(
                _NUMBER_INPUT_TYPE_LITERAL_PATTERN.search(document.masked_text)
                or (
                    _NUMBER_INPUT_DYNAMIC_TYPE_PATTERN.search(document.masked_text)
                    and _SHARED_INPUT_COMPONENT_PATTERN.search(document.masked_text)
                )
            )
            if not has_number_type:
                continue
            if _NUMBER_INPUT_WHEEL_BLUR_GUARD_PATTERN.search(document.masked_text):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message=(
                        "Shared Input renders a number field without a wheel-blur guard; "
                        "add `onWheel` blur handling or `shouldBlurNumberInputOnWheel`."
                    ),
                    path=document.path,
                    line=1,
                    metadata={"pattern": "missing-number-input-wheel-blur"},
                )
            )

        return tuple(findings)

    def _run_client_api_url_in_server_backend_fetch_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.web.no-client-api-url-in-server-backend-fetch")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            if not _looks_like_server_api_module_path(document.path):
                continue
            if _SERVER_BACKEND_URL_HELPER_DEFINITION_PATTERN.search(document.masked_text):
                continue
            for match in _SERVER_API_CLIENT_URL_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                pattern = match.group(0)
                key = (document.path, line, pattern)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message=(
                            "server-api route uses client-facing API URL wiring "
                            f"(`{pattern}`); use getServerBackendApiBaseUrl or "
                            "buildServerBackendApiUrl instead."
                        ),
                        path=document.path,
                        line=line,
                        metadata={"pattern": "client-api-url-in-server-backend-fetch"},
                    )
                )

        return tuple(findings)

    def _run_module_level_throwing_side_effect_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.reliability.no-module-level-throwing-side-effect")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, str]] = set()

        for document in documents:
            for match in _MODULE_LEVEL_THROWING_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line, match.group(0))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="Module-level statement may throw at import time; defer into component scope with try/catch.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "module-level-throwing"},
                    )
                )

        return tuple(findings)

    def _run_formdata_for_raw_binary_upload_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.reliability.no-formdata-for-raw-binary-upload")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _FORMDATA_CONSTRUCT_PATTERN.search(document.comment_masked_text):
                continue
            if not _PUT_METHOD_PATTERN.search(document.comment_masked_text):
                continue
            if not _S3_UPLOAD_URL_PATTERN.search(document.comment_masked_text):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message="`FormData` used as body for an S3 pre-signed PUT or raw-binary upload; upload the Blob/ArrayBuffer directly instead.",
                    path=document.path,
                    line=1,
                    metadata={"pattern": "formdata-raw-binary-upload"},
                )
            )

        return tuple(findings)

    def _run_unbounded_buffer_without_chunking_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.reliability.no-unbounded-buffer-without-chunking")
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int]] = set()

        for document in documents:
            for match in _UNBOUNDED_BUFFER_PUSH_PATTERN.finditer(document.masked_text):
                line = _line_for_offset(document.masked_text, match.start())
                key = (document.path, line)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    self._build_finding(
                        rule,
                        message="Unbounded array accumulation without chunking or size limits can cause memory exhaustion; add a retention cap or flush threshold.",
                        path=document.path,
                        line=line,
                        metadata={"pattern": "unbounded-buffer-push"},
                    )
                )

        return tuple(findings)

    def _run_websocket_reconnect_after_unmount_rule(
        self, documents: Sequence[_SourceDocument]
    ) -> tuple[NormalizedFinding, ...]:
        rule = self._require_rule("typescript.react.no-websocket-reconnect-after-unmount")
        findings: list[NormalizedFinding] = []

        for document in documents:
            if not _should_scan_web_boundary_surface_path(document.path):
                continue
            if not _WEBSOCKET_ONCLOSE_PATTERN.search(document.masked_text):
                continue
            if _MOUNTED_REF_GUARD_PATTERN.search(document.masked_text):
                continue
            findings.append(
                self._build_finding(
                    rule,
                    message="WebSocket `onclose` handler schedules a reconnect timer without checking a `mountedRef` or cleanup flag; guard against post-unmount execution.",
                    path=document.path,
                    line=1,
                    metadata={"pattern": "websocket-reconnect-no-mount-guard"},
                )
            )

        return tuple(findings)

    def _has_external_symbol_reference(
        self,
        *,
        symbol_name: str,
        owner_path: str,
        repo_documents: Sequence[_SourceDocument],
    ) -> bool:
        pattern = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(symbol_name)}(?![A-Za-z0-9_$])")
        for document in repo_documents:
            if document.path == owner_path:
                continue
            if pattern.search(document.masked_text):
                return True
        return False

    def _iter_target_documents(self, context: AdapterContext) -> Iterable[_SourceDocument]:
        candidate_paths: Iterable[str]
        if context.mode.value == "inventory":
            candidate_paths = _iter_repo_ts_paths(context.repo_root)
        else:
            candidate_paths = context.target_files or context.changed_files

        seen: set[str] = set()
        for relative_path in candidate_paths:
            normalized = Path(relative_path).as_posix()
            if normalized in seen or not _is_supported_ts_path(normalized):
                continue
            absolute_path = context.repo_root / normalized
            if not absolute_path.is_file():
                continue
            seen.add(normalized)
            text = absolute_path.read_text(encoding="utf-8", errors="replace")
            yield _SourceDocument(
                path=normalized,
                text=text,
                masked_text=_mask_non_code(text),
                comment_masked_text=_mask_comments(text),
            )

    def _load_repo_documents(self, repo_root: Path) -> tuple[_SourceDocument, ...]:
        documents: list[_SourceDocument] = []
        for relative_path in _iter_repo_ts_paths(repo_root):
            path = repo_root / relative_path
            text = path.read_text(encoding="utf-8", errors="replace")
            documents.append(
                _SourceDocument(
                    path=relative_path,
                    text=text,
                    masked_text=_mask_non_code(text),
                    comment_masked_text=_mask_comments(text),
                )
            )
        return tuple(documents)

    def _looks_like_unsafe_boundary(self, declaration: str) -> bool:
        if _ANY_BOUNDARY_PATTERN.search(declaration):
            return True
        return bool(_RECORD_BOUNDARY_PATTERN.search(declaration))

    def _require_rule(self, rule_id: str) -> RuleDefinition:
        rule = self._rules[rule_id]
        if rule is None:
            raise RuntimeError(f"Missing rule definition for {rule_id}")
        return rule

    def _build_finding(
        self,
        rule: RuleDefinition,
        *,
        message: str,
        path: str,
        line: int,
        metadata: dict[str, str] | None = None,
    ) -> NormalizedFinding:
        return NormalizedFinding.from_rule(
            rule,
            message=message,
            location=FindingLocation(path=path, line=line),
            adapter_id=self.adapter_key,
            language=RepoLanguage.TYPESCRIPT,
            metadata=metadata,
        )


def _collect_exported_symbols(masked_text: str) -> tuple[_ExportedSymbol, ...]:
    symbols: list[_ExportedSymbol] = []
    for match in _EXPORT_PATTERN.finditer(masked_text):
        kind = match.group("kind").replace("async ", "")
        symbols.append(
            _ExportedSymbol(
                name=match.group("name"),
                kind=kind,
                line=_line_for_offset(masked_text, match.start()),
                is_default=bool(match.group("default")),
                declaration=_extract_declaration(masked_text, match.start(), kind),
            )
        )
    return tuple(symbols)


def _extract_declaration(masked_text: str, start: int, kind: str) -> str:
    if kind == "interface":
        first_brace = masked_text.find("{", start)
        if first_brace == -1:
            return _extract_until_newline(masked_text, start)
        end = _find_matching_delimiter(masked_text, first_brace, "{", "}")
        return masked_text[start : end + 1]

    if kind in {"function", "class", "enum"}:
        first_brace = masked_text.find("{", start)
        if first_brace == -1:
            return _extract_until_newline(masked_text, start)
        return masked_text[start:first_brace]

    if kind == "type":
        return _extract_until_statement_end(masked_text, start)

    if kind == "const":
        return _extract_const_declaration(masked_text, start)

    return _extract_until_newline(masked_text, start)


def _extract_until_newline(masked_text: str, start: int) -> str:
    end = masked_text.find("\n", start)
    if end == -1:
        end = len(masked_text)
    return masked_text[start:end]


def _extract_until_statement_end(masked_text: str, start: int) -> str:
    depth_paren = 0
    depth_brace = 0
    depth_bracket = 0

    for index in range(start, len(masked_text)):
        char = masked_text[index]
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace = max(depth_brace - 1, 0)
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket = max(depth_bracket - 1, 0)
        elif char == ";" and depth_paren == depth_brace == depth_bracket == 0:
            return masked_text[start : index + 1]
        elif (
            char == "\n"
            and depth_paren == depth_brace == depth_bracket == 0
            and _starts_top_level_statement(masked_text, index + 1)
        ):
            return masked_text[start:index]
    return masked_text[start:]


def _extract_const_declaration(masked_text: str, start: int) -> str:
    arrow_index = _find_top_level_arrow(masked_text, start)
    if arrow_index is not None:
        return masked_text[start:arrow_index]
    return _extract_until_statement_end(masked_text, start)


def _find_top_level_arrow(masked_text: str, start: int) -> int | None:
    depth_paren = 0
    depth_brace = 0
    depth_bracket = 0

    for index in range(start, len(masked_text) - 1):
        char = masked_text[index]
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace = max(depth_brace - 1, 0)
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket = max(depth_bracket - 1, 0)
        elif (
            char == "="
            and masked_text[index + 1] == ">"
            and depth_paren == depth_brace == depth_bracket == 0
        ):
            return index
    return None


def _starts_top_level_statement(masked_text: str, start: int) -> bool:
    index = start
    while index < len(masked_text) and masked_text[index] in {" ", "\t"}:
        index += 1
    return masked_text.startswith(
        (
            "export ",
            "const ",
            "let ",
            "var ",
            "function ",
            "class ",
            "interface ",
            "type ",
            "enum ",
        ),
        index,
    )


def _find_matching_delimiter(masked_text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(masked_text)):
        char = masked_text[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return len(masked_text) - 1


def _find_statement_end(masked_text: str, start: int, stop: int) -> int:
    depth_paren = 0
    depth_brace = 0
    depth_bracket = 0

    for index in range(start, stop):
        char = masked_text[index]
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif char == "{":
            depth_brace += 1
        elif char == "}":
            if depth_brace == 0 and depth_paren == depth_bracket == 0:
                return index - 1
            depth_brace = max(depth_brace - 1, 0)
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket = max(depth_bracket - 1, 0)
        elif char == ";" and depth_paren == depth_brace == depth_bracket == 0:
            return index
    return stop - 1


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_top_level_segment_offset(text: str, offset: int) -> bool:
    depth_paren = 0
    depth_bracket = 0
    brace_contexts: list[str] = []

    for index in range(offset):
        char = text[index]
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif char == "{":
            brace_contexts.append(_classify_brace_context(text, index))
        elif char == "}":
            if brace_contexts:
                brace_contexts.pop()
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket = max(depth_bracket - 1, 0)
    return depth_paren == depth_bracket == 0 and "function" not in brace_contexts


def _normalize_handle_expression(handle: str) -> str:
    return re.sub(r"\s+", "", handle)


def _classify_brace_context(text: str, opening_brace: int) -> str:
    prefix = text[max(0, opening_brace - 160) : opening_brace]
    if re.search(
        r"(?:=>|function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^{}]*\))\s*$",
        prefix,
    ):
        return "function"
    return "other"


def _should_skip_unused_export_path(path: str) -> bool:
    return Path(path).name in _SKIP_UNUSED_EXPORT_BASENAMES


def _is_supported_ts_file(path: Path) -> bool:
    return _is_supported_ts_path(path.name if not path.is_absolute() else path.as_posix())


def _is_supported_ts_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    suffix = Path(normalized).suffix.lower()
    return suffix in _TS_SUFFIXES and not normalized.endswith(".d.ts")


def _iter_repo_ts_paths(repo_root: Path) -> tuple[str, ...]:
    paths: list[str] = []
    for current_root, dir_names, file_names in os.walk(repo_root):
        dir_names[:] = sorted(
            name for name in dir_names if name not in _SKIP_DIRS and not name.startswith(".cache")
        )
        current_root_path = Path(current_root)
        for file_name in sorted(file_names):
            path = current_root_path / file_name
            relative_path = path.relative_to(repo_root).as_posix()
            if _is_supported_ts_path(relative_path):
                paths.append(relative_path)
    return tuple(paths)


def _should_scan_ui_rule_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.name.endswith(_UI_RULE_EXCLUDED_SUFFIXES):
        return False
    return not any(part in _UI_RULE_EXCLUDED_PARTS for part in candidate.parts)


def _is_ui_module_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.suffix.lower() != ".tsx" or not _should_scan_ui_rule_path(normalized):
        return False
    if candidate.name in _UI_MODULE_ROUTE_BASENAMES:
        return True
    return any(part in _UI_MODULE_SURFACE_PARTS for part in candidate.parts)


def _ui_module_kind(path: str) -> str:
    candidate = Path(path.replace("\\", "/"))
    if candidate.name in _UI_MODULE_ROUTE_BASENAMES:
        if candidate.name == "page.tsx":
            return "page"
        if candidate.name == "layout.tsx":
            return "layout"
        return "route-module"
    parts = {part.lower() for part in candidate.parts}
    if "screens" in parts or "screen" in parts:
        return "screen"
    if "features" in parts:
        return "feature"
    if "components" in parts:
        return "component"
    return "ui-module"


def _ui_module_line_threshold(module_kind: str) -> int:
    if module_kind in {"layout", "page", "route-module"}:
        return _UI_ROUTE_MODULE_CODE_LINE_THRESHOLD
    return _UI_MODULE_CODE_LINE_THRESHOLD


def _effective_ts_code_line_count(masked_text: str) -> int:
    return sum(1 for line in masked_text.splitlines() if line.strip())


def _is_support_module_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    stem_tokens = {token for token in re.split(r"[^a-z0-9]+", candidate.stem.lower()) if token}
    if candidate.suffix.lower() != ".ts":
        return False
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    return bool(
        lower_parts.intersection(_SUPPORT_MODULE_SURFACE_PARTS)
        or stem_tokens.intersection(_SUPPORT_MODULE_FILENAME_TOKENS)
    )


def _support_module_kind(path: str) -> str:
    candidate = Path(path.replace("\\", "/"))
    lower_parts = {part.lower() for part in candidate.parts}
    stem_tokens = {token for token in re.split(r"[^a-z0-9]+", candidate.stem.lower()) if token}
    if (
        "types" in lower_parts
        or "type" in lower_parts
        or stem_tokens.intersection({"type", "types"})
    ):
        return "type-module"
    if (
        "utils" in lower_parts
        or "util" in lower_parts
        or stem_tokens.intersection({"util", "utils"})
    ):
        return "utility-module"
    if (
        "helpers" in lower_parts
        or "helper" in lower_parts
        or stem_tokens.intersection({"helper", "helpers"})
    ):
        return "helper-module"
    return "support-module"


def _support_module_line_threshold(module_kind: str) -> int:
    if module_kind == "type-module":
        return _SUPPORT_TYPE_MODULE_CODE_LINE_THRESHOLD
    return _SUPPORT_MODULE_CODE_LINE_THRESHOLD


def _is_interactive_page_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    return candidate.name == "page.tsx" and _should_scan_web_boundary_surface_path(normalized)


def _collect_interactive_page_signal_categories(masked_text: str) -> tuple[str, ...]:
    categories: list[str] = []
    if _INTERACTIVE_PAGE_STATE_SIGNAL_PATTERN.search(masked_text):
        categories.append("state")
    if _INTERACTIVE_PAGE_QUERY_SIGNAL_PATTERN.search(masked_text):
        categories.append("query")
    if _INTERACTIVE_PAGE_MUTATION_SIGNAL_PATTERN.search(masked_text):
        categories.append("mutation")
    if (
        _INTERACTIVE_PAGE_EVENT_SIGNAL_PATTERN.search(masked_text)
        or "addEventListener(" in masked_text
    ):
        categories.append("event")
    return tuple(categories)


def _collect_hook_call_names(masked_text: str) -> tuple[str, ...]:
    return tuple(match.group("hook") for match in _HOOK_CALL_PATTERN.finditer(masked_text))


def _has_nearby_page_test(page_path: str, repo_documents: Sequence[_SourceDocument]) -> bool:
    page_dir = Path(page_path.replace("\\", "/")).parent
    route_tokens = _page_route_tokens(page_path)
    nearby_test_dirs = {page_dir.as_posix(), (page_dir / "__tests__").as_posix()}

    for document in repo_documents:
        if not document.path.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
            continue
        candidate = Path(document.path.replace("\\", "/"))
        if (
            candidate.parent.as_posix() not in nearby_test_dirs
            and not candidate.parent.as_posix().startswith("src/__tests__")
        ):
            continue
        if _looks_like_page_focused_test(
            candidate,
            document.comment_masked_text,
            route_tokens,
            page_path,
        ):
            return True
    return False


def _looks_like_page_focused_test(
    path: Path,
    comment_masked_text: str,
    route_tokens: Sequence[str],
    page_path: str,
) -> bool:
    lowered_name = path.name.lower()
    if lowered_name in {"page.spec.ts", "page.spec.tsx", "page.test.ts", "page.test.tsx"}:
        return True
    if _NEARBY_PAGE_IMPORT_PATTERN.search(comment_masked_text):
        return True
    for import_source, _ in _collect_import_sources(comment_masked_text):
        if _import_source_matches_page(import_source, path.as_posix(), page_path):
            return True
    return "page" in lowered_name and any(token in lowered_name for token in route_tokens[-2:])


def _page_route_tokens(page_path: str) -> tuple[str, ...]:
    tokens: list[str] = []
    for part in Path(page_path.replace("\\", "/")).parent.parts:
        lowered = part.lower()
        if lowered in {"app", "pages", "src"}:
            continue
        if lowered.startswith("(") and lowered.endswith(")"):
            continue
        if lowered.startswith("[") and lowered.endswith("]"):
            continue
        token = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
        if token:
            tokens.append(token)
    return tuple(tokens)


def _import_source_matches_page(import_source: str, importing_path: str, page_path: str) -> bool:
    resolved_path = _resolve_import_source_path(import_source, importing_path)
    if resolved_path is None:
        return False
    normalized_page_path = page_path.replace("\\", "/")
    return resolved_path in {
        normalized_page_path,
        Path(normalized_page_path).with_suffix("").as_posix(),
    }


def _resolve_import_source_path(import_source: str, importing_path: str) -> str | None:
    normalized_source = import_source.strip().replace("\\", "/")
    if normalized_source.startswith(("./", "../")):
        base_dir = Path(importing_path.replace("\\", "/")).parent.as_posix()
        return posixpath.normpath(posixpath.join(base_dir, normalized_source))
    if normalized_source.startswith(("@/", "~/")):
        return posixpath.normpath(posixpath.join("src", normalized_source[2:]))
    if normalized_source.startswith("src/"):
        return posixpath.normpath(normalized_source)
    return None


def _should_scan_icon_button_accessibility_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return Path(normalized).suffix.lower() == ".tsx" and _should_scan_web_boundary_surface_path(
        normalized
    )


def _collect_icon_import_names(masked_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for match in _ICON_LIBRARY_IMPORT_PATTERN.finditer(masked_text):
        clause = " ".join(match.group("clause").split())
        if "{" in clause and "}" in clause:
            before_named, _, named_remainder = clause.partition("{")
            default_name = before_named.rstrip(", ").strip()
            if default_name and not default_name.startswith("*"):
                names.add(default_name)
            named_clause, _, _ = named_remainder.partition("}")
            for raw_name in named_clause.split(","):
                candidate = raw_name.strip()
                if not candidate:
                    continue
                if " as " in candidate:
                    _, _, local_name = candidate.partition(" as ")
                    candidate = local_name.strip()
                names.add(candidate)
            continue
        default_name = clause.split(",", maxsplit=1)[0].strip()
        if default_name and not default_name.startswith("*"):
            names.add(default_name)
    return tuple(sorted(name for name in names if name))


def _collect_import_sources(comment_masked_text: str) -> tuple[tuple[str, int], ...]:
    return tuple(
        (match.group("source"), _line_for_offset(comment_masked_text, match.start()))
        for match in _IMPORT_STATEMENT_PATTERN.finditer(comment_masked_text)
    )


def _collect_react_use_effect_import_aliases(masked_text: str) -> _ReactUseEffectImports:
    direct_names: set[str] = set()
    namespace_names: set[str] = set()

    for match in _IMPORT_STATEMENT_PATTERN.finditer(masked_text):
        if match.group("source") != "react":
            continue

        clause = " ".join(match.group("clause").split())
        if not clause or clause.startswith("type "):
            continue

        if clause.startswith("* as "):
            namespace_name = clause.removeprefix("* as ").strip()
            if namespace_name:
                namespace_names.add(namespace_name)
            continue

        if "{" in clause and "}" in clause:
            before_named, _, named_remainder = clause.partition("{")
            default_name = before_named.rstrip(", ").strip()
            if default_name and not default_name.startswith("*"):
                namespace_names.add(default_name)

            named_clause, _, _ = named_remainder.partition("}")
            for raw_name in named_clause.split(","):
                candidate = raw_name.strip()
                if not candidate or candidate.startswith("type "):
                    continue
                imported_name = candidate
                local_name = candidate
                if " as " in candidate:
                    imported_name, _, local_name = candidate.partition(" as ")
                    imported_name = imported_name.strip()
                    local_name = local_name.strip()
                if imported_name == "useEffect" and local_name:
                    direct_names.add(local_name)
            continue

        default_name = clause.split(",", maxsplit=1)[0].strip()
        if default_name and not default_name.startswith("*"):
            namespace_names.add(default_name)

    return _ReactUseEffectImports(
        direct_names=tuple(sorted(direct_names)),
        namespace_names=tuple(sorted(namespace_names)),
    )


def _find_first_react_use_effect_call(
    masked_text: str, imports: _ReactUseEffectImports
) -> _ReactUseEffectCall | None:
    matches: list[_ReactUseEffectCall] = []

    for alias in imports.direct_names:
        pattern = re.compile(
            _REACT_DIRECT_USE_EFFECT_PATTERN_TEMPLATE.format(alias=re.escape(alias))
        )
        for match in pattern.finditer(masked_text):
            matches.append(_ReactUseEffectCall(offset=match.start(), pattern=alias))

    for alias in imports.namespace_names:
        pattern = re.compile(
            _REACT_MEMBER_USE_EFFECT_PATTERN_TEMPLATE.format(alias=re.escape(alias))
        )
        for match in pattern.finditer(masked_text):
            matches.append(_ReactUseEffectCall(offset=match.start(), pattern=f"{alias}.useEffect"))

    if not matches:
        return None

    return min(matches, key=lambda match: match.offset)


def _collect_react_use_sync_external_store_import_aliases(
    masked_text: str,
) -> _ReactUseSyncExternalStoreImports:
    direct_names: set[str] = set()
    namespace_names: set[str] = set()

    for match in _IMPORT_STATEMENT_PATTERN.finditer(masked_text):
        if match.group("source") != "react":
            continue

        clause = " ".join(match.group("clause").split())
        if not clause or clause.startswith("type "):
            continue

        if clause.startswith("* as "):
            namespace_name = clause.removeprefix("* as ").strip()
            if namespace_name:
                namespace_names.add(namespace_name)
            continue

        if "{" in clause and "}" in clause:
            before_named, _, named_remainder = clause.partition("{")
            default_name = before_named.rstrip(", ").strip()
            if default_name and not default_name.startswith("*"):
                namespace_names.add(default_name)

            named_clause, _, _ = named_remainder.partition("}")
            for raw_name in named_clause.split(","):
                candidate = raw_name.strip()
                if not candidate or candidate.startswith("type "):
                    continue
                imported_name = candidate
                local_name = candidate
                if " as " in candidate:
                    imported_name, _, local_name = candidate.partition(" as ")
                    imported_name = imported_name.strip()
                    local_name = local_name.strip()
                if imported_name == "useSyncExternalStore" and local_name:
                    direct_names.add(local_name)
            continue

        default_name = clause.split(",", maxsplit=1)[0].strip()
        if default_name and not default_name.startswith("*"):
            namespace_names.add(default_name)

    return _ReactUseSyncExternalStoreImports(
        direct_names=tuple(sorted(direct_names)),
        namespace_names=tuple(sorted(namespace_names)),
    )


def _collect_react_use_sync_external_store_calls(
    masked_text: str, imports: _ReactUseSyncExternalStoreImports
) -> tuple[_ReactUseSyncExternalStoreCall, ...]:
    matches: list[_ReactUseSyncExternalStoreCall] = []

    for alias in imports.direct_names:
        pattern = re.compile(
            _REACT_DIRECT_USE_SYNC_EXTERNAL_STORE_PATTERN_TEMPLATE.format(alias=re.escape(alias))
        )
        for match in pattern.finditer(masked_text):
            matches.append(
                _ReactUseSyncExternalStoreCall(
                    offset=match.start(),
                    opening_paren_offset=match.end() - 1,
                    pattern=alias,
                )
            )

    for alias in imports.namespace_names:
        pattern = re.compile(
            _REACT_MEMBER_USE_SYNC_EXTERNAL_STORE_PATTERN_TEMPLATE.format(alias=re.escape(alias))
        )
        for match in pattern.finditer(masked_text):
            matches.append(
                _ReactUseSyncExternalStoreCall(
                    offset=match.start(),
                    opening_paren_offset=match.end() - 1,
                    pattern=f"{alias}.useSyncExternalStore",
                )
            )

    return tuple(sorted(matches, key=lambda match: match.offset))


def _collect_shared_ui_button_component_names(comment_masked_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for match in _IMPORT_STATEMENT_PATTERN.finditer(comment_masked_text):
        source = match.group("source")
        if not _is_shared_ui_button_import_source(source):
            continue
        clause = " ".join(match.group("clause").split())
        if clause.startswith("type "):
            continue
        if "{" in clause and "}" in clause:
            before_named, _, named_remainder = clause.partition("{")
            default_name = before_named.rstrip(", ").strip()
            if default_name and not default_name.startswith("*") and "Button" in default_name:
                names.add(default_name)
            named_clause, _, _ = named_remainder.partition("}")
            for raw_name in named_clause.split(","):
                candidate = raw_name.strip()
                if not candidate:
                    continue
                if " as " in candidate:
                    _, _, local_name = candidate.partition(" as ")
                    candidate = local_name.strip()
                if "Button" in candidate:
                    names.add(candidate)
            continue
        default_name = clause.split(",", maxsplit=1)[0].strip()
        if default_name and not default_name.startswith("*") and "Button" in default_name:
            names.add(default_name)
    return tuple(sorted(names))


def _is_shared_ui_button_import_source(source: str) -> bool:
    normalized = source.replace("\\", "/").lower()
    return "/ui/" in normalized and bool(re.search(r"(?:^|/)(?:button|buttons)(?:$|/)", normalized))


def _iter_button_like_matches(masked_text: str, component_names: Sequence[str]):
    for match in _BUTTON_ELEMENT_PATTERN.finditer(masked_text):
        yield "button", match
    for component_name in component_names:
        pattern = re.compile(
            rf"<{re.escape(component_name)}(?P<attrs>[^>]*)>(?P<body>.*?)</{re.escape(component_name)}>",
            re.DOTALL,
        )
        for match in pattern.finditer(masked_text):
            yield component_name, match


def _button_body_has_accessible_text(body: str) -> bool:
    visible_text = re.sub(r"<[^>]+>", " ", body)
    return bool(re.search(r"[A-Za-z0-9]", visible_text))


def _button_body_looks_icon_only(body: str, icon_names: Sequence[str]) -> bool:
    if "<svg" in body:
        return True
    if _GENERIC_ICON_COMPONENT_PATTERN.search(body):
        return True
    return any(re.search(rf"<\s*{re.escape(name)}\b", body) for name in icon_names)


def _collect_direct_api_imports(comment_masked_text: str) -> tuple[tuple[str, int], ...]:
    direct_imports: dict[str, int] = {}
    for match in _DIRECT_API_IMPORT_PATTERN.finditer(comment_masked_text):
        source = match.group("source")
        direct_imports.setdefault(source, _line_for_offset(comment_masked_text, match.start()))
    return tuple(sorted(direct_imports.items(), key=lambda item: (item[1], item[0])))


def _should_scan_lifecycle_rule_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.name.endswith(_UI_RULE_EXCLUDED_SUFFIXES):
        return False
    return not any(part in _LIFECYCLE_RULE_EXCLUDED_PARTS for part in candidate.parts)


def _should_scan_react_stack_effect_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.suffix.lower() not in _TS_SUFFIXES:
        return False
    if candidate.name.endswith(_REACT_STACK_EXCLUDED_SUFFIXES):
        return False
    return not any(part in _REACT_STACK_EXCLUDED_PARTS for part in candidate.parts)


def _should_scan_e2e_canary_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.suffix.lower() not in {".ts", ".tsx"}:
        return False
    return "e2e" in {part.lower() for part in candidate.parts}


def _extract_enclosing_function_scope(comment_masked_text: str, offset: int) -> str | None:
    search_region = comment_masked_text[:offset]
    function_starts: list[int] = []
    for match in _ENCLOSING_FUNCTION_PATTERN.finditer(search_region):
        brace_index = search_region.find("{", match.end() - 1)
        if brace_index >= 0:
            function_starts.append(brace_index)
    if not function_starts:
        return None
    brace_index = function_starts[-1]
    closing_brace = _find_matching_delimiter(comment_masked_text, brace_index, "{", "}")
    return comment_masked_text[brace_index : closing_brace + 1]


def _supports_web_boundary_rules(repo_profile) -> bool:
    frameworks = set(repo_profile.frameworks)
    return "react" in frameworks and "react-native" not in frameworks


def _supports_react_stack_rules(repo_profile) -> bool:
    return "react" in set(repo_profile.frameworks)


def _collect_route_contract_signals(
    repo_documents: Sequence[_SourceDocument],
) -> _RouteContractSignals:
    manifest_paths: list[str] = []
    access_policy_paths: list[str] = []
    codec_paths: list[str] = []
    scope_guard_paths: list[str] = []
    route_families: list[str] = []

    for document in repo_documents:
        if _looks_like_route_manifest_path(document.path) and _has_route_manifest_signal(document):
            manifest_paths.append(document.path)
            route_families.extend(_collect_route_families(document.comment_masked_text))
        if _looks_like_route_access_policy_path(document.path) and _has_route_access_policy_signal(
            document
        ):
            access_policy_paths.append(document.path)
        if _looks_like_route_query_codec_path(document.path) and _has_route_query_codec_signal(
            document
        ):
            codec_paths.append(document.path)
        if _looks_like_scope_guard_path(document.path) and _has_scope_guard_signal(document):
            scope_guard_paths.append(document.path)

    return _RouteContractSignals(
        manifest_paths=tuple(dict.fromkeys(manifest_paths)),
        access_policy_paths=tuple(dict.fromkeys(access_policy_paths)),
        codec_paths=tuple(dict.fromkeys(codec_paths)),
        scope_guard_paths=tuple(dict.fromkeys(scope_guard_paths)),
        route_families=tuple(dict.fromkeys(route_families)),
    )


def _collect_tenant_boundary_signals(
    repo_documents: Sequence[_SourceDocument],
) -> _TenantBoundarySignals:
    auth_boundary_paths: list[str] = []
    context_surface_paths: list[str] = []

    for document in repo_documents:
        if _looks_like_tenant_auth_boundary_path(
            document.path
        ) and _has_tenant_auth_boundary_signal(document):
            auth_boundary_paths.append(document.path)
        if _is_allowed_tenant_context_surface_path(
            document.path
        ) and _has_tenant_context_surface_signal(document):
            context_surface_paths.append(document.path)

    return _TenantBoundarySignals(
        auth_boundary_paths=tuple(dict.fromkeys(auth_boundary_paths)),
        context_surface_paths=tuple(dict.fromkeys(context_surface_paths)),
    )


def _collect_web_boundary_signals(
    repo_documents: Sequence[_SourceDocument],
) -> _WebBoundarySignals:
    transport_layer_paths: list[str] = []
    normalization_layer_paths: list[str] = []

    for document in repo_documents:
        if _looks_like_transport_layer_path(document.path) and _has_transport_layer_signal(
            document
        ):
            transport_layer_paths.append(document.path)
        if _looks_like_normalization_layer_path(document.path):
            normalization_layer_paths.append(document.path)

    return _WebBoundarySignals(
        transport_layer_paths=tuple(dict.fromkeys(transport_layer_paths)),
        normalization_layer_paths=tuple(dict.fromkeys(normalization_layer_paths)),
    )


def _collect_web_browser_sideeffect_signals(
    repo_documents: Sequence[_SourceDocument],
) -> _WebBrowserSideEffectSignals:
    dialog_boundary_paths: list[str] = []
    navigation_boundary_paths: list[str] = []
    storage_boundary_paths: list[str] = []
    modal_controller_paths: list[str] = []
    scroll_lock_boundary_paths: list[str] = []
    has_router_api_surface = False

    for document in repo_documents:
        if _looks_like_dialog_boundary_path(document.path) and _has_dialog_boundary_signal(
            document
        ):
            dialog_boundary_paths.append(document.path)
        if _has_router_api_signal(document):
            has_router_api_surface = True
        if _looks_like_navigation_boundary_path(document.path) and _has_hard_navigation_signal(
            document
        ):
            navigation_boundary_paths.append(document.path)
        if _looks_like_storage_boundary_path(document.path) and _has_storage_boundary_signal(
            document
        ):
            storage_boundary_paths.append(document.path)
        if _looks_like_modal_controller_path(document.path) and _has_modal_controller_signal(
            document
        ):
            modal_controller_paths.append(document.path)
        if _looks_like_scroll_lock_boundary_path(
            document.path
        ) and _has_scroll_lock_boundary_signal(document):
            scroll_lock_boundary_paths.append(document.path)

    return _WebBrowserSideEffectSignals(
        dialog_boundary_paths=tuple(dict.fromkeys(dialog_boundary_paths)),
        navigation_boundary_paths=tuple(dict.fromkeys(navigation_boundary_paths)),
        storage_boundary_paths=tuple(dict.fromkeys(storage_boundary_paths)),
        modal_controller_paths=tuple(dict.fromkeys(modal_controller_paths)),
        scroll_lock_boundary_paths=tuple(dict.fromkeys(scroll_lock_boundary_paths)),
        has_router_api_surface=has_router_api_surface,
    )


def _collect_web_query_cache_signals(
    repo_documents: Sequence[_SourceDocument],
) -> _WebQueryCacheSignals:
    boundary_paths: list[str] = []

    for document in repo_documents:
        if _looks_like_query_cache_boundary_path(document.path):
            boundary_paths.append(document.path)

    return _WebQueryCacheSignals(boundary_paths=tuple(dict.fromkeys(boundary_paths)))


def _collect_query_hook_key_references(comment_masked_text: str) -> tuple[_QueryKeyReference, ...]:
    references: list[_QueryKeyReference] = []
    seen: set[tuple[int, tuple[str, ...], str]] = set()

    for match in _QUERY_HOOK_CALL_PATTERN.finditer(comment_masked_text):
        opening_paren = match.end() - 1
        closing_paren = _find_matching_delimiter(comment_masked_text, opening_paren, "(", ")")
        hook_args = comment_masked_text[opening_paren + 1 : closing_paren]
        for offset, segments in _iter_query_key_property_segments(hook_args):
            line = _line_for_offset(comment_masked_text, opening_paren + 1 + offset)
            key = (line, segments, match.group("hook"))
            if key in seen:
                continue
            seen.add(key)
            references.append(
                _QueryKeyReference(
                    segments=segments,
                    line=line,
                    source=match.group("hook"),
                )
            )

    return tuple(references)


def _collect_query_cache_key_references(
    comment_masked_text: str,
) -> tuple[_QueryKeyReference, ...]:
    references: list[_QueryKeyReference] = []
    seen: set[tuple[int, tuple[str, ...], str]] = set()

    for match in _QUERY_CACHE_KEY_OPERATION_PATTERN.finditer(comment_masked_text):
        opening_paren = match.end() - 1
        closing_paren = _find_matching_delimiter(comment_masked_text, opening_paren, "(", ")")
        call_args = comment_masked_text[opening_paren + 1 : closing_paren]
        first_argument = _extract_first_argument_text(call_args)
        if first_argument is None:
            continue
        segments = _extract_query_key_segments_from_argument_text(first_argument)
        if segments is None:
            continue
        line = _line_for_offset(comment_masked_text, match.start("method"))
        key = (line, segments, match.group("method"))
        if key in seen:
            continue
        seen.add(key)
        references.append(
            _QueryKeyReference(
                segments=segments,
                line=line,
                source=match.group("method"),
            )
        )

    return tuple(references)


def _is_query_key_registry_path(path: str) -> bool:
    return Path(path).name in {"query-keys.ts", "queryKeys.ts"}


def _collect_inline_query_key_violations(
    comment_masked_text: str,
) -> tuple[_InlineQueryKeyViolation, ...]:
    violations: list[_InlineQueryKeyViolation] = []
    seen: set[tuple[int, str, str]] = set()

    for match in _QUERY_HOOK_CALL_PATTERN.finditer(comment_masked_text):
        opening_paren = match.end() - 1
        closing_paren = _find_matching_delimiter(comment_masked_text, opening_paren, "(", ")")
        hook_args = comment_masked_text[opening_paren + 1 : closing_paren]
        hook_name = match.group("hook")

        for offset, segments in _iter_query_key_property_segments(hook_args):
            line = _line_for_offset(comment_masked_text, opening_paren + 1 + offset)
            rendered_key = _render_query_key_segments(segments)
            key = (line, hook_name, rendered_key)
            if key in seen:
                continue
            seen.add(key)
            violations.append(
                _InlineQueryKeyViolation(line=line, source=hook_name, rendered_key=rendered_key)
            )

        first_argument = _extract_first_argument_text(hook_args.lstrip())
        if first_argument is not None and first_argument.lstrip().startswith("["):
            segments = _extract_static_query_key_segments(first_argument.lstrip())
            if segments is not None:
                line = _line_for_offset(comment_masked_text, opening_paren + 1)
                rendered_key = _render_query_key_segments(segments)
                key = (line, hook_name, rendered_key)
                if key not in seen:
                    seen.add(key)
                    violations.append(
                        _InlineQueryKeyViolation(
                            line=line,
                            source=hook_name,
                            rendered_key=rendered_key,
                        )
                    )

    for match in _MUTATION_DECLARATION_PATTERN.finditer(comment_masked_text):
        opening_paren = comment_masked_text.find("(", match.start())
        if opening_paren < 0:
            continue
        closing_paren = _find_matching_delimiter(comment_masked_text, opening_paren, "(", ")")
        mutation_args = comment_masked_text[opening_paren + 1 : closing_paren]
        for property_pattern, source in (
            (_INLINE_QUERY_KEY_ARRAY_PATTERN, "useMutation.queryKey"),
            (_MUTATION_KEY_PROPERTY_PATTERN, "useMutation.mutationKey"),
        ):
            for property_match in property_pattern.finditer(mutation_args):
                bracket_start = property_match.end() - 1
                closing_bracket = _find_matching_delimiter(
                    mutation_args,
                    bracket_start,
                    "[",
                    "]",
                )
                segments = _extract_static_query_key_segments(
                    mutation_args[bracket_start : closing_bracket + 1]
                )
                if segments is None:
                    continue
                line = _line_for_offset(
                    comment_masked_text,
                    opening_paren + 1 + property_match.start(),
                )
                rendered_key = _render_query_key_segments(segments)
                key = (line, source, rendered_key)
                if key in seen:
                    continue
                seen.add(key)
                violations.append(
                    _InlineQueryKeyViolation(line=line, source=source, rendered_key=rendered_key)
                )

    for match in _QUERY_CACHE_KEY_OPERATION_PATTERN.finditer(comment_masked_text):
        opening_paren = match.end() - 1
        closing_paren = _find_matching_delimiter(comment_masked_text, opening_paren, "(", ")")
        call_args = comment_masked_text[opening_paren + 1 : closing_paren]
        first_argument = _extract_first_argument_text(call_args)
        if first_argument is None:
            continue
        segments = _extract_query_key_segments_from_argument_text(first_argument)
        if segments is None:
            continue
        line = _line_for_offset(comment_masked_text, match.start("method"))
        rendered_key = _render_query_key_segments(segments)
        source = match.group("method")
        key = (line, source, rendered_key)
        if key in seen:
            continue
        seen.add(key)
        violations.append(
            _InlineQueryKeyViolation(line=line, source=source, rendered_key=rendered_key)
        )

    return tuple(violations)


def _collect_mutation_declarations(comment_masked_text: str) -> tuple[tuple[str, int], ...]:
    return tuple(
        (
            match.group("name"),
            _line_for_offset(comment_masked_text, match.start("name")),
        )
        for match in _MUTATION_DECLARATION_PATTERN.finditer(comment_masked_text)
    )


def _find_mutation_trigger_line(comment_masked_text: str, mutation_name: str) -> int | None:
    pattern = re.compile(rf"\b{re.escape(mutation_name)}\s*\.\s*(?:mutate|mutateAsync)\s*\(")
    match = pattern.search(comment_masked_text)
    if match is None:
        return None
    return _line_for_offset(comment_masked_text, match.start())


def _document_has_mutation_pending_guard(comment_masked_text: str, mutation_name: str) -> bool:
    guard_patterns = (
        rf"\bif\s*\(\s*{re.escape(mutation_name)}\s*\.\s*isPending\b[^)]*\)\s*(?:return\b|\{{)",
        rf"\bdisabled\s*=\s*\{{[^}}]*{re.escape(mutation_name)}\s*\.\s*isPending[^}}]*\}}",
        rf"\baria-disabled\s*=\s*\{{[^}}]*{re.escape(mutation_name)}\s*\.\s*isPending[^}}]*\}}",
        rf"\baria-busy\s*=\s*\{{[^}}]*{re.escape(mutation_name)}\s*\.\s*isPending[^}}]*\}}",
    )
    return any(re.search(pattern, comment_masked_text) for pattern in guard_patterns)


def _collect_web_semantic_token_signals(
    repo_documents: Sequence[_SourceDocument],
) -> _WebSemanticTokenSignals:
    helper_paths: list[str] = []
    token_paths: list[str] = []

    for document in repo_documents:
        if _looks_like_web_semantic_helper_path(document.path) and _has_web_semantic_helper_signal(
            document
        ):
            helper_paths.append(document.path)
            continue
        if _looks_like_web_semantic_token_path(document.path) and _has_web_semantic_token_signal(
            document
        ):
            token_paths.append(document.path)

    return _WebSemanticTokenSignals(
        helper_paths=tuple(dict.fromkeys(helper_paths)),
        token_paths=tuple(dict.fromkeys(token_paths)),
    )


def _looks_like_server_route_module_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name not in _SERVER_ROUTE_BASENAMES:
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    return bool(lower_parts.intersection({"api", "server", "server-api"}))


def _looks_like_server_api_module_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if "server-api" not in lower_parts:
        return False
    return not any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts)


def _looks_like_shared_input_component_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    stem = candidate.stem.lower()
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if stem in {"input", "textfield", "text-input"}:
        return True
    if "components" in lower_parts and "ui" in lower_parts:
        return True
    return stem == "input" and "components" in lower_parts


def _looks_like_app_server_api_route_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    return (
        candidate.name in _SERVER_ROUTE_BASENAMES
        and "app" in lower_parts
        and bool(lower_parts.intersection({"api", "server-api"}))
        and not any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts)
    )


def _looks_like_tenant_auth_boundary_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    stem_tokens = set(_stem_tokens(normalized))
    if candidate.name in _SERVER_ROUTE_BASENAMES:
        return False
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    has_auth_signal = bool(lower_parts.intersection({"auth", "session"})) or bool(
        stem_tokens.intersection({"auth", "cookie", "cookies", "jwt", "session", "token"})
    )
    has_tenant_signal = "tenant" in lower_parts or "tenant" in stem_tokens
    return has_auth_signal and has_tenant_signal


def _is_allowed_tenant_context_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    stem_tokens = set(_stem_tokens(normalized))
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if candidate.name in _TENANT_CONTEXT_ALLOWED_BASENAMES:
        return True
    has_tenant_signal = "tenant" in lower_parts or "tenant" in stem_tokens
    if {"provider", "providers"}.intersection(lower_parts) and has_tenant_signal:
        return True
    if "bootstrap" in lower_parts and has_tenant_signal:
        return True
    if "bootstrap" in stem_tokens and has_tenant_signal:
        return True
    return bool(stem_tokens.intersection({"provider", "providers"}) and has_tenant_signal)


def _should_scan_tenant_context_surface_path(path: str, approved_paths: set[str]) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if normalized in approved_paths or _is_allowed_tenant_context_surface_path(normalized):
        return False
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    return not any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts)


def _has_tenant_auth_boundary_signal(document: _SourceDocument) -> bool:
    lower_text = document.masked_text.lower()
    return "tenant" in lower_text and (
        _AUTH_COOKIE_READ_PATTERN.search(document.comment_masked_text) is not None
        or _DIRECT_JWT_LIBRARY_CALL_PATTERN.search(document.masked_text) is not None
        or _ATOB_JWT_PAYLOAD_PATTERN.search(document.comment_masked_text) is not None
    )


def _has_tenant_context_surface_signal(document: _SourceDocument) -> bool:
    lower_text = document.masked_text.lower()
    return "tenant" in lower_text and (
        _TENANT_BOOTSTRAP_GLOBAL_PATTERN.search(document.comment_masked_text) is not None
        or _HOST_TENANT_RESOLUTION_SIGNAL_PATTERN.search(document.comment_masked_text) is not None
        or _TENANT_SNAPSHOT_IDENTIFIER_PATTERN.search(document.masked_text) is not None
        or re.search(r"\b(?:Provider|createContext|middleware)\b", document.masked_text) is not None
    )


def _has_authenticated_tenant_cross_check(masked_text: str) -> bool:
    if _AUTHENTICATED_TENANT_CROSSCHECK_PATTERN.search(masked_text):
        return True
    if _TENANT_ACCESS_GUARD_WITH_AUTH_AND_ROUTE_PATTERN.search(masked_text):
        return True
    return bool(
        _AUTHENTICATED_TENANT_SIGNAL_PATTERN.search(masked_text)
        and _TENANT_ACCESS_GUARD_CALL_PATTERN.search(masked_text)
    )


def _tenant_auth_boundary_hint(signals: _TenantBoundarySignals) -> str:
    if signals.auth_boundary_paths:
        return signals.auth_boundary_paths[0]
    return "a shared auth boundary helper"


def _tenant_context_boundary_hint(signals: _TenantBoundarySignals) -> str:
    if signals.context_surface_paths:
        return signals.context_surface_paths[0]
    return "an approved tenant bootstrap/provider surface"


def _describe_direct_jwt_source(text: str) -> str:
    match = _DIRECT_JWT_LIBRARY_CALL_PATTERN.search(text)
    if match is not None:
        receiver = match.group("receiver").lower()
        method = match.group("method").lower()
        return f"{receiver}.{method}"
    return "JSON.parse(atob(...))"


def _iter_server_tenant_resolution_matches(text: str):
    seen: set[tuple[int, str, str]] = set()
    patterns = (
        (_TENANT_ROUTE_HELPER_PATTERN, "tenant-id-helper"),
        (_TENANT_REQUEST_HEADER_PATTERN, "header-tenant"),
        (_TENANT_SEARCH_PARAM_PATTERN, "search-param-tenant"),
        (_TENANT_ROUTE_PARAM_PATTERN, "route-param-tenant"),
    )
    for pattern, label in patterns:
        for match in pattern.finditer(text):
            source = (
                match.groupdict().get("name") or match.groupdict().get("expr") or match.group(0)
            ).strip()
            line = _line_for_offset(text, match.start())
            key = (line, label, source)
            if key in seen:
                continue
            seen.add(key)
            yield line, label, source


def _iter_direct_jwt_tenant_derivation_matches(text: str):
    seen: set[tuple[int, str, str]] = set()
    direct_patterns = (
        (_DIRECT_JWT_TENANT_DESTRUCTURE_PATTERN, "destructured-jwt-tenant-claim"),
        (_DIRECT_JWT_TENANT_INLINE_ACCESS_PATTERN, "inline-jwt-tenant-access"),
    )
    for pattern, label in direct_patterns:
        for match in pattern.finditer(text):
            line = _line_for_offset(text, match.start())
            source = _describe_direct_jwt_source(match.group(0))
            key = (line, label, source)
            if key in seen:
                continue
            seen.add(key)
            yield line, label, source

    for match in _DIRECT_JWT_PAYLOAD_ASSIGNMENT_PATTERN.finditer(text):
        variable_name = match.group("name")
        claim_access_pattern = re.compile(
            rf"\b{re.escape(variable_name)}\s*\??\.\s*tenant(?:Id|Slug)?\b"
            rf"|\b{re.escape(variable_name)}\s*\[\s*['\"`](?:tenant(?:Id|Slug)?)['\"`]\s*\]",
            re.IGNORECASE,
        )
        if claim_access_pattern.search(text, match.end()) is None:
            continue
        line = _line_for_offset(text, match.start())
        source = _describe_direct_jwt_source(match.group(0))
        key = (line, "decoded-jwt-payload", source)
        if key in seen:
            continue
        seen.add(key)
        yield line, "decoded-jwt-payload", source


def _iter_direct_tenant_context_access_matches(text: str):
    seen: set[tuple[int, str, str]] = set()

    for line, raw_line in enumerate(text.splitlines(), start=1):
        line_text = raw_line.strip()
        if not line_text:
            continue

        bootstrap_match = _TENANT_BOOTSTRAP_GLOBAL_PATTERN.search(line_text)
        if bootstrap_match is not None:
            source = re.sub(r"\s+", "", bootstrap_match.group(0))
            key = (line, "bootstrap-global", source)
            if key not in seen:
                seen.add(key)
                yield line, "bootstrap-global", source

        host_helper_match = _TENANT_FROM_HOST_HELPER_PATTERN.search(line_text)
        if host_helper_match is not None:
            source = host_helper_match.group(0)
            key = (line, "host-derived-tenant", source)
            if key not in seen:
                seen.add(key)
                yield line, "host-derived-tenant", source
        else:
            host_signal_match = _HOST_TENANT_RESOLUTION_SIGNAL_PATTERN.search(line_text)
            if host_signal_match is not None and "tenant" in line_text.lower():
                source = re.sub(r"\s+", "", host_signal_match.group(0))
                key = (line, "host-derived-tenant", source)
                if key not in seen:
                    seen.add(key)
                    yield line, "host-derived-tenant", source

        if bootstrap_match is not None:
            continue
        if "=" not in line_text and not line_text.startswith("return "):
            continue
        snapshot_match = _TENANT_SNAPSHOT_IDENTIFIER_PATTERN.search(line_text)
        if snapshot_match is None:
            continue
        source = snapshot_match.group(0)
        lowered_source = source.lower()
        if lowered_source.endswith("provider") or lowered_source.endswith("context"):
            continue
        key = (line, "tenant-snapshot", source)
        if key in seen:
            continue
        seen.add(key)
        yield line, "tenant-snapshot", source


def _has_transport_layer_signal(document: _SourceDocument) -> bool:
    if _RAW_FETCH_CALL_PATTERN.search(document.masked_text) or _RAW_AXIOS_CALL_PATTERN.search(
        document.masked_text
    ):
        return True

    stem_tokens = _stem_tokens(document.path)
    return _has_transport_filename_signal(stem_tokens)


def _has_transport_filename_signal(stem_tokens: Sequence[str]) -> bool:
    token_set = set(stem_tokens)
    if token_set.intersection({"fetcher", "http", "request", "transport"}):
        return True
    return "client" in token_set and bool(token_set.intersection(_WEB_TRANSPORT_CLIENT_CO_TOKENS))


def _looks_like_transport_layer_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if candidate.name in {"route.ts", "route.tsx"}:
        return False
    if lower_parts.intersection(_WEB_TRANSPORT_LAYER_PARTS):
        return True
    stem_tokens = _stem_tokens(normalized)
    if lower_parts.intersection(_WEB_TRANSPORT_SERVICE_PARTS) and _has_transport_filename_signal(
        stem_tokens
    ):
        return True
    return bool(
        _has_transport_filename_signal(stem_tokens)
        and (
            {"lib", "src"}.intersection(lower_parts)
            or lower_parts.intersection(_WEB_TRANSPORT_SERVICE_PARTS)
        )
    )


def _looks_like_normalization_layer_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = _stem_tokens(normalized)
    return bool(
        lower_parts.intersection(_WEB_NORMALIZATION_LAYER_PARTS)
        or any(token in stem_tokens for token in _WEB_NORMALIZATION_FILENAME_TOKENS)
    )


def _looks_like_dialog_boundary_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return any(required.issubset(stem_tokens) for required in _DIALOG_BOUNDARY_REQUIRED_TOKENS)


def _has_dialog_boundary_signal(document: _SourceDocument) -> bool:
    return bool(_DIALOG_BOUNDARY_COMPONENT_SIGNAL_PATTERN.search(document.masked_text))


def _has_router_api_signal(document: _SourceDocument) -> bool:
    return bool(
        _ROUTER_IMPORT_SIGNAL_PATTERN.search(document.masked_text)
        or _ROUTER_USAGE_SIGNAL_PATTERN.search(document.masked_text)
    )


def _looks_like_navigation_boundary_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return bool(
        stem_tokens.intersection(_NAVIGATION_BOUNDARY_HELPER_TOKENS)
        and lower_parts.intersection(_WEB_HELPER_CONTAINER_PARTS)
    )


def _has_hard_navigation_signal(document: _SourceDocument) -> bool:
    return bool(
        _WINDOW_LOCATION_CALL_PATTERN.search(document.masked_text)
        or _WINDOW_LOCATION_ASSIGNMENT_PATTERN.search(document.masked_text)
    )


def _looks_like_storage_boundary_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return bool(
        stem_tokens.intersection(_STORAGE_BOUNDARY_HELPER_TOKENS)
        and lower_parts.intersection(_WEB_HELPER_CONTAINER_PARTS)
    )


def _has_storage_boundary_signal(document: _SourceDocument) -> bool:
    return bool(_DIRECT_BROWSER_STORAGE_PATTERN.search(document.masked_text))


def _looks_like_modal_controller_path(path: str) -> bool:
    stem_tokens = set(_stem_tokens(path.replace("\\", "/")))
    return {"controller", "modal"}.issubset(stem_tokens)


def _has_modal_controller_signal(document: _SourceDocument) -> bool:
    return bool(
        "createBrowserModalController" in document.text
        or _MODAL_DOCUMENT_KEYDOWN_PATTERN.search(document.text)
    )


def _looks_like_scroll_lock_boundary_path(path: str) -> bool:
    stem_tokens = set(_stem_tokens(path.replace("\\", "/")))
    return {"scroll", "lock"}.issubset(stem_tokens)


def _has_scroll_lock_boundary_signal(document: _SourceDocument) -> bool:
    return "overflow = 'hidden'" in document.text or 'overflow = "hidden"' in document.text


def _looks_like_query_cache_boundary_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    lower_stem = candidate.stem.lower()
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if {"lib", "libs"}.intersection(lower_parts) and lower_parts.intersection(
        _QUERY_CACHE_BOUNDARY_CONTAINER_PARTS
    ):
        return True
    return any(hint in lower_stem for hint in _QUERY_CACHE_BOUNDARY_FILENAME_HINTS)


def _looks_like_web_semantic_helper_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return bool(
        (
            lower_parts.intersection(_WEB_SEMANTIC_HELPER_CONTAINER_PARTS)
            or ("components" in lower_parts and "ui" in lower_parts)
        )
        and (
            candidate.stem == "index"
            or stem_tokens.intersection(_WEB_SEMANTIC_HELPER_FILENAME_TOKENS)
        )
    )


def _has_web_semantic_helper_signal(document: _SourceDocument) -> bool:
    for match in _SEMANTIC_STATUS_HELPER_DECLARATION_PATTERN.finditer(document.masked_text):
        if _is_semantic_status_helper_name(match.group("name")):
            return True
    return False


def _looks_like_web_semantic_token_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return bool(
        lower_parts.intersection(_WEB_SEMANTIC_TOKEN_CONTAINER_PARTS)
        or stem_tokens.intersection({"palette", "theme", "token", "tokens"})
    )


def _has_web_semantic_token_signal(document: _SourceDocument) -> bool:
    return bool(
        _document_has_semantic_status_context(document.path, document.comment_masked_text)
        and (
            _SEMANTIC_TAILWIND_STATUS_CLASS_PATTERN.search(document.comment_masked_text)
            or _SEMANTIC_STATUS_COLOR_LITERAL_PATTERN.search(document.comment_masked_text)
        )
    )


def _should_scan_web_boundary_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if candidate.name in {"route.ts", "route.tsx"}:
        return False
    if _looks_like_transport_layer_path(normalized) or _looks_like_normalization_layer_path(
        normalized
    ):
        return False
    return bool(
        lower_parts.intersection(_WEB_BOUNDARY_SURFACE_PARTS)
        or candidate.name in _WEB_BOUNDARY_SURFACE_BASENAMES
    )


def _should_scan_web_sideeffect_surface_path(path: str, approved_paths: Sequence[str]) -> bool:
    normalized = path.replace("\\", "/")
    return normalized not in set(approved_paths) and _should_scan_web_boundary_surface_path(
        normalized
    )


def _should_scan_web_query_cache_surface_path(path: str, approved_paths: set[str]) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if normalized in approved_paths:
        return False
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if _looks_like_query_cache_boundary_path(normalized):
        return False
    return bool(
        lower_parts.intersection(_WEB_QUERY_CACHE_SURFACE_PARTS)
        or "ui" in lower_parts
        or candidate.name in _WEB_BOUNDARY_SURFACE_BASENAMES
    )


def _should_scan_web_semantic_path(path: str, approved_paths: set[str]) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if normalized in approved_paths:
        return False
    if candidate.name.endswith(_WEB_BOUNDARY_EXCLUDED_SUFFIXES):
        return False
    return not any(part.lower() in _WEB_BOUNDARY_EXCLUDED_PARTS for part in candidate.parts)


def _should_scan_route_contract_surface_path(path: str, signals: _RouteContractSignals) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    approved_paths = {
        *signals.manifest_paths,
        *signals.access_policy_paths,
        *signals.codec_paths,
        *signals.scope_guard_paths,
    }
    if normalized in approved_paths:
        return False
    if candidate.name.endswith(_ROUTE_CONTRACT_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _ROUTE_CONTRACT_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if candidate.name in {"route.ts", "route.tsx"}:
        return False
    return bool(
        lower_parts.intersection(_ROUTE_CONTRACT_SURFACE_PARTS)
        or candidate.name in _ROUTE_CONTRACT_SURFACE_BASENAMES
    )


def _iter_raw_transport_matches(masked_text: str):
    for match in _RAW_FETCH_CALL_PATTERN.finditer(masked_text):
        yield match, "fetch"
    for match in _RAW_AXIOS_CALL_PATTERN.finditer(masked_text):
        yield match, "axios"


def _iter_direct_response_cast_matches(masked_text: str):
    patterns = (
        (_DIRECT_RESPONSE_JSON_CAST_PATTERN, "response-json-cast"),
        (_TYPED_RESPONSE_JSON_ASSIGNMENT_PATTERN, "typed-response-json"),
    )
    for pattern, label in patterns:
        for match in pattern.finditer(masked_text):
            yield match, label


def _has_shadowed_confirm_binding(masked_text: str) -> bool:
    return bool(_CONFIRM_SHADOW_SIGNAL_PATTERN.search(masked_text))


def _normalize_response_type(type_text: str) -> str:
    rendered = " ".join(type_text.split())
    return rendered.rstrip("),;")


def _looks_like_route_manifest_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    lower_parts = {part.lower() for part in candidate.parts}
    if candidate.name.endswith(_ROUTE_CONTRACT_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _ROUTE_CONTRACT_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if candidate.name in _ROUTE_CONTRACT_SURFACE_BASENAMES:
        return False
    stem_tokens = _stem_tokens(normalized)
    return bool(
        lower_parts.intersection(_ROUTE_MANIFEST_PATH_PARTS)
        or any(token in stem_tokens for token in _ROUTE_MANIFEST_FILENAME_TOKENS)
        or lower_parts.intersection(_ROUTE_MANIFEST_SHARED_NAV_TOKENS)
        or any(token in stem_tokens for token in _ROUTE_MANIFEST_SHARED_NAV_TOKENS)
    )


def _looks_like_route_access_policy_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.name.endswith(_ROUTE_CONTRACT_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _ROUTE_CONTRACT_EXCLUDED_PARTS for part in candidate.parts):
        return False
    if candidate.name in _ROUTE_CONTRACT_SURFACE_BASENAMES:
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return any(
        required_tokens.issubset(stem_tokens)
        for required_tokens in _ROUTE_ACCESS_POLICY_REQUIRED_TOKENS
    )


def _looks_like_route_query_codec_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.name.endswith(_ROUTE_CONTRACT_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _ROUTE_CONTRACT_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return any(
        required_tokens.issubset(stem_tokens)
        for required_tokens in _ROUTE_QUERY_CODEC_REQUIRED_TOKENS
    )


def _has_route_query_codec_signal(document: _SourceDocument) -> bool:
    return bool(
        _ROUTE_QUERY_CODEC_SIGNAL_PATTERN.search(document.masked_text)
        and (
            _ROUTE_PARAM_ACCESS_PATTERN.search(document.masked_text)
            or _SEARCH_PARAM_ACCESS_PATTERN.search(document.masked_text)
        )
    )


def _looks_like_scope_guard_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.name.endswith(_ROUTE_CONTRACT_EXCLUDED_SUFFIXES):
        return False
    if any(part.lower() in _ROUTE_CONTRACT_EXCLUDED_PARTS for part in candidate.parts):
        return False
    stem_tokens = set(_stem_tokens(normalized))
    return bool(
        stem_tokens.intersection(_SCOPE_GUARD_TOKENS)
        and stem_tokens.intersection(_ROUTE_GUARD_FILENAME_TOKENS)
    )


def _has_route_manifest_signal(document: _SourceDocument) -> bool:
    route_literals = _collect_document_route_literals(document.comment_masked_text)
    if len(route_literals) < 2:
        return False
    return bool(_EXPORTED_ROUTE_COLLECTION_PATTERN.search(document.masked_text)) and bool(
        _ROUTE_MANIFEST_ENTRY_PATTERN.search(document.comment_masked_text)
        or re.search(r"\b(?:nav|navigation|route|routes)\b", document.masked_text)
    )


def _has_route_access_policy_signal(document: _SourceDocument) -> bool:
    route_literals = _collect_document_route_literals(document.comment_masked_text)
    if not route_literals:
        return False
    lower_text = document.masked_text.lower()
    return any(token in lower_text for token in _ROUTE_ACCESS_POLICY_FILENAME_TOKENS) and bool(
        re.search(r"\b(?:allow|auth|path|protected|public|route)\b", lower_text)
    )


def _has_scope_guard_signal(document: _SourceDocument) -> bool:
    lower_text = document.masked_text.lower()
    return bool(
        _ROUTE_GUARD_SIGNAL_PATTERN.search(document.masked_text)
        and lower_text.count("branch") + lower_text.count("owner") + lower_text.count("tenant") >= 1
    )


def _iter_manifest_route_matches(text: str):
    for match in _ROUTE_MANIFEST_ENTRY_PATTERN.finditer(text):
        route = match.group("route")
        if _is_supported_page_route_literal(route):
            yield match, route


def _iter_root_route_literal_matches(text: str):
    for match in _ROOT_ROUTE_LITERAL_PATTERN.finditer(text):
        route = match.group("route")
        if _is_supported_page_route_literal(route):
            yield match, route


def _iter_route_access_policy_matches(text: str):
    seen_lines: set[tuple[int, str]] = set()
    for collection_match in _INLINE_ROUTE_POLICY_COLLECTION_PATTERN.finditer(text):
        if not _looks_like_inline_route_policy_name(collection_match.group("name")):
            continue
        opening_bracket = collection_match.end() - 1
        closing_bracket = _find_matching_delimiter(text, opening_bracket, "[", "]")
        segment = text[opening_bracket : closing_bracket + 1]
        for route_match, route in _iter_root_route_literal_matches(segment):
            offset = opening_bracket + route_match.start()
            line = _line_for_offset(text, offset)
            key = (line, route)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            yield offset, route, "inline-route-policy-collection"
    for match in _PATHNAME_ROUTE_CHECK_PATTERN.finditer(text):
        route = match.group("route")
        line = _line_for_offset(text, match.start())
        key = (line, route)
        if key in seen_lines:
            continue
        seen_lines.add(key)
        yield match.start(), route, "pathname-route-check"


def _collect_document_route_literals(text: str) -> tuple[str, ...]:
    routes = [route for _, route in _iter_root_route_literal_matches(text)]
    return tuple(dict.fromkeys(routes))


def _collect_route_families(text: str) -> tuple[str, ...]:
    families: list[str] = []
    for _, route in _iter_root_route_literal_matches(text):
        family = _extract_route_family(route)
        if family is not None:
            families.append(family)
    return tuple(dict.fromkeys(families))


def _looks_like_inline_route_policy_name(name: str) -> bool:
    tokens = tuple(part.lower() for part in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", name))
    if not tokens:
        tokens = tuple(part.lower() for part in re.split(r"[_-]+", name) if part)
    policy_tokens = {"access", "allowed", "auth", "protected", "public", "route", "routes"}
    route_tokens = {"path", "paths", "route", "routes"}
    token_set = set(tokens)
    return bool(token_set.intersection(policy_tokens) and token_set.intersection(route_tokens))


def _is_supported_page_route_literal(route: str) -> bool:
    return route.startswith("/") and not route.startswith("/api/")


def _extract_route_family(route: str) -> str | None:
    canonical = route.split("?", 1)[0].split("#", 1)[0]
    segments = [segment for segment in canonical.split("/") if segment]
    if not segments:
        return None
    family = segments[0]
    if family.startswith("${") or family.startswith("[") or family.startswith(":"):
        return None
    return family


def _normalize_route_family_stem(family: str) -> str:
    if family.endswith("ies") and len(family) > 3:
        return family[:-3] + "y"
    if family.endswith("ses") and len(family) > 3:
        return family[:-2]
    if family.endswith("s") and len(family) > 1:
        return family[:-1]
    return family


def _index_route_families_by_stem(families: Sequence[str]) -> dict[str, tuple[str, ...]]:
    indexed: dict[str, list[str]] = {}
    for family in families:
        indexed.setdefault(_normalize_route_family_stem(family), []).append(family)
    return {stem: tuple(dict.fromkeys(values)) for stem, values in indexed.items()}


def _resolve_canonical_route_family(
    family: str, canonical_families_by_stem: dict[str, tuple[str, ...]]
) -> str | None:
    canonicals = canonical_families_by_stem.get(_normalize_route_family_stem(family))
    if not canonicals:
        return None
    if family in canonicals:
        return family
    if len(canonicals) == 1:
        return canonicals[0]
    return None


def _is_scope_sensitive_detail_route(route: str) -> bool:
    canonical = route.split("?", 1)[0].split("#", 1)[0]
    segments = [segment for segment in canonical.split("/") if segment]
    if len(segments) < 4:
        return False
    dynamic_count = sum(
        segment.startswith("${")
        or segment.startswith("[")
        or segment.startswith(":")
        or "${" in segment
        for segment in segments
    )
    if dynamic_count < 2:
        return False
    static_segments = [
        segment.lower()
        for segment in segments
        if not (
            segment.startswith("${")
            or segment.startswith("[")
            or segment.startswith(":")
            or "${" in segment
        )
    ]
    if not any(segment in _ROUTE_CONTRACT_SCOPE_TOKENS for segment in static_segments):
        return False
    return segments[-1].startswith("${") or segments[-1].startswith("[") or "${" in segments[-1]


def _stem_tokens(path: str) -> tuple[str, ...]:
    stem = Path(path).stem
    return _identifier_tokens(stem)


def _identifier_tokens(value: str) -> tuple[str, ...]:
    pieces = re.split(r"[-_.]+", value)
    tokens: list[str] = []
    for piece in pieces:
        if not piece:
            continue
        expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", piece)
        tokens.extend(part.lower() for part in expanded.split() if part)
    return tuple(tokens)


def _is_semantic_status_helper_name(name: str) -> bool:
    token_set = set(_identifier_tokens(name))
    has_subject = bool(token_set.intersection(_SEMANTIC_STATUS_SUBJECT_TOKENS))
    has_descriptor = bool(token_set.intersection(_SEMANTIC_STATUS_DESCRIPTOR_TOKENS))
    if has_subject and has_descriptor:
        return True
    return "tone" in token_set and bool(token_set.intersection(_SEMANTIC_STATUS_SUBJECT_TOKENS))


def _has_semantic_status_context(path: str, text: str, offset: int) -> bool:
    window = text[max(0, offset - 160) : min(len(text), offset + 160)]
    if _SEMANTIC_STATUS_CONTEXT_PATTERN.search(window):
        return True
    return bool(set(_stem_tokens(path)).intersection(_SEMANTIC_STATUS_PATH_TOKENS))


def _document_has_semantic_status_context(path: str, text: str) -> bool:
    if _SEMANTIC_STATUS_CONTEXT_PATTERN.search(text):
        return True
    return bool(set(_stem_tokens(path)).intersection(_SEMANTIC_STATUS_PATH_TOKENS))


def _extract_semantic_tailwind_status_classes(value: str) -> tuple[str, ...]:
    classes = _SEMANTIC_TAILWIND_STATUS_CLASS_TOKEN_PATTERN.findall(value)
    return tuple(dict.fromkeys(classes))


def _semantic_boundary_hint(signals: _WebSemanticTokenSignals) -> str | None:
    if signals.helper_paths:
        return signals.helper_paths[0]
    if signals.token_paths:
        return signals.token_paths[0]
    return None


def _query_cache_boundary_hint(signals: _WebQueryCacheSignals) -> str:
    if signals.boundary_paths:
        return signals.boundary_paths[0]
    return "src/lib/cache"


def _iter_query_key_property_segments(text: str):
    for match in _QUERY_KEY_PROPERTY_PATTERN.finditer(text):
        value_start = _skip_whitespace(text, match.end())
        segments = _extract_query_key_segments_from_expression(text, value_start)
        if segments is not None:
            yield match.start(), segments


def _extract_first_argument_text(arguments_text: str) -> str | None:
    expressions = _split_top_level_expressions(arguments_text)
    if not expressions:
        return None
    return expressions[0]


def _extract_query_key_segments_from_argument_text(argument_text: str) -> tuple[str, ...] | None:
    trimmed_argument = argument_text.strip()
    if not trimmed_argument:
        return None
    if trimmed_argument[0] == "{":
        for _, segments in _iter_query_key_property_segments(trimmed_argument):
            return segments
        return None
    return _extract_query_key_segments_from_expression(trimmed_argument, 0)


def _extract_query_key_segments_from_expression(text: str, start: int) -> tuple[str, ...] | None:
    offset = _skip_whitespace(text, start)
    if offset >= len(text):
        return None
    char = text[offset]
    if char == "[":
        closing_bracket = _find_matching_delimiter(text, offset, "[", "]")
        return _extract_static_query_key_segments(text[offset : closing_bracket + 1])
    string_value = _extract_static_string_expression(text[offset:])
    if string_value is None:
        return None
    return (string_value,)


def _extract_static_query_key_segments(array_expression: str) -> tuple[str, ...] | None:
    if len(array_expression) < 2 or array_expression[0] != "[" or array_expression[-1] != "]":
        return None
    segments: list[str] = []
    for element in _split_top_level_expressions(array_expression[1:-1]):
        string_value = _extract_static_string_expression(element)
        if string_value is None:
            break
        segments.append(string_value)
    if not segments:
        return None
    return tuple(segments)


def _extract_static_string_expression(expression: str) -> str | None:
    trimmed_expression = expression.strip()
    if not trimmed_expression:
        return None
    parsed = _parse_static_string_literal(trimmed_expression, 0)
    if parsed is None:
        return None
    string_value, end = parsed
    remainder = trimmed_expression[end:].strip()
    if remainder.startswith("as const"):
        remainder = remainder[8:].strip()
    if remainder and remainder[0] not in {",", ")", "}", "]"}:
        return None
    return string_value


def _parse_static_string_literal(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] not in {"'", '"'}:
        return None
    quote = text[start]
    value_parts: list[str] = []
    index = start + 1

    while index < len(text):
        char = text[index]
        if char == "\\":
            if index + 1 >= len(text):
                return None
            value_parts.append(text[index + 1])
            index += 2
            continue
        if char == quote:
            return "".join(value_parts), index + 1
        if char == "\n":
            return None
        value_parts.append(char)
        index += 1

    return None


def _split_top_level_expressions(text: str) -> tuple[str, ...]:
    expressions: list[str] = []
    depth_paren = 0
    depth_brace = 0
    depth_bracket = 0
    quote = ""
    start = 0
    index = 0

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if quote:
            if char == "\\":
                index += 2 if next_char else 1
                continue
            if char == quote:
                quote = ""
            index += 1
            continue

        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace = max(depth_brace - 1, 0)
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket = max(depth_bracket - 1, 0)
        elif char == "," and depth_paren == depth_brace == depth_bracket == 0:
            expression = text[start:index].strip()
            if expression:
                expressions.append(expression)
            start = index + 1
        index += 1

    tail = text[start:].strip()
    if tail:
        expressions.append(tail)
    return tuple(expressions)


def _collect_external_store_snapshot_arguments(
    arguments_text: str,
) -> tuple[tuple[str, str], ...]:
    expressions = _split_top_level_expressions(arguments_text)
    snapshot_arguments: list[tuple[str, str]] = []
    if len(expressions) >= 2:
        snapshot_arguments.append(("getSnapshot", expressions[1]))
    if len(expressions) >= 3:
        snapshot_arguments.append(("getServerSnapshot", expressions[2]))
    return tuple(snapshot_arguments)


def _snapshot_expression_is_unstable(
    *, full_text: str, expression_text: str, seen: frozenset[str]
) -> bool:
    trimmed_expression = _normalize_snapshot_expression(expression_text)
    if not trimmed_expression:
        return False
    if _looks_like_unstable_snapshot_literal(trimmed_expression):
        return True

    if trimmed_expression.startswith("function"):
        body_start = trimmed_expression.find("{")
        if body_start == -1:
            return False
        body_end = _find_matching_delimiter(trimmed_expression, body_start, "{", "}")
        return _block_returns_unstable_snapshot_expression(
            full_text=full_text,
            block_text=trimmed_expression[body_start : body_end + 1],
            seen=seen,
        )

    arrow_index = trimmed_expression.find("=>")
    if arrow_index != -1:
        arrow_body = _normalize_snapshot_expression(trimmed_expression[arrow_index + 2 :])
        if not arrow_body:
            return False
        if arrow_body.startswith("{"):
            body_end = _find_matching_delimiter(arrow_body, 0, "{", "}")
            return _block_returns_unstable_snapshot_expression(
                full_text=full_text,
                block_text=arrow_body[: body_end + 1],
                seen=seen,
            )
        return _snapshot_expression_is_unstable(
            full_text=full_text,
            expression_text=arrow_body,
            seen=seen,
        )

    if _looks_like_unstable_snapshot_factory_call(trimmed_expression):
        return True

    symbol_reference = _extract_snapshot_symbol_reference(trimmed_expression)
    if symbol_reference is None:
        return False
    symbol_name, is_member_access = symbol_reference
    if symbol_name in seen:
        return False
    if is_member_access and not _has_snapshot_object_shorthand(full_text, symbol_name):
        return False
    return _named_snapshot_function_is_unstable(
        full_text=full_text,
        name=symbol_name,
        seen=seen | frozenset({symbol_name}),
    )


def _named_snapshot_function_is_unstable(
    *, full_text: str, name: str, seen: frozenset[str]
) -> bool:
    for block_text in _collect_named_snapshot_block_bodies(full_text, name):
        if _block_returns_unstable_snapshot_expression(
            full_text=full_text,
            block_text=block_text,
            seen=seen,
        ):
            return True

    for expression_text in _collect_named_snapshot_expression_bodies(full_text, name):
        if _snapshot_expression_is_unstable(
            full_text=full_text,
            expression_text=expression_text,
            seen=seen,
        ):
            return True

    return False


def _collect_named_snapshot_block_bodies(full_text: str, name: str) -> tuple[str, ...]:
    bodies: list[str] = []
    seen_regions: set[tuple[int, int]] = set()
    patterns = (
        re.compile(
            rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)\s*(?::\s*[^{{=\n]+)?\s*(?P<body>\{{)"
        ),
        re.compile(
            rf"\b(?:const|let|var)\s+{re.escape(name)}\s*(?::\s*[^=;\n]+)?=\s*function"
            r"(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\)\s*(?::\s*[^{{=\n]+)?\s*(?P<body>\{)"
        ),
        re.compile(
            rf"(?m)^[ \t]*{re.escape(name)}\s*\([^)]*\)\s*(?::\s*[^{{=\n]+)?\s*(?P<body>\{{)"
        ),
    )

    for pattern in patterns:
        for match in pattern.finditer(full_text):
            body_start = match.start("body")
            body_end = _find_matching_delimiter(full_text, body_start, "{", "}")
            key = (body_start, body_end)
            if key in seen_regions:
                continue
            seen_regions.add(key)
            bodies.append(full_text[body_start : body_end + 1])

    for pattern in (
        re.compile(
            rf"\b(?:const|let|var)\s+{re.escape(name)}\s*(?::\s*[^=;\n]+)?=\s*(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*"
        ),
        re.compile(
            rf"(?m)^[ \t]*{re.escape(name)}\s*:\s*(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*"
        ),
    ):
        for match in pattern.finditer(full_text):
            body_start = _skip_whitespace(full_text, match.end())
            if body_start >= len(full_text) or full_text[body_start] != "{":
                continue
            body_end = _find_matching_delimiter(full_text, body_start, "{", "}")
            key = (body_start, body_end)
            if key in seen_regions:
                continue
            seen_regions.add(key)
            bodies.append(full_text[body_start : body_end + 1])

    return tuple(bodies)


def _collect_named_snapshot_expression_bodies(full_text: str, name: str) -> tuple[str, ...]:
    expressions: list[str] = []
    seen_regions: set[tuple[int, int]] = set()
    patterns = (
        re.compile(
            rf"\b(?:const|let|var)\s+{re.escape(name)}\s*(?::\s*[^=;\n]+)?=\s*(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*"
        ),
        re.compile(
            rf"(?m)^[ \t]*{re.escape(name)}\s*:\s*(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*"
        ),
    )

    for pattern in patterns:
        for match in pattern.finditer(full_text):
            expression_start = _skip_whitespace(full_text, match.end())
            if expression_start >= len(full_text) or full_text[expression_start] == "{":
                continue
            expression_end = _find_statement_end(full_text, expression_start, len(full_text))
            key = (expression_start, expression_end)
            if key in seen_regions:
                continue
            seen_regions.add(key)
            expressions.append(full_text[expression_start:expression_end])

    return tuple(expressions)


def _block_returns_unstable_snapshot_expression(
    *, full_text: str, block_text: str, seen: frozenset[str]
) -> bool:
    if len(block_text) < 2 or block_text[0] != "{" or block_text[-1] != "}":
        return False

    inner_text = block_text[1:-1]
    for match in re.finditer(r"\breturn\b", inner_text):
        if not _is_top_level_segment_offset(inner_text, match.start()):
            continue
        expression_start = _skip_whitespace(inner_text, match.end())
        if expression_start >= len(inner_text):
            continue
        expression_end = _find_statement_end(inner_text, expression_start, len(inner_text))
        if _snapshot_expression_is_unstable(
            full_text=full_text,
            expression_text=inner_text[expression_start:expression_end],
            seen=seen,
        ):
            return True

    return False


def _normalize_snapshot_expression(expression_text: str) -> str:
    trimmed = expression_text.strip().rstrip(",;")
    while trimmed.startswith("(") and trimmed.endswith(")"):
        try:
            closing_paren = _find_matching_delimiter(trimmed, 0, "(", ")")
        except ValueError:
            break
        if closing_paren != len(trimmed) - 1:
            break
        trimmed = trimmed[1:-1].strip().rstrip(",;")
    return trimmed


def _looks_like_unstable_snapshot_literal(expression_text: str) -> bool:
    if not expression_text:
        return False

    opening = expression_text[0]
    if opening in {"{", "["}:
        closing = "}" if opening == "{" else "]"
        try:
            end = _find_matching_delimiter(expression_text, 0, opening, closing)
        except ValueError:
            end = -1
        if end == len(expression_text) - 1:
            return True
        if end >= 0:
            remainder = expression_text[end + 1 :].strip()
            if remainder.startswith(("as ", "satisfies ")):
                return True

    return bool(re.search(r"(?:\?\?|\|\|)\s*(?:\{|\[)", expression_text))


def _looks_like_unstable_snapshot_factory_call(expression_text: str) -> bool:
    return bool(
        re.match(
            r"(?:Array\.from|Object\.(?:assign|entries|keys|values)|structuredClone)\s*\(",
            expression_text,
        )
    )


def _extract_snapshot_symbol_reference(expression_text: str) -> tuple[str, bool] | None:
    match = re.fullmatch(
        r"(?P<symbol>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)"
        r"(?:\s*(?:<[^>]+>)?\s*\([^)]*\))?",
        expression_text,
    )
    if match is None:
        return None
    symbol = match.group("symbol")
    return symbol.split(".")[-1], "." in symbol


def _has_snapshot_object_shorthand(full_text: str, name: str) -> bool:
    return bool(re.search(rf"\{{[^{{}}]{{0,400}}\b{re.escape(name)}\b\s*(?:,|\}})", full_text))


def _skip_whitespace(text: str, start: int) -> int:
    index = start
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _query_key_segments_are_prefix_compatible(
    left: tuple[str, ...], right: tuple[str, ...]
) -> bool:
    if not left or not right:
        return False
    common_length = min(len(left), len(right))
    return left[:common_length] == right[:common_length]


def _render_query_key_segments(segments: Sequence[str]) -> str:
    return "/".join(segments)


def _iter_style_regions(text: str) -> tuple[_StyleRegion, ...]:
    regions: list[_StyleRegion] = []
    seen: set[tuple[int, int]] = set()

    for match in _STYLE_SHEET_CREATE_PATTERN.finditer(text):
        opening_brace = text.find("{", match.end())
        if opening_brace == -1:
            continue
        end = _find_matching_delimiter(text, opening_brace, "{", "}")
        key = (opening_brace, end)
        if key not in seen:
            seen.add(key)
            regions.append(_StyleRegion(start=opening_brace, end=end))

    for pattern in (_INLINE_STYLE_OBJECT_PATTERN, _STYLE_OBJECT_KEY_PATTERN):
        for match in pattern.finditer(text):
            opening_brace = match.start(1)
            end = _find_matching_delimiter(text, opening_brace, "{", "}")
            key = (opening_brace, end)
            if key not in seen:
                seen.add(key)
                regions.append(_StyleRegion(start=opening_brace, end=end))

    normalized: list[_StyleRegion] = []
    for region in sorted(regions, key=lambda item: (item.start, item.end)):
        if normalized and region.start >= normalized[-1].start and region.end <= normalized[-1].end:
            continue
        normalized.append(region)
    return tuple(normalized)


def _iter_lifecycle_regions(text: str) -> tuple[_LifecycleRegion, ...]:
    regions: list[_LifecycleRegion] = []
    seen: set[tuple[str, int, int]] = set()

    for match in _LIFECYCLE_HOOK_PATTERN.finditer(text):
        hook = match.group("hook")
        opening_paren = text.find("(", match.start())
        if opening_paren == -1:
            continue
        call_end = _find_matching_delimiter(text, opening_paren, "(", ")")
        call_text = text[opening_paren + 1 : call_end]
        callback_match = _LIFECYCLE_CALLBACK_BODY_PATTERN.search(call_text)
        if callback_match is None:
            continue
        body_start = opening_paren + 1 + callback_match.start("body")
        body_end = _find_matching_delimiter(text, body_start, "{", "}")
        if body_end > call_end:
            continue
        key = (hook, body_start, body_end)
        if key in seen:
            continue
        seen.add(key)
        regions.append(
            _LifecycleRegion(
                hook=hook,
                body_start=body_start,
                body_end=body_end,
                cleanup_regions=_iter_lifecycle_cleanup_regions(text, body_start, body_end),
            )
        )

    return tuple(sorted(regions, key=lambda item: (item.body_start, item.body_end)))


def _iter_readability_regions(text: str) -> tuple[_StyleRegion, ...]:
    regions: list[_StyleRegion] = []
    seen: set[tuple[int, int]] = set()

    for match in _STYLE_SHEET_CREATE_PATTERN.finditer(text):
        opening_brace = text.find("{", match.end())
        if opening_brace == -1:
            continue
        end = _find_matching_delimiter(text, opening_brace, "{", "}")
        outer_text = text[opening_brace : end + 1]
        for object_match in _STYLE_OBJECT_VALUE_PATTERN.finditer(outer_text):
            object_start = opening_brace + object_match.start(1)
            object_end = _find_matching_delimiter(text, object_start, "{", "}")
            key = (object_start, object_end)
            if key not in seen:
                seen.add(key)
                regions.append(_StyleRegion(start=object_start, end=object_end))

    for pattern in (_INLINE_STYLE_OBJECT_PATTERN, _STYLE_OBJECT_KEY_PATTERN):
        for match in pattern.finditer(text):
            opening_brace = match.start(1)
            end = _find_matching_delimiter(text, opening_brace, "{", "}")
            key = (opening_brace, end)
            if key not in seen:
                seen.add(key)
                regions.append(_StyleRegion(start=opening_brace, end=end))

    for match in _INLINE_STYLE_ARRAY_PATTERN.finditer(text):
        array_start = match.start(1)
        array_end = _find_matching_delimiter(text, array_start, "[", "]")
        array_text = text[array_start : array_end + 1]
        for object_match in _STYLE_ARRAY_OBJECT_PATTERN.finditer(array_text):
            object_start = array_start + object_match.start(1)
            object_end = _find_matching_delimiter(text, object_start, "{", "}")
            if object_end > array_end:
                continue
            key = (object_start, object_end)
            if key not in seen:
                seen.add(key)
                regions.append(_StyleRegion(start=object_start, end=object_end))

    return tuple(sorted(regions, key=lambda item: (item.start, item.end)))


def _iter_lifecycle_cleanup_regions(
    masked_text: str, body_start: int, body_end: int
) -> tuple[_StyleRegion, ...]:
    inner_text = masked_text[body_start + 1 : body_end]
    regions: list[_StyleRegion] = []
    seen: set[tuple[int, int]] = set()

    for match in _LIFECYCLE_CLEANUP_RETURN_PATTERN.finditer(inner_text):
        if not _is_top_level_segment_offset(inner_text, match.start()):
            continue
        cleanup_start = body_start + 1 + match.end()
        while cleanup_start < body_end and masked_text[cleanup_start] in {" ", "\t", "\n"}:
            cleanup_start += 1
        if cleanup_start >= body_end:
            continue
        if masked_text[cleanup_start] == "{":
            cleanup_end = _find_matching_delimiter(masked_text, cleanup_start, "{", "}")
        else:
            cleanup_end = _find_statement_end(masked_text, cleanup_start, body_end)
        key = (cleanup_start, cleanup_end)
        if key in seen:
            continue
        seen.add(key)
        regions.append(_StyleRegion(start=cleanup_start, end=cleanup_end))

    for match in _LIFECYCLE_CLEANUP_IDENTIFIER_RETURN_PATTERN.finditer(inner_text):
        if not _is_top_level_segment_offset(inner_text, match.start()):
            continue
        return_offset = body_start + 1 + match.start()
        named_region = _resolve_named_cleanup_region(
            masked_text,
            body_start=body_start,
            body_end=body_end,
            return_offset=return_offset,
            name=match.group("name"),
        )
        if named_region is None:
            continue
        key = (named_region.start, named_region.end)
        if key in seen:
            continue
        seen.add(key)
        regions.append(named_region)

    return tuple(regions)


def _collect_lifecycle_timers(
    *, region_text: str, region_start: int, full_text: str
) -> tuple[_LifecycleTimer, ...]:
    timers: list[_LifecycleTimer] = []
    inner_text = region_text[1:-1]
    inner_start = region_start + 1

    for match in _LIFECYCLE_TIMER_ASSIGNMENT_PATTERN.finditer(inner_text):
        if not _is_top_level_segment_offset(inner_text, match.start()):
            continue
        call_offset = inner_start + match.start("call")
        timer_call = match.group("call")
        timers.append(
            _LifecycleTimer(
                timer_kind="interval" if timer_call == "setInterval" else "timeout",
                timer_call=timer_call,
                handle=_normalize_handle_expression(match.group("handle")),
                line=_line_for_offset(full_text, call_offset),
            )
        )

    return tuple(timers)


def _classify_lifecycle_timer_cleanup(cleanup_texts: Sequence[str], timer: _LifecycleTimer) -> str:
    if timer.handle is None:
        return "untracked-handle"
    if not cleanup_texts:
        return "missing-cleanup"

    clear_call = "clearInterval" if timer.timer_kind == "interval" else "clearTimeout"
    for cleanup_text in cleanup_texts:
        if re.search(
            rf"\b{clear_call}\s*\(\s*{re.escape(timer.handle)}\s*\)",
            cleanup_text,
        ):
            return "cleared"
    for cleanup_text in cleanup_texts:
        if re.search(rf"\b{clear_call}\s*\(", cleanup_text):
            return "different-handle"
    return "missing-cleanup"


def _build_lifecycle_timer_message(timer: _LifecycleTimer, hook: str, cleanup_status: str) -> str:
    timer_label = "repeating timer" if timer.timer_kind == "interval" else "timeout"
    if cleanup_status == "untracked-handle":
        return (
            f"`{hook}` creates a {timer_label} via `{timer.timer_call}` without storing "
            "the handle for cleanup."
        )
    if cleanup_status == "different-handle":
        return (
            f"`{hook}` creates `{timer.handle}` via `{timer.timer_call}`, but the returned "
            "cleanup clears a different handle."
        )
    return (
        f"`{hook}` creates `{timer.handle}` via `{timer.timer_call}`, but the returned "
        "cleanup does not clear it."
    )


def _resolve_named_cleanup_region(
    masked_text: str,
    *,
    body_start: int,
    body_end: int,
    return_offset: int,
    name: str,
) -> _StyleRegion | None:
    inner_start = body_start + 1
    lookup_limit = return_offset - inner_start
    inner_text = masked_text[inner_start:body_end]

    block_assignment_pattern = re.compile(
        rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=\s*"
        r"(?:(?:async\s*)?\([^)]*\)\s*=>|function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\([^)]*\))"
        r"\s*(?P<body>\{)"
    )
    block_declaration_pattern = re.compile(
        rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)\s*(?P<body>\{{)"
    )
    expression_assignment_pattern = re.compile(
        rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=\s*"
        r"(?:async\s*)?\([^)]*\)\s*=>\s*"
    )

    candidates: list[_StyleRegion] = []

    for match in block_assignment_pattern.finditer(inner_text[:lookup_limit]):
        body_offset = inner_start + match.start("body")
        body_end_offset = _find_matching_delimiter(masked_text, body_offset, "{", "}")
        candidates.append(_StyleRegion(start=body_offset, end=body_end_offset))

    for match in block_declaration_pattern.finditer(inner_text):
        body_offset = inner_start + match.start("body")
        body_end_offset = _find_matching_delimiter(masked_text, body_offset, "{", "}")
        candidates.append(_StyleRegion(start=body_offset, end=body_end_offset))

    for match in expression_assignment_pattern.finditer(inner_text[:lookup_limit]):
        expression_start = inner_start + match.end()
        while expression_start < body_end and masked_text[expression_start] in {" ", "\t", "\n"}:
            expression_start += 1
        if expression_start >= body_end or masked_text[expression_start] == "{":
            continue
        expression_end = _find_statement_end(masked_text, expression_start, body_end)
        candidates.append(_StyleRegion(start=expression_start, end=expression_end))

    if not candidates:
        return None
    return max(candidates, key=lambda region: region.start)


def _collect_local_color_constants(text: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    for match in _LOCAL_COLOR_CONSTANT_PATTERN.finditer(text):
        constants[match.group("name")] = match.group("value")
    return constants


def _load_theme_color_tokens(repo_root: Path) -> dict[str, str]:
    theme_path = repo_root / "src" / "theme" / "index.ts"
    if not theme_path.is_file():
        return {}
    text = theme_path.read_text(encoding="utf-8", errors="replace")
    export_match = _THEME_COLORS_EXPORT_PATTERN.search(text)
    if export_match is None:
        return {}
    opening_brace = text.find("{", export_match.end() - 1)
    if opening_brace == -1:
        return {}
    masked_text = _mask_non_code(text)
    end = _find_matching_delimiter(masked_text, opening_brace, "{", "}")
    object_text = text[opening_brace : end + 1]

    tokens: dict[str, str] = {}
    path_stack: list[str] = []
    for raw_line in object_text.splitlines()[1:]:
        stripped = re.sub(r"\s*//.*$", "", raw_line).strip()
        if not stripped or stripped.startswith("//"):
            continue
        while stripped.startswith("}"):
            if path_stack:
                path_stack.pop()
            stripped = stripped[1:].lstrip(" ,")
        if not stripped:
            continue
        if object_match := _THEME_OBJECT_START_PATTERN.match(stripped):
            path_stack.append(object_match.group("key"))
            continue
        if value_match := _THEME_VALUE_PATTERN.match(stripped):
            token_path = ".".join(("colors", *path_stack, value_match.group("key")))
            tokens[token_path] = value_match.group("value")
    return tokens


def _collect_color_assignments(
    *,
    region_text: str,
    region_start: int,
    full_text: str,
    theme_color_tokens: dict[str, str],
    local_constants: dict[str, str],
) -> tuple[_ColorAssignment, ...]:
    assignments: list[_ColorAssignment] = []
    for match in _STYLE_COLOR_ASSIGNMENT_PATTERN.finditer(region_text):
        assignments.append(
            _ColorAssignment(
                property=match.group("property"),
                line=_line_for_offset(full_text, region_start + match.start()),
                resolved=_resolve_color_expression(
                    match.group("value"), theme_color_tokens, local_constants
                ),
            )
        )
    return tuple(assignments)


def _resolve_color_expression(
    expression: str, theme_color_tokens: dict[str, str], local_constants: dict[str, str]
) -> _ResolvedColor:
    rendered = expression.strip().rstrip(",")
    base_expression = rendered
    alpha_suffix: str | None = None
    literal: str | None = None
    token_path: str | None = None
    source = "unresolved"

    alpha_match = re.fullmatch(
        r"(?P<base>(?:colors(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+|[A-Z_][A-Z0-9_]*))"
        r"\s*\+\s*['\"](?P<alpha>[0-9A-Fa-f]{2})['\"]",
        rendered,
    )
    if alpha_match is not None:
        base_expression = alpha_match.group("base")
        alpha_suffix = alpha_match.group("alpha")

    if rendered[:1] in {"'", '"'} and rendered[-1:] == rendered[:1]:
        literal = rendered[1:-1]
        source = "literal"
    elif base_expression.startswith("colors."):
        literal = theme_color_tokens.get(base_expression)
        source = "theme-token"
        token_path = base_expression
    elif base_expression in local_constants:
        literal = local_constants[base_expression]
        source = "local-const"

    if alpha_suffix is not None and literal is not None:
        normalized_hex = _normalize_hex_color_without_alpha(literal)
        if normalized_hex is not None:
            literal = f"{normalized_hex}{alpha_suffix}"

    return _ResolvedColor(
        expression=rendered,
        source=source,
        literal=literal,
        rgba=_parse_color_literal(literal) if literal is not None else None,
        token_path=token_path,
    )


def _parse_color_literal(value: str | None) -> tuple[float, float, float, float] | None:
    if value is None:
        return None
    rendered = value.strip()
    if not rendered:
        return None
    if rendered.startswith("#"):
        return _parse_hex_color(rendered)
    if rendered.lower().startswith("rgb"):
        return _parse_rgb_color(rendered)
    return None


def _parse_hex_color(value: str) -> tuple[float, float, float, float] | None:
    rendered = value.lstrip("#")
    if len(rendered) == 3:
        rendered = "".join(character * 2 for character in rendered) + "ff"
    elif len(rendered) == 4:
        rendered = "".join(character * 2 for character in rendered)
    elif len(rendered) == 6:
        rendered = f"{rendered}ff"
    elif len(rendered) != 8:
        return None

    red = int(rendered[0:2], 16) / 255.0
    green = int(rendered[2:4], 16) / 255.0
    blue = int(rendered[4:6], 16) / 255.0
    alpha = int(rendered[6:8], 16) / 255.0
    return (red, green, blue, alpha)


def _normalize_hex_color_without_alpha(value: str) -> str | None:
    rendered = value.lstrip("#")
    if len(rendered) == 3:
        return f"#{''.join(character * 2 for character in rendered)}"
    if len(rendered) == 4:
        return f"#{''.join(character * 2 for character in rendered[:3])}"
    if len(rendered) == 6:
        return f"#{rendered}"
    if len(rendered) == 8:
        return f"#{rendered[:6]}"
    return None


def _parse_rgb_color(value: str) -> tuple[float, float, float, float] | None:
    match = re.fullmatch(
        r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})"
        r"(?:\s*,\s*(0(?:\.\d+)?|1(?:\.0+)?|\.\d+))?\s*\)",
        value.strip(),
        re.IGNORECASE,
    )
    if match is None:
        return None
    red = min(int(match.group(1)), 255) / 255.0
    green = min(int(match.group(2)), 255) / 255.0
    blue = min(int(match.group(3)), 255) / 255.0
    alpha = float(match.group(4)) if match.group(4) is not None else 1.0
    return (red, green, blue, alpha)


def _latest_assignment(
    assignments: Sequence[_ColorAssignment], property_name: str
) -> _ColorAssignment | None:
    for assignment in reversed(assignments):
        if assignment.property == property_name:
            return assignment
    return None


def _contrast_ratio(
    foreground: tuple[float, float, float, float], background: tuple[float, float, float, float]
) -> float:
    foreground_luminance = _relative_luminance(foreground[:3])
    background_luminance = _relative_luminance(background[:3])
    lighter = max(foreground_luminance, background_luminance)
    darker = min(foreground_luminance, background_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def _relative_luminance(rgb: tuple[float, float, float]) -> float:
    red, green, blue = (_linearize_channel(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _linearize_channel(value: float) -> float:
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def _is_risky_status_pair(background: _ResolvedColor, foreground: _ResolvedColor) -> bool:
    if (
        background.token_path is not None
        and foreground.token_path is not None
        and background.token_path.startswith("colors.status.")
        and foreground.token_path.startswith("colors.status.")
        and background.token_path.endswith("Muted")
    ):
        return background.token_path[: -len("Muted")] == foreground.token_path

    if background.rgba is None or foreground.rgba is None:
        return False
    if background.rgba[3] > _RISKY_STATUS_ALPHA_THRESHOLD or foreground.rgba[3] != 1.0:
        return False
    return _same_rgb(background.rgba, foreground.rgba)


def _same_rgb(
    first: tuple[float, float, float, float], second: tuple[float, float, float, float]
) -> bool:
    return all(abs(first[index] - second[index]) <= 0.01 for index in range(3))


def _should_skip_layout_literal(text: str, property_name: str, offset: int) -> bool:
    if property_name not in {"width", "height"}:
        return False
    object_start = text.rfind("{", 0, offset)
    if object_start == -1:
        return False
    key_context = text[max(0, object_start - 120) : object_start]
    return re.search(r"shadowOffset\s*:\s*$", key_context) is not None


def _mask_non_code(text: str) -> str:
    result: list[str] = []
    state = "code"
    quote = ""
    index = 0

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                result.extend("  ")
                index += 2
                state = "line-comment"
                continue
            if char == "/" and next_char == "*":
                result.extend("  ")
                index += 2
                state = "block-comment"
                continue
            if char in {"'", '"', "`"}:
                quote = char
                result.append(" ")
                index += 1
                state = "string"
                continue
            result.append(char)
            index += 1
            continue

        if state == "line-comment":
            if char == "\n":
                result.append("\n")
                state = "code"
            else:
                result.append(" ")
            index += 1
            continue

        if state == "block-comment":
            if char == "*" and next_char == "/":
                result.extend("  ")
                index += 2
                state = "code"
                continue
            result.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if state == "string":
            if char == "\\":
                result.extend("  " if next_char else " ")
                index += 2 if next_char else 1
                continue
            if char == quote:
                result.append(" ")
                index += 1
                state = "code"
                continue
            result.append("\n" if char == "\n" else " ")
            index += 1

    return "".join(result)


def _mask_comments(text: str) -> str:
    result: list[str] = []
    state = "code"
    quote = ""
    index = 0

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                result.extend("  ")
                index += 2
                state = "line-comment"
                continue
            if char == "/" and next_char == "*":
                result.extend("  ")
                index += 2
                state = "block-comment"
                continue
            if char in {"'", '"', "`"}:
                quote = char
                result.append(char)
                index += 1
                state = "string"
                continue
            result.append(char)
            index += 1
            continue

        if state == "line-comment":
            if char == "\n":
                result.append("\n")
                state = "code"
            else:
                result.append(" ")
            index += 1
            continue

        if state == "block-comment":
            if char == "*" and next_char == "/":
                result.extend("  ")
                index += 2
                state = "code"
                continue
            result.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if state == "string":
            result.append(char)
            if char == "\\":
                if next_char:
                    result.append(next_char)
                    index += 2
                else:
                    index += 1
                continue
            if char == quote:
                state = "code"
            index += 1

    return "".join(result)


DEFAULT_ADAPTERS = (TypeScriptAdapter(),)
