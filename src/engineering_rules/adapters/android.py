"""Android-native engineering rules adapter."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

from ..engine import AdapterContext, ExecutionMode, RulesAdapter
from ..models import FindingLocation, NormalizedFinding, RepoLanguage
from ..registry import RulesRegistry, create_default_registry
from .shared import (
    _looks_like_placeholder as _shared_looks_like_placeholder,
)
from .shared import (
    _looks_like_secret_assignment as _shared_looks_like_secret_assignment,
)
from .shared import (
    _match_secret_pattern as _shared_match_secret_pattern,
)

_SOURCE_SUFFIXES = {".kt", ".java"}
_SUPPORTED_SUFFIXES = _SOURCE_SUFFIXES | {".kts", ".gradle", ".pro"}
_EXCLUDED_PATH_MARKERS = (
    "/build/",
    "/generated/",
    "/.gradle/",
    "/androidtest/",
    "/node_modules/",
    "/test/",
)

_PREFS_COMMIT_PATTERN = re.compile(r"\.edit\s*\([^)]*\).*\.commit\s*\(")
_FILE_IO_PATTERNS = (
    re.compile(
        r"\bFile\s*\([^\n]*\)\s*\.\s*(readText|readBytes|readLines|writeText|writeBytes|inputStream|outputStream)\s*\("
    ),
    re.compile(r"\bFiles\s*\.\s*(readAllBytes|readString|write|writeString)\s*\("),
    re.compile(r"\b(FileInputStream|FileOutputStream|RandomAccessFile)\s*\("),
)
_NETWORK_IO_PATTERNS = (
    re.compile(r"\.newCall\s*\([^)]*\)\s*\.\s*execute\s*\("),
    re.compile(r"\bURL\s*\([^\n]*\)\s*\.\s*(openConnection|openStream)\s*\("),
    re.compile(r"\b(HttpURLConnection|URLConnection)\b.*\.\s*getInputStream\s*\("),
)
_RUNBLOCKING_PATTERN = re.compile(r"\brunBlocking(?:\s*<[^>\n]+>)?\s*(?:\(|\{)")
_RUNBLOCKING_INTERCEPTOR_CLASS_PATTERN = re.compile(
    r"\b(?:class|object)\s+[A-Za-z_][A-Za-z0-9_]*Interceptor[A-Za-z0-9_]*\b"
)
_RUNBLOCKING_AUTHENTICATOR_CLASS_PATTERN = re.compile(
    r"\b(?:class|object)\s+[A-Za-z_][A-Za-z0-9_]*Authenticator[A-Za-z0-9_]*\b"
)
_RUNBLOCKING_INTERCEPT_METHOD_PATTERN = re.compile(r"\bintercept\s*\([^)]*\bInterceptor\.Chain\b")
_RUNBLOCKING_AUTHENTICATE_METHOD_PATTERN = re.compile(r"\bauthenticate\s*\([^)]*\bResponse\b")
_WORKER_CONTEXT_PATTERNS = (
    re.compile(r"withContext\s*\(\s*Dispatchers\.IO"),
    re.compile(r"launch\s*\(\s*Dispatchers\.IO"),
    re.compile(r"async\s*\(\s*Dispatchers\.IO"),
    re.compile(r"@WorkerThread"),
)
_WORKER_SCOPE_PATTERNS = (
    re.compile(r"\bdoWork\s*\("),
    re.compile(r":\s*CoroutineWorker\b"),
    re.compile(r"\bextends\s+Worker\b"),
)
_UNSCOPED_BOUNDARY_COROUTINE_PATTERN = re.compile(
    r"\bCoroutineScope\b[\s\S]{0,160}?Dispatchers\.[A-Za-z_][A-Za-z0-9_]*[\s\S]{0,160}?\.launch\s*(?:\(|\{)"
)
_GLOBAL_SCOPE_BOUNDARY_COROUTINE_PATTERN = re.compile(
    r"\bGlobalScope\s*\.\s*launch\s*(?:\(\s*Dispatchers\.[A-Za-z_][A-Za-z0-9_]*\s*\)|\{)"
)
_BOUNDARY_COROUTINE_COORDINATION_PATTERN = re.compile(
    r"\bgoAsync\s*\(|\bPendingResult\b|\bpendingResult\b"
)
_BOUNDARY_CALLBACK_PATTERNS = (
    (
        "broadcastreceiver-onreceive",
        re.compile(r"\boverride\s+fun\s+onReceive\s*\("),
        re.compile(r"\bBroadcastReceiver\b"),
    ),
    (
        "service-onstartcommand",
        re.compile(r"\boverride\s+fun\s+onStartCommand\s*\("),
        re.compile(r"\b(?:Service|IntentService|JobIntentService)\b"),
    ),
    (
        "service-onhandleintent",
        re.compile(r"\boverride\s+fun\s+onHandleIntent\s*\("),
        re.compile(r"\b(?:IntentService|JobIntentService)\b"),
    ),
    (
        "fcm-onmessagereceived",
        re.compile(r"\boverride\s+fun\s+onMessageReceived\s*\("),
        re.compile(r"\bFirebaseMessagingService\b"),
    ),
    (
        "fcm-onnewtoken",
        re.compile(r"\boverride\s+fun\s+onNewToken\s*\("),
        re.compile(r"\bFirebaseMessagingService\b"),
    ),
    (
        "fcm-ondeletedmessages",
        re.compile(r"\boverride\s+fun\s+onDeletedMessages\s*\("),
        re.compile(r"\bFirebaseMessagingService\b"),
    ),
)
_BOUNDARY_COROUTINE_MANAGED_SCOPE_TOKENS = (
    "lifecycleScope",
    "viewModelScope",
    "rememberCoroutineScope",
)
_FUNCTION_SIGNATURE_PATTERN = re.compile(
    r"\b(?P<suspend>suspend\s+)?fun\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_CLASS_SIGNATURE_PATTERN = re.compile(r"\b(?:class|object)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_BLOCKING_SYNC_WRAPPER_OWNER_PATTERN = re.compile(
    r"(?:Manager|Repository|Helper|Util|Utils|Store|Provider)$"
)
_BLOCKING_SYNC_WRAPPER_DATASTORE_PATTERNS = (
    re.compile(r"\bDataStore\b"),
    re.compile(r"\bdataStore\b"),
    re.compile(r"\bpreferencesDataStore\b"),
    re.compile(r"\.data\s*\.\s*(?:first|single)\s*\("),
    re.compile(r"\.edit\s*\("),
)
_BLOCKING_SYNC_WRAPPER_NETWORK_PATTERNS = (
    re.compile(r"\bApiClient\."),
    re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:Api|Service|Client)\s*\."),
    re.compile(r"\bRetrofit\b"),
    re.compile(r"\bOkHttp(?:Client)?\b"),
    re.compile(r"\bHttpURLConnection\b"),
    re.compile(r"\.(?:await|execute)\s*\("),
)
_CLASS_DECLARATION_START_PATTERN = re.compile(
    r"\b(?:class|object)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_VIEWMODEL_FIELD_INSTANTIATION_PATTERN = re.compile(
    r"""
    ^\s*(?:private|internal|protected|public)?\s*
    (?:lateinit\s+)?
    (?:val|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*
    (?::\s*[^=]+)?=\s*
    (?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P<type>[A-Z][A-Za-z0-9_]*(?:Repository|Manager))
    (?:<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_VIEWMODEL_LAZY_INSTANTIATION_PATTERN = re.compile(
    r"""
    ^\s*(?:private|internal|protected|public)?\s*
    (?:val|var)\s+[A-Za-z_][A-Za-z0-9_]*\s+
    by\s+lazy(?:\s*\([^)]*\))?\s*\{\s*
    (?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P<type>[A-Z][A-Za-z0-9_]*(?:Repository|Manager))
    (?:<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_VIEWMODEL_JAVA_FIELD_INSTANTIATION_PATTERN = re.compile(
    r"""
    ^\s*(?:private|protected|public)\s+
    (?:static\s+)?(?:final\s+)?
    (?P<type>[A-Z][A-Za-z0-9_]*(?:Repository|Manager))
    (?:<[^>\n]+>)?\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*
    new\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P=type)(?:<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_BOUNDARY_DIRECT_DEPENDENCY_INSTANTIATION_PATTERN = re.compile(
    r"""
    ^\s*(?:private|internal|protected|public)?\s*
    (?:lateinit\s+)?
    (?:val|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*
    (?::\s*[^=]+)?=\s*
    (?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P<type>(?:[A-Z][A-Za-z0-9_]*Repository|(?:[A-Z][A-Za-z0-9_]*)?PreferencesManager))
    (?:<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_BOUNDARY_DIRECT_LAZY_DEPENDENCY_INSTANTIATION_PATTERN = re.compile(
    r"""
    ^\s*(?:private|internal|protected|public)?\s*
    (?:val|var)\s+[A-Za-z_][A-Za-z0-9_]*\s+
    by\s+lazy(?:\s*\([^)]*\))?\s*\{\s*
    (?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P<type>(?:[A-Z][A-Za-z0-9_]*Repository|(?:[A-Z][A-Za-z0-9_]*)?PreferencesManager))
    (?:<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_BOUNDARY_DIRECT_JAVA_DEPENDENCY_INSTANTIATION_PATTERN = re.compile(
    r"""
    ^\s*(?:private|protected|public)?\s*
    (?:static\s+)?(?:final\s+)?
    (?P<type>(?:[A-Z][A-Za-z0-9_]*Repository|(?:[A-Z][A-Za-z0-9_]*)?PreferencesManager))
    (?:<[^>\n]+>)?\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*
    new\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)*
    (?P=type)(?:<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_KOTLIN_OBJECT_DECLARATION_PATTERN = re.compile(r"\bobject\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_COMPANION_OBJECT_DECLARATION_PATTERN = re.compile(
    r"\bcompanion\s+object(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\b"
)
_KOTLIN_MUTABLE_STATIC_IDENTITY_FIELD_PATTERN = re.compile(
    r"""
    ^\s*(?:@Volatile\s+)?(?:private|internal|protected|public)?\s*
    (?:lateinit\s+)?var\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b
    """,
    re.VERBOSE,
)
_JAVA_MUTABLE_STATIC_IDENTITY_FIELD_PATTERN = re.compile(
    r"""
    ^\s*(?:public|protected|private)?\s*
    static\s+(?:volatile\s+)?(?!final\b)
    [A-Za-z_][A-Za-z0-9_<>,.?[\]]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)
    """,
    re.VERBOSE,
)

_UNSAFE_UI_TRIGGER_PATTERNS = (
    re.compile(r"\bGlobalScope\s*\.\s*launch\s*\(\s*Dispatchers\.Main"),
    re.compile(
        r"\bCoroutineScope\b[\s\S]{0,80}?Dispatchers\.Main[\s\S]{0,80}?\.launch\s*(?:\(|\{)"
    ),
    re.compile(r"\brunOnUiThread\s*\{"),
    re.compile(
        r"\b(?:requireActivity\s*\(\s*\)\s*\.)?runOnUiThread[\s\S]{0,80}?\(\s*Runnable\s*\{"
    ),
    re.compile(r"\brequireActivity\s*\(\s*\)\s*\.\s*runOnUiThread\s*\{"),
    re.compile(r"\bHandler\s*\(\s*Looper\.getMainLooper\s*\(\s*\)\s*\)[\s\S]{0,80}?\.post\s*\{"),
    re.compile(
        r"\bHandler\s*\(\s*Looper\.getMainLooper\s*\(\s*\)\s*\)[\s\S]{0,80}?\.post\s*\(\s*Runnable\s*\{"
    ),
)
_UI_UPDATE_PATTERNS = (
    re.compile(r"\bbinding\."),
    re.compile(r"\bfindViewById\s*\("),
    re.compile(r"\.\s*(setText|setVisibility|setImageResource|setAdapter|submitList)\s*\("),
    re.compile(
        r"\.\s*(notifyDataSetChanged|notifyItemInserted|notifyItemRemoved|notifyItemChanged)\s*\("
    ),
    re.compile(r"\.\s*(text|visibility|isVisible|isGone)\s*="),
)
_LIFECYCLE_SCOPE_PATTERNS = (
    re.compile(r"viewLifecycleOwner\.lifecycleScope\s*\.\s*launch"),
    re.compile(r"\blifecycleScope\s*\.\s*launch"),
    re.compile(r"repeatOnLifecycle\s*\("),
    re.compile(r"launchWhen(Created|Started|Resumed)\s*\("),
)
_COMPOSE_TEXT_INPUT_PATTERN = re.compile(r"\b(?:OutlinedTextField|TextField|BasicTextField)\s*\(")
_COMPOSE_TEXT_PATTERN = re.compile(r"\bText\s*\(")
_COMPOSE_SCROLL_SURFACE_PATTERNS = (
    ("vertical_scroll", re.compile(r"\.\s*verticalScroll\s*\(")),
    ("lazy_column", re.compile(r"\bLazyColumn\s*\(")),
    ("lazy_vertical_grid", re.compile(r"\bLazyVerticalGrid\s*\(")),
)
_COMPOSE_IME_SAFE_PATTERNS = (
    re.compile(r"\.\s*imePadding\s*\("),
    re.compile(r"\bWindowInsets\s*\.\s*ime\b"),
    re.compile(r"\bnavigationBarsWithImePadding\s*\("),
    re.compile(r"\bimeNestedScroll\s*\("),
    re.compile(r"\bBringIntoViewRequester\s*\("),
    re.compile(r"\.\s*bringIntoViewRequester\s*\("),
    re.compile(r"\bbringIntoView\s*\("),
)
_COMPOSE_INPUT_INTERACTION_PATTERNS = (
    re.compile(r"\bkeyboardOptions\s*="),
    re.compile(r"\bkeyboardActions\s*="),
    re.compile(r"\bImeAction\."),
    re.compile(r"\bKeyboardType\."),
)
_API_CONTRACT_DRIFT_RULE_ID = "android.foundation.api-contract-surface-needs-doc-refresh"
_DTO_NULLABILITY_RULE_ID = "android.reliability.dto-nullability-default-discipline"
_DEEPLINK_COORDINATOR_RULE_ID = "android.architecture.no-fragmented-deeplink-intent-parsing"
_STRINGLY_TYPED_STATE_MACHINE_RULE_ID = "android.reliability.no-stringly-typed-state-machine"
_VARIANT_OWNERSHIP_RULE_ID = "android.foundation.variant-owned-release-config"
_DIRECT_SECRET_RULE_ID = "android.security.no-hardcoded-secret-literals"
_FALLBACK_SECRET_RULE_ID = "android.security.no-secret-fallback-literals"
_COMPOSE_IME_AWARE_INPUT_RULE_ID = (
    "android.reliability.scrollable-compose-inputs-need-ime-awareness"
)
_RUNBLOCKING_HOTPATH_RULE_ID = "android.reliability.no-runblocking-hotpath"
_UNSCOPED_BOUNDARY_COROUTINE_RULE_ID = "android.reliability.no-unscoped-boundary-coroutine"
_BLOCKING_SYNC_WRAPPER_RULE_ID = "android.reliability.no-blocking-sync-wrapper"
_TINY_READABILITY_TEXT_RULE_ID = "android.ui.avoid-tiny-readability-text"
_VIEWMODEL_DIRECT_REPOSITORY_INSTANTIATION_RULE_ID = (
    "android.architecture.no-viewmodel-direct-repository-instantiation"
)
_DEFAULT_VIEWMODEL_PARAMETER_RULE_ID = (
    "android.architecture.no-default-viewmodel-parameter-in-composable"
)
_UI_DIRECT_API_CLIENT_RULE_ID = "android.architecture.no-ui-direct-api-client"
_UI_DIRECT_BUILDCONFIG_TRANSPORT_RULE_ID = "android.architecture.no-ui-direct-buildconfig-transport"
_UI_DIRECT_PREFERENCES_MANAGER_RULE_ID = "android.architecture.no-ui-direct-preferences-manager"
_SERVICE_OR_RECEIVER_DIRECT_SERVICE_LOCATOR_ACCESS_RULE_ID = (
    "android.architecture.no-service-or-receiver-direct-service-locator-access"
)
_OVERSIZED_SCREEN_COMPOSABLE_RULE_ID = "android.maintainability.no-oversized-screen-composable"
_UI_DETEKT_SUPPRESSION_RULE_ID = "android.maintainability.no-ui-detekt-suppression"
_RAW_UI_COLOR_LITERAL_RULE_ID = "android.ui.no-raw-color-literals"
_FIXED_UI_LAYOUT_RULE_ID = "android.ui.avoid-fixed-tokenless-layout-values"
_LOCAL_STATUS_COLOR_MAP_RULE_ID = "android.ui.no-local-status-color-map"
_SEMANTIC_STATUS_COLOR_LITERAL_RULE_ID = "android.ui.no-semantic-status-color-literals"
_BOUNDARY_CALLBACK_WITHOUT_TEST_RULE_ID = "android.testing.no-boundary-callback-without-test"
_VIEWMODEL_WITHOUT_TESTS_RULE_ID = "android.testing.no-viewmodel-without-tests"
_GSON_NONNULL_FIELD_RULE_ID = "android.correctness.gson-nonnull-field-needs-nullable-type"
_API_RESPONSE_TYPE_RULE_ID = "android.reliability.api-response-type-must-match-contract"
_VIEWMODEL_CLEARED_SINGULAR_RULE_ID = "android.lifecycle.viewmodel-cleared-must-be-singular"
_GEOFENCE_DEBOUNCE_RULE_ID = "android.lifecycle.geofence-transition-needs-debounce"
_HARDCODED_CREDENTIALS_BUILDCONFIG_RULE_ID = (
    "android.security.no-hardcoded-credentials-in-buildconfig"
)
_SENSITIVE_TOKEN_QUERY_RULE_ID = "android.security.no-sensitive-token-in-url-query"
_FCM_DEFAULT_CHANNEL_RULE_ID = "android.correctness.fcm-default-notification-channel-required"
_DIALOG_STATE_HOISTED_RULE_ID = "android.compose.dialog-state-must-be-hoisted-above-conditional"
_UNSUPPORTED_COMPOSE_PARAM_RULE_ID = "android.compose.unsupported-parameter-must-not-be-used"
_DARK_THEME_TEXTFIELD_COLOR_RULE_ID = (
    "android.compose.dark-theme-textfield-needs-explicit-text-color"
)
_PROGUARD_SIGNATURE_RULE_ID = "android.reliability.proguard-r8-must-keep-generic-type-signatures"
_CUSTOM_FLOW_FIRST_RULE_ID = "android.correctness.custom-flow-first-extension-is-unsafe"
_OKHTTP_LEGACY_MEDIATYPE_RULE_ID = "android.reliability.okhttp-legacy-mediatype-needs-extension"
_DEEPLINK_ROUTING_RULE_ID = "android.architecture.deep-link-routing-must-use-shared-target-parser"
_KEYBOARD_IME_PADDING_RULE_ID = "android.correctness.keyboard-input-needs-ime-padding"
_NOTIFICATION_DEEP_LINK_BY_ID_RULE_ID = (
    "android.reliability.notification-deep-link-must-fetch-by-id"
)
_ASYNC_PAGINATED_FETCH_GENERATION_RULE_ID = (
    "android.reliability.no-async-paginated-fetch-without-generation-guard"
)
_SECRET_CONFIG_SUFFIXES = {".gradle", ".kts"}
_COMPOSABLE_ANNOTATION_PATTERN = re.compile(r"@\s*Composable\b")
_PREVIEW_ANNOTATION_PATTERN = re.compile(r"@\s*Preview\b")
_DEFAULT_VIEWMODEL_PARAMETER_PATTERN = re.compile(
    r"""
    \b(?P<parameter>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*
    [A-Za-z_][A-Za-z0-9_<>,?.\s]*
    =\s*
    (?P<call>(?:[A-Za-z_][A-Za-z0-9_]*\.)*viewModel)
    (?:\s*<[^>\n]+>)?\s*\(
    """,
    re.VERBOSE,
)
_COMPOSABLE_SCREEN_STATE_PATTERN = re.compile(
    r"\b(?:remember(?:Saveable)?|collectAsState(?:WithLifecycle)?|"
    r"mutableStateOf|derivedStateOf|LaunchedEffect|DisposableEffect|produceState|"
    r"snapshotFlow)\b"
)
_COMPOSABLE_BRANCH_PATTERN = re.compile(r"^\s*(?:if|when)\b|\belse\s+if\b|->")
_UI_API_CLIENT_ACCESS_PATTERN = re.compile(r"\bApiClient\.(?P<member>[A-Za-z_][A-Za-z0-9_]*)")
_UI_BUILD_CONFIG_ACCESS_PATTERN = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)*BuildConfig\.(?P<name>[A-Z][A-Z0-9_]*)"
)
_GRADLE_BLOCK_DECLARATION_PATTERN = re.compile(r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{")
_GRADLE_BUILD_CONFIG_FIELD_PATTERN = re.compile(
    r'buildConfigField\s*\(\s*"[^"]+"\s*,\s*"(?P<name>[A-Z][A-Z0-9_]*)"\s*,'
)
_DTO_CLASS_DECLARATION_PATTERN = re.compile(
    r"\bdata\s+class\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_DTO_FIELD_LINE_PATTERN = re.compile(
    r"""
    @SerializedName\s*\(
    [^\n]*
    \)\s*
    (?:val|var)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*
    (?P<type>[^=,\n]+?)
    (?P<default>\s*=\s*[^,\n]+)?
    \s*(?:,|$)
    """,
    re.VERBOSE,
)
_REQUEST_DTO_NAME_PATTERN = re.compile(
    r"(?:Request|CreateRequest|UpdateRequest|PatchRequest|Query|Params|Filter|Body)$"
)
_DEEPLINK_DIRECT_ACCESS_PATTERNS = (
    ("getStringExtra", re.compile(r"\.\s*getStringExtra\s*\(")),
    ("getLongExtra", re.compile(r"\.\s*getLongExtra\s*\(")),
    ("getIntExtra", re.compile(r"\.\s*getIntExtra\s*\(")),
    ("getBooleanExtra", re.compile(r"\.\s*getBooleanExtra\s*\(")),
    ("getParcelableExtra", re.compile(r"\.\s*getParcelableExtra\s*\(")),
    ("getSerializableExtra", re.compile(r"\.\s*getSerializableExtra\s*\(")),
    ("intentData", re.compile(r"\bintent\s*\.\s*data\b")),
    ("queryParameter", re.compile(r"\.\s*getQueryParameter\s*\(")),
)
_STRING_STATE_CONSTANT_PATTERN = re.compile(
    r'^\s*(?:private|internal|public)?\s*const\s+val\s+(?P<name>(?P<family>[A-Z][A-Z0-9]*)_[A-Z0-9_]+)\s*=\s*"[^"]+"'
)
_STRING_STATE_HOLDER_PATTERN = re.compile(
    r"\b(?:mutableStateOf\s*\(\s*(?P<constant>[A-Z][A-Z0-9_]+)\b|MutableState\s*<\s*String\s*>|:\s*String\s*=)"
)
_STRING_STATE_WHEN_PATTERN = re.compile(
    r"\bwhen\s*\(\s*[^)]*\b(?:state|screen|status|mode|phase|step)\b[^)]*\)"
)
_UI_PREFERENCES_MANAGER_PATTERN = re.compile(r"\bApiClient\.preferencesManager\b")
_UI_PREFERENCES_MANAGER_CONSTRUCTION_PATTERN = re.compile(
    r"\b(?P<type>(?:[A-Z][A-Za-z0-9_]*)?PreferencesManager)(?:<[^>\n]+>)?\s*\("
)
_RAW_UI_COLOR_LITERAL_PATTERN = re.compile(r"\bColor\s*\(\s*(?P<value>0x[0-9A-Fa-f]{6,8})\s*\)")
_FIXED_UI_LAYOUT_LITERAL_PATTERN = re.compile(r"(?P<value>-?\d+(?:\.\d+)?)\.(?P<unit>dp|sp)\b")
_READABILITY_FONT_SIZE_PATTERN = re.compile(r"\bfontSize\s*=\s*(?P<value>\d+(?:\.\d+)?)\s*\.sp\b")
_LOCAL_STATUS_COLOR_MAP_TRIGGER_PATTERN = re.compile(
    r"\bwhen\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_UI_DIRECT_API_CLIENT_ALLOWED_MEMBERS = {"init"}
_UI_TRANSPORT_BUILD_CONFIG_EXACT_NAMES = {
    "API_URL",
    "BASE_URL",
    "TENANT_CODE",
    "TENANT_ID",
    "WEBSOCKET_URL",
    "WS_URL",
}
_VARIANT_OWNED_BUILD_CONFIG_EXACT_NAMES = {
    "API_URL",
    "BASE_URL",
    "TENANT_CODE",
    "TENANT_ID",
    "WEBSOCKET_URL",
    "WS_URL",
}
_VARIANT_OWNED_BUILD_CONFIG_NAME_PATTERN = re.compile(
    r"^(?:[A-Z0-9_]*?(?:API|BASE|TENANT|SECRET|TOKEN|ENDPOINT|URL|KEYSTORE)[A-Z0-9_]*|SARVAM_API_KEY)$"
)
_CONTRACT_ARTIFACT_NAME_PATTERNS = (
    re.compile(r"^api-docs\.json$", re.IGNORECASE),
    re.compile(r"^openapi(?:[-_.][A-Za-z0-9_-]+)?\.(?:json|ya?ml)$", re.IGNORECASE),
    re.compile(r"^swagger(?:[-_.][A-Za-z0-9_-]+)?\.(?:json|ya?ml)$", re.IGNORECASE),
    re.compile(r"^api[-_]?documentation\.md$", re.IGNORECASE),
)
_SEMANTIC_STATUS_TOKENS = {
    "ACTIVE",
    "APPROVED",
    "CANCELLED",
    "CLOSED",
    "COMPLETED",
    "ERROR",
    "FAILED",
    "INFO",
    "INACTIVE",
    "ON_TIME",
    "OPEN",
    "OVERRUN",
    "PAID",
    "PENDING",
    "REJECTED",
    "SKIPPED",
    "SUCCESS",
    "UNPAID",
    "WARNING",
}
_SEMANTIC_STATUS_CONTEXT_TERMS = frozenset({"status", "badge", "chip", "tone"})
_SEMANTIC_STATUS_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    + "|".join(re.escape(token) for token in sorted(_SEMANTIC_STATUS_TOKENS))
    + r")(?![A-Za-z0-9_])"
)
_SEMANTIC_STATUS_WORD_PATTERN = re.compile(r"\b(?:status|badge|chip|tone)\b", re.IGNORECASE)
_UI_ENTRYPOINT_FUNCTION_SUFFIXES = ("Route", "Screen")
_STATIC_CONTEXT_GUARD_TOKENS = (
    "@Volatile",
    "volatile ",
    "Atomic",
    "Mutex",
    "synchronized",
    "ThreadLocal",
)
_BOUNDARY_CALLBACK_TEST_CLASS_CALLBACKS = (
    ("BroadcastReceiver", ("onReceive",)),
    ("JobIntentService", ("onHandleIntent", "onStartCommand")),
    ("IntentService", ("onHandleIntent", "onStartCommand")),
    (
        "FirebaseMessagingService",
        ("onMessageReceived", "onNewToken", "onDeletedMessages"),
    ),
    ("Service", ("onStartCommand",)),
)
_DETEKT_SUPPRESSION_NAME_PATTERN = re.compile(r'["\'](?P<name>[A-Za-z0-9_.]+)["\']')
_UI_DETEKT_SUPPRESSIONS = frozenset(
    {
        "ComplexCondition",
        "CyclomaticComplexMethod",
        "FunctionNaming",
        "LongMethod",
        "LongParameterList",
        "NestedBlockDepth",
        "TooManyFunctions",
    }
)
_ALLOWED_ANDROID_LAYOUT_LITERALS = {
    "0",
    "0.0",
    "1",
    "1.0",
    "2",
    "2.0",
    "4",
    "4.0",
    "8",
    "8.0",
    "12",
    "12.0",
    "16",
    "16.0",
    "24",
    "24.0",
    "32",
    "32.0",
    "48",
    "48.0",
}
_MIN_READABILITY_TEXT_SP = 12.0
_OVERSIZED_SCREEN_COMPOSABLE_MIN_CODE_LINES = 28
_OVERSIZED_SCREEN_COMPOSABLE_MIN_BLOCK_COUNT = 5
_OVERSIZED_SCREEN_COMPOSABLE_MIN_NESTING_DEPTH = 3
_BOUNDARY_CALLBACK_MIN_CODE_LINES = 5
_BOUNDARY_CALLBACK_MIN_CODE_LINES_WITH_COMPLEXITY = 3
_SUBSTANTIAL_VIEWMODEL_MIN_MEMBER_COUNT = 3
_SUBSTANTIAL_VIEWMODEL_MIN_CODE_LINES = 18
_GRADLE_CONFIG_NAME_PATTERN = re.compile(
    r'\b(?:buildConfigField|resValue)\s*\(\s*"[^"]+"\s*,\s*"(?P<name>[A-Za-z0-9_.-]+)"',
    re.DOTALL,
)
_SECRET_ASSIGNMENT_NAME_PATTERN = re.compile(r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)\s*=")
_SECRET_LITERAL_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?P<name>
        [A-Za-z0-9_.-]*
        (?:
            api[_-]?key|
            auth[_-]?token|
            access[_-]?token|
            refresh[_-]?token|
            client[_-]?secret|
            password|
            passwd|
            private[_-]?key|
            secret|
            token
        )
        [A-Za-z0-9_.-]*
    )
    \s*=\s*
    (?:
        "(?P<double_value>[^"\n]+)"
        |
        '(?P<single_value>[^'\n]+)'
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SECRET_FALLBACK_ENV_TOKENS = (
    "System.getenv(",
    "System.getProperty(",
    "providers.environmentVariable(",
    "providers.gradleProperty(",
    "findProperty(",
    "project.findProperty(",
)
_SECRET_FALLBACK_PATTERNS = (
    ("elvis_fallback", re.compile(r'\?:\s*\\?"(?P<value>[^"\n]+)\\?"')),
    ("or_else_fallback", re.compile(r'\borElse\s*\(\s*\\?"(?P<value>[^"\n]+)\\?"\s*\)')),
)
_VIEWMODEL_MEMBER_PATTERN = re.compile(
    r"""
    ^\s*(?:
        (?:(?:private|internal|protected|public)\s+)?
        (?:(?:override|suspend|open|final|inline|lateinit)\s+)*
        (?:fun|val|var)\b
        |
        init\b
    )
    """,
    re.VERBOSE,
)
_GSON_DATA_CLASS_FIELD_PATTERN = re.compile(
    r"""
    ^\s*(?:
        @SerializedName\s*\([^)]+\)\s*
        |
        @Expose\s*
        |
        @JsonAdapter\s*\([^)]+\)\s*
    )*
    (?:val|var)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*
    (?P<type>[^=,\n]+?)
    (?P<default>\s*=\s*[^,\n]+)?
    \s*(?:,|$)
    """,
    re.VERBOSE,
)
_RETROFIT_LIST_RETURN_PATTERN = re.compile(
    r"(?:@GET|@POST|@PUT|@PATCH|@DELETE)\s*\([^)]*\)[\s\S]{0,80}?\b(?:suspend\s+)?fun\s+\w+\s*\([^)]*\)\s*:\s*List<"
)
_PAGED_RESPONSE_IMPORT_PATTERN = re.compile(r"\bPagedResponse\b")
_PAGED_RESPONSE_USAGE_PATTERN = re.compile(r"\bPagedResponse<")
_ONCLEARED_PATTERN = re.compile(r"\boverride\s+fun\s+onCleared\s*\(")
_GEOFENCE_EXIT_PATTERN = re.compile(r"\bGeofence\.GEOFENCE_TRANSITION_EXIT\b")
_GEOFENCE_DEBOUNCE_SAFE_PATTERN = re.compile(
    r"\b(?:delay|debounce|alarm|setAlarm|postDelayed|schedule)\b"
)
_BUILDCONFIG_CREDENTIAL_PATTERN = re.compile(
    r"buildConfigField\s*\(\s*"
    r'"[^"]+"\s*,\s*"'
    r"(?P<name>[A-Za-z0-9_]*"
    r"(?:EMAIL|USERNAME|PASSWORD|PASSWD|SECRET|API_KEY|TOKEN)"
    r"[A-Za-z0-9_]*)"
    r'"\s*,\s*"[^"]*"\s*\)',
    re.IGNORECASE,
)
_QUERY_TOKEN_PATTERN = re.compile(
    r'@Query\s*\(\s*"(?P<name>refreshToken|accessToken|authToken|token|apiKey)"\s*\)',
    re.IGNORECASE,
)
_FCM_CHANNEL_META_PATTERN = re.compile(
    r"com\.google\.firebase\.messaging\.default_notification_channel_id"
)
_REMEMBER_STATE_IN_CONDITIONAL_PATTERN = re.compile(r"\bremember\b[\s\S]{0,80}?\bmutableStateOf\b")
_CONDITIONAL_BLOCK_START_PATTERN = re.compile(r"\b(?:if|when)\s*[({]")
_UNSUPPORTED_COMPOSE_PARAMS = frozenset(
    {
        "containerColor",
        "tabIndicatorOffset",
        "navigationIconContentColor",
        "titleContentColor",
        "actionContentColor",
        "iconContentColor",
    }
)
_UNSUPPORTED_COMPOSE_PARAM_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in sorted(_UNSUPPORTED_COMPOSE_PARAMS)) + r")\s*="
)
_DARK_THEME_REFERENCE_PATTERN = re.compile(r"\b(?:darkTheme|isSystemInDarkTheme|DarkTheme)\b")
_TEXTFIELD_COLOR_SAFE_PATTERN = re.compile(r"\b(?:colors\s*=|textColor\s*=|TextFieldDefaults\b)")
_PROGUARD_GSON_RETROFIT_PATTERN = re.compile(r"\b(?:gson|retrofit|okhttp)\b", re.IGNORECASE)
_PROGUARD_SIGNATURE_KEEP_PATTERN = re.compile(r"-keepattributes\s+Signature", re.IGNORECASE)
_CUSTOM_FLOW_FIRST_PATTERN = re.compile(r"fun\s+<[^>]*>\s*Flow<[^>]*>\.first\s*\(")
_FLOW_COLLECT_PATTERN = re.compile(r"\bcollect\b")
_OKHTTP_LEGACY_MEDIATYPE_PATTERN = re.compile(r"\bMediaType\.parse\b|\bRequestBody\.create\b")
_DEEP_LINK_INTENT_FIELD_PATTERN = re.compile(
    r"\bintent\.(?:getStringExtra|getIntExtra|getLongExtra|getBooleanExtra|extras|data)\b"
)
_NOTIFICATION_DEEP_LINK_INDEX_PATTERN = re.compile(
    r"\b(?:get\s*\(\s*(?:\d+|[A-Za-z_][A-Za-z0-9_]*)\s*\)|\[\s*(?:\d+|[A-Za-z_][A-Za-z0-9_]*)\s*\])"
)
_NOTIFICATION_DEEP_LINK_CONTEXT_PATTERN = re.compile(
    r"\b(?:notification|navTarget|deep[-_ ]?link|reference(?:Type|Id)?|purchaseOrderId|poId|"
    r"jobCard(?:Id|Number)?|invoiceId|paymentId|workflow(?:Step)?Id|onNotificationClicked)\b",
    re.IGNORECASE,
)
_NOTIFICATION_DEEP_LINK_LOAD_BY_ID_PATTERN = re.compile(r"\bloadById\b")
_PAGINATED_FETCH_PATTERN = re.compile(
    r"\b(?:page|loadMore|append)\b",
    re.IGNORECASE,
)
_GENERATION_GUARD_PATTERN = re.compile(
    r"\b(?:fetchGeneration|currentGeneration|generation\s*!=|generation\s*==)\b"
)
_VIEWMODEL_CLASS_PATTERN = re.compile(r"\bclass\s+\w+ViewModel\b")
_ASYNC_RESULT_HANDLING_PATTERN = re.compile(r"\b(?:await|getOrElse|getOrNull)\b")


class AndroidAdapter(RulesAdapter):
    adapter_key = "android"

    def __init__(self, registry: RulesRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> tuple[NormalizedFinding, ...]:
        findings: list[NormalizedFinding] = []
        candidate_files = tuple(self._iter_candidate_files(context))

        for rule_id in dict.fromkeys(rule_ids):
            rule = self._registry.get(rule_id)
            if rule is None:
                continue
            if rule_id == _API_CONTRACT_DRIFT_RULE_ID:
                findings.extend(
                    self._run_api_contract_surface_needs_doc_refresh(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _VARIANT_OWNERSHIP_RULE_ID:
                findings.extend(
                    self._run_variant_owned_release_config(rule, context, candidate_files)
                )
            elif rule_id == "android.performance.no-main-thread-io":
                findings.extend(self._run_no_main_thread_io(rule, context, candidate_files))
            elif rule_id == _RUNBLOCKING_HOTPATH_RULE_ID:
                findings.extend(self._run_no_runblocking_hotpath(rule, context, candidate_files))
            elif rule_id == _UNSCOPED_BOUNDARY_COROUTINE_RULE_ID:
                findings.extend(
                    self._run_no_unscoped_boundary_coroutine(rule, context, candidate_files)
                )
            elif rule_id == _BLOCKING_SYNC_WRAPPER_RULE_ID:
                findings.extend(self._run_no_blocking_sync_wrapper(rule, context, candidate_files))
            elif rule_id == _DTO_NULLABILITY_RULE_ID:
                findings.extend(
                    self._run_dto_nullability_default_discipline(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == "android.reliability.lifecycle-safe-ui-updates":
                findings.extend(self._run_lifecycle_safe_ui_updates(rule, context, candidate_files))
            elif rule_id == _COMPOSE_IME_AWARE_INPUT_RULE_ID:
                findings.extend(
                    self._run_scrollable_compose_inputs_need_ime_awareness(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _DIRECT_SECRET_RULE_ID:
                findings.extend(
                    self._run_no_hardcoded_secret_literals(rule, context, candidate_files)
                )
            elif rule_id == _FALLBACK_SECRET_RULE_ID:
                findings.extend(
                    self._run_no_secret_fallback_literals(rule, context, candidate_files)
                )
            elif rule_id == _UI_DIRECT_API_CLIENT_RULE_ID:
                findings.extend(self._run_no_ui_direct_api_client(rule, context, candidate_files))
            elif rule_id == _UI_DIRECT_BUILDCONFIG_TRANSPORT_RULE_ID:
                findings.extend(
                    self._run_no_ui_direct_buildconfig_transport(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _UI_DIRECT_PREFERENCES_MANAGER_RULE_ID:
                findings.extend(
                    self._run_no_ui_direct_preferences_manager(rule, context, candidate_files)
                )
            elif rule_id == _DEEPLINK_COORDINATOR_RULE_ID:
                findings.extend(
                    self._run_no_fragmented_deeplink_intent_parsing(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _SERVICE_OR_RECEIVER_DIRECT_SERVICE_LOCATOR_ACCESS_RULE_ID:
                findings.extend(
                    self._run_no_service_or_receiver_direct_service_locator_access(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _VIEWMODEL_DIRECT_REPOSITORY_INSTANTIATION_RULE_ID:
                findings.extend(
                    self._run_no_viewmodel_direct_repository_instantiation(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _DEFAULT_VIEWMODEL_PARAMETER_RULE_ID:
                findings.extend(
                    self._run_no_default_viewmodel_parameter_in_composable(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _OVERSIZED_SCREEN_COMPOSABLE_RULE_ID:
                findings.extend(
                    self._run_no_oversized_screen_composable(rule, context, candidate_files)
                )
            elif rule_id == _UI_DETEKT_SUPPRESSION_RULE_ID:
                findings.extend(self._run_no_ui_detekt_suppression(rule, context, candidate_files))
            elif rule_id == _BOUNDARY_CALLBACK_WITHOUT_TEST_RULE_ID:
                findings.extend(
                    self._run_no_boundary_callback_without_test(rule, context, candidate_files)
                )
            elif rule_id == _VIEWMODEL_WITHOUT_TESTS_RULE_ID:
                findings.extend(
                    self._run_no_viewmodel_without_tests(rule, context, candidate_files)
                )
            elif rule_id == _RAW_UI_COLOR_LITERAL_RULE_ID:
                findings.extend(self._run_raw_ui_color_literals(rule, context, candidate_files))
            elif rule_id == _FIXED_UI_LAYOUT_RULE_ID:
                findings.extend(self._run_fixed_ui_layout_literals(rule, context, candidate_files))
            elif rule_id == _TINY_READABILITY_TEXT_RULE_ID:
                findings.extend(self._run_tiny_readability_text(rule, context, candidate_files))
            elif rule_id == _LOCAL_STATUS_COLOR_MAP_RULE_ID:
                findings.extend(self._run_local_status_color_map(rule, context, candidate_files))
            elif rule_id == _SEMANTIC_STATUS_COLOR_LITERAL_RULE_ID:
                findings.extend(
                    self._run_semantic_status_color_literals(
                        rule,
                        context,
                        candidate_files,
                        suppress_if_raw_color_rule_selected=(
                            _RAW_UI_COLOR_LITERAL_RULE_ID in dict.fromkeys(rule_ids)
                        ),
                    )
                )
            elif rule_id == _STRINGLY_TYPED_STATE_MACHINE_RULE_ID:
                findings.extend(
                    self._run_no_stringly_typed_state_machine(
                        rule,
                        context,
                        candidate_files,
                    )
                )
            elif rule_id == _GSON_NONNULL_FIELD_RULE_ID:
                findings.extend(
                    self._run_gson_nonnull_field_needs_nullable_type(rule, context, candidate_files)
                )
            elif rule_id == _API_RESPONSE_TYPE_RULE_ID:
                findings.extend(
                    self._run_api_response_type_must_match_contract(rule, context, candidate_files)
                )
            elif rule_id == _VIEWMODEL_CLEARED_SINGULAR_RULE_ID:
                findings.extend(
                    self._run_viewmodel_cleared_must_be_singular(rule, context, candidate_files)
                )
            elif rule_id == _GEOFENCE_DEBOUNCE_RULE_ID:
                findings.extend(
                    self._run_geofence_transition_needs_debounce(rule, context, candidate_files)
                )
            elif rule_id == _HARDCODED_CREDENTIALS_BUILDCONFIG_RULE_ID:
                findings.extend(
                    self._run_no_hardcoded_credentials_in_buildconfig(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _SENSITIVE_TOKEN_QUERY_RULE_ID:
                findings.extend(
                    self._run_no_sensitive_token_in_url_query(rule, context, candidate_files)
                )
            elif rule_id == _FCM_DEFAULT_CHANNEL_RULE_ID:
                findings.extend(
                    self._run_fcm_default_notification_channel_required(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _DIALOG_STATE_HOISTED_RULE_ID:
                findings.extend(
                    self._run_dialog_state_must_be_hoisted_above_conditional(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _UNSUPPORTED_COMPOSE_PARAM_RULE_ID:
                findings.extend(
                    self._run_unsupported_parameter_must_not_be_used(rule, context, candidate_files)
                )
            elif rule_id == _DARK_THEME_TEXTFIELD_COLOR_RULE_ID:
                findings.extend(
                    self._run_dark_theme_textfield_needs_explicit_text_color(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _PROGUARD_SIGNATURE_RULE_ID:
                findings.extend(
                    self._run_proguard_r8_must_keep_generic_type_signatures(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _CUSTOM_FLOW_FIRST_RULE_ID:
                findings.extend(
                    self._run_custom_flow_first_extension_is_unsafe(rule, context, candidate_files)
                )
            elif rule_id == _OKHTTP_LEGACY_MEDIATYPE_RULE_ID:
                findings.extend(
                    self._run_okhttp_legacy_mediatype_needs_extension(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _DEEPLINK_ROUTING_RULE_ID:
                findings.extend(
                    self._run_deep_link_routing_must_use_shared_target_parser(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _KEYBOARD_IME_PADDING_RULE_ID:
                findings.extend(
                    self._run_keyboard_input_needs_ime_padding(rule, context, candidate_files)
                )
            elif rule_id == _NOTIFICATION_DEEP_LINK_BY_ID_RULE_ID:
                findings.extend(
                    self._run_notification_deep_link_must_fetch_by_id(
                        rule, context, candidate_files
                    )
                )
            elif rule_id == _ASYNC_PAGINATED_FETCH_GENERATION_RULE_ID:
                findings.extend(
                    self._run_async_paginated_fetch_without_generation_guard(
                        rule, context, candidate_files
                    )
                )

        return tuple(findings)

    def _iter_candidate_files(self, context: AdapterContext) -> Iterable[str]:
        if context.mode is ExecutionMode.INVENTORY or not context.target_files:
            for path in context.repo_root.rglob("*"):
                if not path.is_file():
                    continue
                relative = path.relative_to(context.repo_root).as_posix()
                if _is_supported_android_path(context.repo_root, relative):
                    yield relative
            return

        for path in context.target_files:
            normalized = path.replace("\\", "/")
            if _is_supported_android_path(context.repo_root, normalized):
                yield normalized

    def _run_no_main_thread_io(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in enumerate(lines):
                match_name = _main_thread_io_match_name(line)
                if match_name is None or _has_worker_context(lines, index):
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Blocking Android disk or network I/O appears on a changed code path "
                            "without a nearby worker-thread context."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Move the work to withContext(Dispatchers.IO), a worker/executor, "
                            "or switch SharedPreferences.commit() to apply() when synchronous "
                            "writes are unnecessary."
                        ),
                        metadata={"matched_pattern": match_name},
                    )
                )
        return findings

    def _run_no_runblocking_hotpath(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, _line in enumerate(lines):
                match_name = _runblocking_hotpath_match_name(lines, index, relative_path)
                if match_name is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "runBlocking blocks an Android UI or request hot path; move the work "
                            "behind suspend APIs or prefetch it before the hot path executes."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Prefer suspend-first repository APIs, async token refresh flows, or "
                            "ViewModel preloading instead of bridging hot paths through "
                            "runBlocking."
                        ),
                        metadata={"matched_pattern": match_name},
                    )
                )
        return findings

    def _run_no_unscoped_boundary_coroutine(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for index, line in enumerate(sanitized_lines):
                if "CoroutineScope" not in line and "GlobalScope" not in line:
                    continue
                match = _unscoped_boundary_coroutine_match(
                    sanitized_lines,
                    index,
                    relative_path,
                )
                if match is None:
                    continue
                boundary_name, launch_pattern = match
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Short-lived Android boundary callback launches a naked coroutine "
                            "scope without explicit ownership; the work can outlive the "
                            "receiver or service callback."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Use goAsync()/PendingResult coordination, WorkManager, or an "
                            "injected application-owned scope instead of creating "
                            "CoroutineScope(...).launch directly inside the callback."
                        ),
                        metadata={
                            "matched_pattern": boundary_name,
                            "launch_pattern": launch_pattern,
                        },
                    )
                )
        return findings

    def _run_no_blocking_sync_wrapper(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for index, line in enumerate(sanitized_lines):
                if "runBlocking" not in line:
                    continue
                match = _blocking_sync_wrapper_match(sanitized_lines, index, relative_path)
                if match is None:
                    continue
                matched_pattern, function_name = match
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "runBlocking is used to expose DataStore or network work through a "
                            "synchronous wrapper; this hides coroutine boundaries and can block "
                            "Android callers."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Keep the API suspend/Flow-based, or move the bridge to a "
                            "caller-owned async boundary instead of `*Sync()` or manager-style "
                            "blocking helpers."
                        ),
                        metadata={
                            "matched_pattern": matched_pattern,
                            "wrapper_function": function_name,
                        },
                    )
                )
        return findings

    def _run_lifecycle_safe_ui_updates(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, _line in enumerate(lines):
                trigger_name = _unsafe_ui_trigger_name(lines, index)
                if trigger_name is None:
                    continue
                if _has_lifecycle_guard(lines, index):
                    continue
                if not _has_ui_update_nearby(lines, index):
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "UI work is dispatched from a non-lifecycle-aware Android callback; "
                            "prefer lifecycleScope/viewLifecycleOwner.lifecycleScope or add an "
                            "explicit lifecycle guard before touching views."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Route UI updates through lifecycle-aware scopes such as "
                            "viewLifecycleOwner.lifecycleScope, or guard the callback with "
                            "isAdded/isDestroyed checks before updating views."
                        ),
                        metadata={"matched_pattern": trigger_name},
                    )
                )
        return findings

    def _run_scrollable_compose_inputs_need_ime_awareness(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            if Path(relative_path).suffix.lower() != ".kt":
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            match = _scrollable_compose_input_ime_gap(sanitized_lines)
            if match is None:
                continue
            match_name, line_number, input_count = match
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Scrollable Compose screen contains text inputs but no visible IME inset "
                        "or bring-into-view handling; focused fields can be covered by the "
                        "keyboard."
                    ),
                    location=FindingLocation(path=relative_path, line=line_number),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.ANDROID,
                    suggestion=(
                        "Add Modifier.imePadding(), WindowInsets.ime-based padding, or "
                        "BringIntoViewRequester/bringIntoView handling around the affected input "
                        "surface."
                    ),
                    metadata={
                        "matched_pattern": match_name,
                        "input_count": str(input_count),
                    },
                )
            )
        return findings

    def _run_no_hardcoded_secret_literals(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_secret_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index in range(len(lines)):
                if Path(
                    relative_path
                ).suffix.lower() in _SECRET_CONFIG_SUFFIXES and not _should_scan_gradle_secret_line(
                    lines[index]
                ):
                    continue
                scan_text = _secret_scan_text(relative_path, lines, index)
                match_name = _hardcoded_secret_match_name(relative_path, lines[index], scan_text)
                if match_name is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Hardcoded Android secret or credential literal appears in source or "
                            "build config; move it to secure runtime or build configuration."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Remove the checked-in literal and load the value from secure "
                            "environment, Gradle properties, or platform-managed config."
                        ),
                        metadata={"matched_pattern": match_name},
                    )
                )
        return findings

    def _run_no_ui_direct_api_client(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        boundary_hint = _android_repository_boundary_hint(context.repo_root)
        for relative_path in candidate_files:
            if not _is_android_ui_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in _iter_stripped_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            ):
                for member in _iter_ui_api_client_members(line):
                    message = (
                        f"UI code reaches directly into `ApiClient.{member}`; keep backend access "
                        "behind repository or data helpers."
                    )
                    if boundary_hint is not None:
                        message = (
                            f"UI code reaches directly into `ApiClient.{member}`; route backend "
                            f"access through boundary layers such as `{boundary_hint}`."
                        )
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=message,
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Keep transport calls in data/repository or dedicated data/api "
                                "helpers and expose UI-ready state through ViewModels."
                            ),
                            metadata={
                                "matched_pattern": f"ApiClient.{member}",
                                "boundary_layer": boundary_hint or "data/repository/*",
                            },
                        )
                    )
        return findings

    def _run_no_ui_direct_buildconfig_transport(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        boundary_hint = _android_repository_boundary_hint(context.repo_root)
        for relative_path in candidate_files:
            if not _is_android_ui_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in _iter_stripped_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            ):
                for name in _iter_ui_transport_build_config_names(line):
                    message = (
                        f"UI code reads transport config `BuildConfig.{name}` directly; keep "
                        "URLs and tenant routing inside repository or client helpers."
                    )
                    if boundary_hint is not None:
                        message = (
                            f"UI code reads transport config `BuildConfig.{name}` directly; keep "
                            f"URLs and tenant routing inside boundary layers such as "
                            f"`{boundary_hint}`."
                        )
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=message,
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Resolve API base URLs and tenant transport context in "
                                "ApiClient/repository/session helpers, then pass prepared data "
                                "into the UI."
                            ),
                            metadata={
                                "matched_pattern": f"BuildConfig.{name}",
                                "boundary_layer": boundary_hint or "data/repository/*",
                            },
                        )
                    )
        return findings

    def _run_no_ui_direct_preferences_manager(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        boundary_hint = _android_repository_boundary_hint(context.repo_root)
        for relative_path in candidate_files:
            if not _is_android_ui_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in _iter_stripped_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            ):
                if line.strip().startswith("import "):
                    continue
                matched_pattern = "ApiClient.preferencesManager"
                if _UI_PREFERENCES_MANAGER_PATTERN.search(line) is None:
                    direct_instantiation_match = (
                        _UI_PREFERENCES_MANAGER_CONSTRUCTION_PATTERN.search(line)
                    )
                    if (
                        direct_instantiation_match is None
                        or _CLASS_DECLARATION_START_PATTERN.search(line) is not None
                    ):
                        continue
                    matched_pattern = direct_instantiation_match.group("type")
                message = (
                    "UI code reaches into `ApiClient.preferencesManager` directly; route "
                    "persisted tenant/session state through state or repository helpers."
                )
                if matched_pattern != "ApiClient.preferencesManager":
                    message = (
                        f"UI code directly constructs `{matched_pattern}`; keep tenant/session "
                        "persistence behind repository or session helper boundaries."
                    )
                if boundary_hint is not None and matched_pattern == "ApiClient.preferencesManager":
                    message = (
                        "UI code reaches into `ApiClient.preferencesManager` directly; route "
                        f"persisted tenant/session state through boundary layers such as "
                        f"`{boundary_hint}`."
                    )
                elif boundary_hint is not None:
                    message = (
                        f"UI code directly constructs `{matched_pattern}`; route tenant/session "
                        f"persistence through boundary layers such as `{boundary_hint}`."
                    )
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=message,
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Move tenant/session persistence access behind repository, auth, "
                            "or session helper APIs and feed resolved state into the UI."
                        ),
                        metadata={
                            "matched_pattern": matched_pattern,
                            "boundary_layer": boundary_hint or "data/repository/*",
                        },
                    )
                )
        return findings

    def _run_api_contract_surface_needs_doc_refresh(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        contract_artifacts = _android_contract_artifact_paths(context.repo_root)
        changed_paths = {path.replace("\\", "/") for path in context.target_files}
        contract_surface_paths = [
            path
            for path in candidate_files
            if _is_android_contract_surface_path(path)
            and _has_android_contract_signal(_read_lines(context.repo_root, path))
        ]
        if not contract_surface_paths:
            return findings

        if context.mode is ExecutionMode.INVENTORY:
            if contract_artifacts:
                return findings
            relative_path = contract_surface_paths[0]
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Android transport and DTO contract surfaces exist without a checked-in "
                        "API contract artifact snapshot."
                    ),
                    location=FindingLocation(path=relative_path, line=1),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.ANDROID,
                    suggestion=(
                        "Check in an artifact such as api-docs.json or openapi.yaml when Android "
                        "Retrofit interfaces and DTO surfaces define a durable backend contract."
                    ),
                    metadata={
                        "matched_pattern": _android_contract_surface_kind(relative_path),
                        "contract_artifact": "",
                    },
                )
            )
            return findings

        if not changed_paths:
            return findings
        if not contract_artifacts:
            return findings
        if any(path in changed_paths for path in contract_artifacts):
            return findings

        artifact_hint = contract_artifacts[0]
        for relative_path in contract_surface_paths:
            if relative_path not in changed_paths:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Android API contract surface changed without refreshing `{artifact_hint}`; "
                        "keep checked-in contract snapshots aligned with Retrofit and DTO drift."
                    ),
                    location=FindingLocation(path=relative_path, line=1),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.ANDROID,
                    suggestion=(
                        "Refresh the checked-in API contract artifact whenever Retrofit "
                        "interfaces, request shapes, or response DTOs change."
                    ),
                    metadata={
                        "matched_pattern": _android_contract_surface_kind(relative_path),
                        "contract_artifact": artifact_hint,
                    },
                )
            )
        return findings

    def _run_variant_owned_release_config(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if Path(relative_path).name not in {"build.gradle", "build.gradle.kts"}:
                continue
            lines = _read_lines(context.repo_root, relative_path)
            if not _gradle_has_variant_surfaces(lines):
                continue
            for line_number, field_name, owner_block in _iter_variant_owned_default_config_fields(
                lines
            ):
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Variant-owned BuildConfig field `{field_name}` is declared in "
                            f"`{owner_block}`; keep release or tenant ownership inside buildTypes "
                            "or productFlavors."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Move release endpoints, tenant config, and secrets to release/debug "
                            "buildTypes or productFlavors instead of defaultConfig."
                        ),
                        metadata={
                            "field_name": field_name,
                            "owner_block": owner_block,
                        },
                    )
                )
        return findings

    def _run_dto_nullability_default_discipline(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _looks_like_android_dto_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for class_name, field_name, line_number in _iter_android_dto_default_violations(lines):
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Android DTO `{class_name}` keeps `{field_name}` non-null without a "
                            "default; prefer nullable fields or safe defaults for contract drift."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Make response DTO fields nullable or assign defaults so transport "
                            "parity changes do not crash deserialization paths."
                        ),
                        metadata={"class_name": class_name, "field_name": field_name},
                    )
                )
        return findings

    def _run_no_fragmented_deeplink_intent_parsing(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        boundary_hint = _android_navigation_boundary_hint(context.repo_root)
        if boundary_hint is None:
            return findings
        for relative_path in candidate_files:
            if not _is_android_source_path(
                context.repo_root, relative_path
            ) or _is_android_navigation_boundary_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in _iter_stripped_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            ):
                for pattern_name, pattern in _DEEPLINK_DIRECT_ACCESS_PATTERNS:
                    if pattern.search(line) is None:
                        continue
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=(
                                "Android deep-link and notification payload parsing should stay "
                                f"centralized in helpers such as `{boundary_hint}`."
                            ),
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Resolve Intent extras and deep-link params inside a dedicated "
                                "routing/coordinator helper, then pass typed targets into UI and "
                                "lifecycle boundaries."
                            ),
                            metadata={
                                "matched_pattern": pattern_name,
                                "boundary_layer": boundary_hint,
                            },
                        )
                    )
                    break
        return findings

    def _run_no_stringly_typed_state_machine(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            state_family = _stringly_typed_state_family(lines)
            if state_family is None:
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        f"Android flow coordinates `{state_family}` states through raw string "
                        "constants; prefer an enum or sealed state machine with explicit "
                        "transitions."
                    ),
                    location=FindingLocation(path=relative_path, line=1),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.ANDROID,
                    suggestion=(
                        "Replace raw string families with enum/sealed state types so transitions "
                        "and when branches stay explicit and reviewable."
                    ),
                    metadata={
                        "matched_pattern": "string-state-family",
                        "state_family": state_family,
                    },
                )
            )
        return findings

    def _run_no_service_or_receiver_direct_service_locator_access(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        boundary_hint = _android_repository_boundary_hint(context.repo_root)
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for (
                _class_line,
                class_name,
                _callback_names,
                body_start,
                body_end,
            ) in _iter_boundary_callback_class_ranges(sanitized_lines):
                if body_start >= body_end:
                    continue
                findings.extend(
                    self._boundary_service_locator_findings(
                        rule,
                        relative_path=relative_path,
                        lines=sanitized_lines,
                        class_name=class_name,
                        body_start=body_start,
                        body_end=body_end,
                        boundary_hint=boundary_hint,
                    )
                )
        return findings

    def _boundary_service_locator_findings(
        self,
        rule,
        *,
        relative_path: str,
        lines: Sequence[str],
        class_name: str,
        body_start: int,
        body_end: int,
        boundary_hint: str | None,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for index in range(body_start, body_end):
            line = lines[index]
            if not line.strip():
                continue
            dependency_type = _boundary_direct_dependency_type(lines, index)
            if dependency_type is not None:
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Lifecycle boundary `{class_name}` directly constructs "
                            f"`{dependency_type}`; inject repositories or preferences "
                            "collaborators instead of instantiating them inside services "
                            "and receivers."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Receive repository or session collaborators through the "
                            "boundary setup path and delegate callback work to those "
                            "collaborators or WorkManager."
                        ),
                        metadata={
                            "matched_pattern": dependency_type,
                            "boundary_class": class_name,
                            "access_kind": "direct-instantiation",
                            "boundary_layer": boundary_hint or "data/repository/*",
                        },
                    )
                )
                continue
            for member in _iter_boundary_service_locator_api_client_members(line):
                message = (
                    f"Lifecycle boundary `{class_name}` reaches directly into "
                    f"`ApiClient.{member}`; keep service locator access out of services "
                    "and receivers."
                )
                if boundary_hint is not None:
                    message = (
                        f"Lifecycle boundary `{class_name}` reaches directly into "
                        f"`ApiClient.{member}`; route that work through collaborators "
                        f"such as `{boundary_hint}`."
                    )
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=message,
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Keep transport and persistence lookups behind repositories, "
                            "session wrappers, or boundary-owned collaborators prepared "
                            "before the lifecycle callback runs."
                        ),
                        metadata={
                            "matched_pattern": f"ApiClient.{member}",
                            "boundary_class": class_name,
                            "access_kind": "api-client",
                            "boundary_layer": boundary_hint or "data/repository/*",
                        },
                    )
                )
        return findings

    def _run_no_viewmodel_direct_repository_instantiation(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for index, viewmodel_name, dependency_type in _iter_viewmodel_direct_instantiations(
                sanitized_lines
            ):
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"ViewModel `{viewmodel_name}` directly constructs "
                            f"`{dependency_type}` as a field; keep repositories and managers "
                            "outside the ViewModel construction boundary."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Receive repositories and managers through the ViewModel "
                            "constructor, factory, or DI container instead of instantiating "
                            "them inside the ViewModel."
                        ),
                        metadata={
                            "matched_pattern": dependency_type,
                            "viewmodel_class": viewmodel_name,
                        },
                    )
                )
        return findings

    def _run_no_default_viewmodel_parameter_in_composable(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_entrypoint_surface_path(relative_path):
                continue
            if Path(relative_path).suffix.lower() != ".kt":
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            for (
                line_number,
                composable_name,
                parameter_name,
                matched_call,
            ) in _iter_composable_default_viewmodel_parameters(sanitized_lines):
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Composable entrypoint `{composable_name}` defaults "
                            f"`{parameter_name}` via `{matched_call}`; pass the ViewModel from "
                            "the caller so screen dependencies stay explicit and testable."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Remove default ViewModel lookup from the Composable signature and "
                            "inject the dependency from a route, Activity, Fragment, or "
                            "preview/test harness."
                        ),
                        metadata={
                            "matched_pattern": matched_call,
                            "composable_name": composable_name,
                            "parameter_name": parameter_name,
                        },
                    )
                )
        return findings

    def _run_no_oversized_screen_composable(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_entrypoint_surface_path(relative_path):
                continue
            if Path(relative_path).suffix.lower() != ".kt":
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            for (
                function_line,
                composable_name,
                body_start,
                body_end,
            ) in _iter_composable_function_ranges(sanitized_lines):
                (
                    code_lines,
                    block_count,
                    max_depth,
                    state_count,
                    branch_count,
                ) = _oversized_screen_composable_metrics(sanitized_lines[body_start:body_end])
                if code_lines < _OVERSIZED_SCREEN_COMPOSABLE_MIN_CODE_LINES:
                    continue
                if block_count < _OVERSIZED_SCREEN_COMPOSABLE_MIN_BLOCK_COUNT:
                    continue
                if max_depth < _OVERSIZED_SCREEN_COMPOSABLE_MIN_NESTING_DEPTH:
                    continue
                if state_count == 0 and branch_count == 0:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Composable screen `{composable_name}` packs {code_lines} lines of "
                            f"nested UI/state flow (max depth {max_depth}) into one entrypoint; "
                            "split sections before the screen becomes hard to review and test."
                        ),
                        location=FindingLocation(path=relative_path, line=function_line + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Extract screen sections, state-to-UI mapping, or callback branches "
                            "into smaller composables/helpers so the route/screen entrypoint stays "
                            "focused."
                        ),
                        metadata={
                            "matched_pattern": composable_name,
                            "code_lines": str(code_lines),
                            "nested_block_count": str(block_count),
                            "max_nesting_depth": str(max_depth),
                            "state_signal_count": str(state_count),
                            "branch_count": str(branch_count),
                        },
                    )
                )
        return findings

    def _run_no_ui_detekt_suppression(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        if context.mode is ExecutionMode.INVENTORY:
            return []

        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, int, tuple[str, ...]]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_runtime_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            changed_lines = _changed_line_numbers_for_file(context, relative_path, len(lines))
            for line_number, end_line_number, suppressed_rules in _iter_ui_detekt_suppressions(lines):
                if changed_lines is not None and changed_lines.isdisjoint(
                    range(line_number, end_line_number + 1)
                ):
                    continue
                key = (relative_path, line_number, suppressed_rules)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                matched_suppressions = ", ".join(f"`{name}`" for name in suppressed_rules)
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Android UI/runtime code locally suppresses Detekt "
                            f"{matched_suppressions}; refactor the screen or ViewModel instead "
                            "of muting maintainability signals."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Split oversized UI/runtime code, extract helpers, or align naming "
                            "with the UI conventions instead of suppressing Detekt locally."
                        ),
                        metadata={"matched_pattern": ", ".join(suppressed_rules)},
                    )
                )
        return findings

    def _run_no_viewmodel_without_tests(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, str]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_viewmodel_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for class_line, viewmodel_name, body_start, body_end in _iter_viewmodel_class_ranges(
                sanitized_lines
            ):
                if not _is_substantial_viewmodel_body(sanitized_lines[body_start:body_end]):
                    continue
                if _find_nearby_viewmodel_test(context.repo_root, relative_path, viewmodel_name):
                    continue
                key = (relative_path, viewmodel_name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                expected_test_path = _preferred_viewmodel_test_path(relative_path, viewmodel_name)
                message = (
                    f"Substantial ViewModel `{viewmodel_name}` has no nearby "
                    f"`{viewmodel_name}Test` coverage."
                )
                if expected_test_path is not None:
                    message = f"{message} Add a focused test such as `{expected_test_path}`."
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=message,
                        location=FindingLocation(path=relative_path, line=class_line + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Add a nearby ViewModel test that covers state shaping, events, and "
                            "error paths, or split the ViewModel until smaller slices are easy "
                            "to exercise."
                        ),
                        metadata={
                            "matched_pattern": viewmodel_name,
                            "expected_test_path": expected_test_path or f"{viewmodel_name}Test.kt",
                        },
                    )
                )
        return findings

    def _run_no_boundary_callback_without_test(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        seen_keys: set[tuple[str, str]] = set()
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for (
                class_line,
                class_name,
                callback_names,
                body_start,
                body_end,
            ) in _iter_boundary_callback_class_ranges(sanitized_lines):
                matched_callbacks: list[str] = []
                class_body_lines = sanitized_lines[body_start:body_end]
                for (
                    _callback_line,
                    callback_name,
                    callback_body_start,
                    callback_body_end,
                ) in _iter_named_function_ranges(
                    class_body_lines,
                    required_names=callback_names,
                    require_override=True,
                ):
                    if _is_meaningful_boundary_callback_body(
                        class_body_lines[callback_body_start:callback_body_end]
                    ):
                        matched_callbacks.append(callback_name)
                if not matched_callbacks:
                    continue
                if _find_nearby_android_test(
                    context.repo_root,
                    relative_path,
                    f"{class_name}Test",
                ):
                    continue
                key = (relative_path, class_name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                expected_test_path = _preferred_android_test_path(
                    relative_path, f"{class_name}Test"
                )
                callback_list = ", ".join(dict.fromkeys(matched_callbacks))
                message = (
                    f"Boundary callback class `{class_name}` contains meaningful "
                    f"`{callback_list}` logic without nearby `{class_name}Test` coverage."
                )
                if expected_test_path is not None:
                    message = f"{message} Add a focused test such as `{expected_test_path}`."
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=message,
                        location=FindingLocation(path=relative_path, line=class_line + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Add a nearby boundary callback test that covers callback branches, "
                            "payload handling, and collaborator interactions, or move the logic "
                            "behind a smaller tested collaborator."
                        ),
                        metadata={
                            "matched_pattern": class_name,
                            "boundary_callbacks": callback_list,
                            "expected_test_path": expected_test_path or f"{class_name}Test.kt",
                        },
                    )
                )
        return findings

    def _run_raw_ui_color_literals(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        theme_hint = _android_theme_boundary_hint(context.repo_root)
        seen_keys: set[tuple[str, int, str]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in _iter_stripped_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            ):
                for match in _RAW_UI_COLOR_LITERAL_PATTERN.finditer(line):
                    color_value = match.group("value")
                    key = (relative_path, index + 1, color_value)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    message = (
                        f"Use shared theme tokens instead of raw UI color literal `{color_value}`."
                    )
                    if theme_hint is not None:
                        message = f"{message} Prefer the repo theme layer such as `{theme_hint}`."
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=message,
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Move colors into the Android theme/design-system layer and "
                                "reference shared tokens from screens and components."
                            ),
                            metadata={
                                "matched_pattern": color_value,
                                "boundary_layer": theme_hint or "ui/theme/Color.kt",
                            },
                        )
                    )
        return findings

    def _run_fixed_ui_layout_literals(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        theme_hint = _android_theme_boundary_hint(context.repo_root)
        seen_keys: set[tuple[str, int, str, str]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in _iter_stripped_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            ):
                for match in _FIXED_UI_LAYOUT_LITERAL_PATTERN.finditer(line):
                    value = match.group("value")
                    unit = match.group("unit")
                    if unit != "dp":
                        continue
                    if value in _ALLOWED_ANDROID_LAYOUT_LITERALS:
                        continue
                    key = (relative_path, index + 1, value, unit)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    message = (
                        f"Prefer shared layout tokens over raw `{value}.{unit}` in Android UI code."
                    )
                    if theme_hint is not None:
                        message = (
                            f"{message} Reuse spacing/radius tokens from `{theme_hint}` where "
                            "possible."
                        )
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=message,
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Promote repeated spacing, sizing, and radius values into the "
                                "shared Android design-system layer instead of raw dp/sp literals."
                            ),
                            metadata={
                                "matched_pattern": f"{value}.{unit}",
                                "boundary_layer": theme_hint or "ui/theme/DesignSystem.kt",
                            },
                        )
                    )
        return findings

    def _run_tiny_readability_text(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        theme_hint = _android_theme_boundary_hint(context.repo_root)
        seen_keys: set[tuple[str, int, str]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            if Path(relative_path).suffix.lower() != ".kt":
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            for line_number, matched_size in _iter_tiny_compose_text_sizes(sanitized_lines):
                key = (relative_path, line_number, matched_size)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                message = (
                    f"Avoid explicit tiny readability text size `{matched_size}` in Android UI "
                    f"code; text below `{int(_MIN_READABILITY_TEXT_SP)}.sp` is hard to scan."
                )
                if theme_hint is not None:
                    message = (
                        f"{message} Prefer shared typography or readable badge helpers from "
                        f"`{theme_hint}`."
                    )
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=message,
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Use shared typography tokens or a readable badge component instead of "
                            "explicit sub-12.sp text in screens and components."
                        ),
                        metadata={
                            "matched_pattern": matched_size,
                            "minimum_readable_size": f"{int(_MIN_READABILITY_TEXT_SP)}.sp",
                            "boundary_layer": theme_hint or "ui/theme/DesignSystem.kt",
                        },
                    )
                )
        return findings

    def _run_local_status_color_map(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        theme_hint = _android_theme_boundary_hint(context.repo_root)
        seen_keys: set[tuple[str, int]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for index, line in enumerate(sanitized_lines):
                if not line.strip():
                    continue
                if not _looks_like_local_status_color_map(line, sanitized_lines, index):
                    continue
                key = (relative_path, index + 1)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                message = (
                    "Semantic status color maps should stay in shared Android theme helpers "
                    "instead of local UI `when(status)` blocks."
                )
                if theme_hint is not None:
                    message = (
                        "Semantic status color maps should stay in shared Android theme helpers "
                        f"such as `{theme_hint}` instead of local UI `when(status)` blocks."
                    )
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=message,
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Promote status/badge/chip tone mapping into the shared theme or "
                            "design-system layer and consume a helper from UI code."
                        ),
                        metadata={
                            "matched_pattern": "when(status)",
                            "boundary_layer": theme_hint or "ui/theme/Color.kt",
                        },
                    )
                )
        return findings

    def _run_semantic_status_color_literals(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
        *,
        suppress_if_raw_color_rule_selected: bool,
    ) -> list[NormalizedFinding]:
        if suppress_if_raw_color_rule_selected:
            return []
        findings: list[NormalizedFinding] = []
        theme_hint = _android_theme_boundary_hint(context.repo_root)
        seen_keys: set[tuple[str, int, str]] = set()
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(
                lines,
                preserve_kotlin_templates=Path(relative_path).suffix.lower() == ".kt",
            )
            for index, line in enumerate(sanitized_lines):
                if not line.strip():
                    continue
                for match in _RAW_UI_COLOR_LITERAL_PATTERN.finditer(line):
                    color_value = match.group("value")
                    if not _has_semantic_status_context(sanitized_lines, index):
                        continue
                    key = (relative_path, index + 1, color_value)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    message = (
                        f"Semantic status styling should avoid raw color literal `{color_value}` "
                        "in Android UI code."
                    )
                    if theme_hint is not None:
                        message = f"{message} Prefer the shared theme boundary `{theme_hint}`."
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=message,
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Route badge/chip/status colors through shared semantic theme "
                                "tokens instead of inline Compose color literals."
                            ),
                            metadata={
                                "matched_pattern": color_value,
                                "boundary_layer": theme_hint or "ui/theme/Color.kt",
                            },
                        )
                    )
        return findings

    def _run_no_secret_fallback_literals(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_secret_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index in range(len(lines)):
                if Path(
                    relative_path
                ).suffix.lower() in _SECRET_CONFIG_SUFFIXES and not _should_scan_gradle_secret_line(
                    lines[index]
                ):
                    continue
                scan_text = _secret_scan_text(relative_path, lines, index)
                fallback = _secret_fallback_match(relative_path, lines[index], scan_text)
                if fallback is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Android build or runtime config falls back to an inline secret "
                            "literal; require secure environment or Gradle input instead."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Remove the checked-in fallback literal and fail fast or inject the "
                            "credential from environment, Gradle properties, or secure storage."
                        ),
                        metadata={"matched_pattern": fallback},
                    )
                )
        return findings

    def _run_gson_nonnull_field_needs_nullable_type(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for class_name, field_name, line_number in _iter_gson_nonnull_fields(lines):
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Gson-deserialized Kotlin field `{field_name}` in `{class_name}` "
                            "is non-null without a default; Gson may silently inject nulls."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=("Make the field nullable (`Type?`) or provide a safe default."),
                        metadata={"class_name": class_name, "field_name": field_name},
                    )
                )
        return findings

    def _run_api_response_type_must_match_contract(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            content = "\n".join(lines)
            if not _RETROFIT_LIST_RETURN_PATTERN.search(content):
                continue
            if (
                _PAGED_RESPONSE_IMPORT_PATTERN.search(content) is None
                and _PAGED_RESPONSE_USAGE_PATTERN.search(content) is None
            ):
                continue
            for index, line in enumerate(lines):
                if _RETROFIT_LIST_RETURN_PATTERN.search(
                    "\n".join(lines[max(0, index - 2) : index + 3])
                ):
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=(
                                "Retrofit service returns `List<T>` but the repo uses "
                                "`PagedResponse<T>`; align the wrapper type with the backend contract."
                            ),
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Return `PagedResponse<T>` or an equivalent contract wrapper "
                                "instead of a raw list."
                            ),
                            metadata={"matched_pattern": "retrofit-list-return"},
                        )
                    )
                    break
        return findings

    def _run_viewmodel_cleared_must_be_singular(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            cleared_lines = [
                index for index, line in enumerate(lines) if _ONCLEARED_PATTERN.search(line)
            ]
            if len(cleared_lines) > 1:
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"ViewModel contains {len(cleared_lines)} `onCleared()` overrides; "
                            "only one is allowed."
                        ),
                        location=FindingLocation(path=relative_path, line=cleared_lines[1] + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=("Merge cleanup logic into a single `onCleared()` override."),
                        metadata={
                            "matched_pattern": "duplicate-oncleared",
                            "count": str(len(cleared_lines)),
                        },
                    )
                )
        return findings

    def _run_geofence_transition_needs_debounce(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            content = "\n".join(lines)
            if _GEOFENCE_EXIT_PATTERN.search(content) is None:
                continue
            if _GEOFENCE_DEBOUNCE_SAFE_PATTERN.search(content):
                continue
            for index, line in enumerate(lines):
                if _GEOFENCE_EXIT_PATTERN.search(line):
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=(
                                "Geofence EXIT transition triggers side effects without "
                                "visible debounce, delay, or alarm guard."
                            ),
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=("Add a debounce, delay, or alarm before acting on EXIT."),
                            metadata={"matched_pattern": "geofence-exit-immediate"},
                        )
                    )
                    break
        return findings

    def _run_no_hardcoded_credentials_in_buildconfig(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if Path(relative_path).name not in {"build.gradle", "build.gradle.kts"}:
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in enumerate(lines):
                match = _BUILDCONFIG_CREDENTIAL_PATTERN.search(line)
                if match is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Hardcoded credential `{match.group('name')}` found in "
                            f"`{Path(relative_path).name}`."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Load credentials from environment, Gradle properties, or "
                            "secure storage instead of embedding them in build config."
                        ),
                        metadata={
                            "matched_pattern": match.group("name"),
                            "field_name": match.group("name"),
                        },
                    )
                )
        return findings

    def _run_no_sensitive_token_in_url_query(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in enumerate(lines):
                match = _QUERY_TOKEN_PATTERN.search(line)
                if match is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Sensitive token `{match.group('name')}` is sent as a URL query "
                            "parameter; move it to the request body or header."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Use `@Body` or `@Header` for sensitive tokens instead of `@Query`."
                        ),
                        metadata={"matched_pattern": match.group("name")},
                    )
                )
        return findings

    def _run_fcm_default_notification_channel_required(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        manifest_files = [
            path for path in candidate_files if path.lower().endswith("androidmanifest.xml")
        ]
        if not manifest_files and context.mode is ExecutionMode.INVENTORY:
            manifest_files = [
                path.relative_to(context.repo_root).as_posix()
                for path in context.repo_root.rglob("AndroidManifest.xml")
                if path.is_file()
                and not _has_excluded_path_marker(
                    path.relative_to(context.repo_root).as_posix().lower()
                )
            ]
        for relative_path in manifest_files:
            lines = _read_lines(context.repo_root, relative_path)
            content = "\n".join(lines)
            if "com.google.firebase.messaging" not in content:
                continue
            if _FCM_CHANNEL_META_PATTERN.search(content):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "FCM is used but `com.google.firebase.messaging."
                        "default_notification_channel_id` is missing from AndroidManifest.xml."
                    ),
                    location=FindingLocation(path=relative_path, line=1),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.ANDROID,
                    suggestion=(
                        "Add the default notification channel meta-data to AndroidManifest.xml."
                    ),
                    metadata={"matched_pattern": "missing-fcm-default-channel"},
                )
            )
        return findings

    def _run_dialog_state_must_be_hoisted_above_conditional(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            brace_depth = 0
            in_conditional = False
            for index, line in enumerate(sanitized_lines):
                stripped = line.strip()
                if _CONDITIONAL_BLOCK_START_PATTERN.search(stripped):
                    in_conditional = True
                if "{" in stripped:
                    brace_depth += stripped.count("{")
                if "}" in stripped:
                    brace_depth -= stripped.count("}")
                    if brace_depth <= 0:
                        in_conditional = False
                        brace_depth = 0
                if in_conditional and _REMEMBER_STATE_IN_CONDITIONAL_PATTERN.search(stripped):
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=(
                                "Dialog or bottom-sheet state is remembered inside a conditional "
                                "block; hoist it above the branch so it survives recomposition."
                            ),
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Move `remember { mutableStateOf(...) }` above the `if` or "
                                "`when` block."
                            ),
                            metadata={"matched_pattern": "remembered-state-in-conditional"},
                        )
                    )
                    in_conditional = False
        return findings

    def _run_unsupported_parameter_must_not_be_used(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            seen_keys: set[tuple[str, int, str]] = set()
            for index, line in enumerate(sanitized_lines):
                match = _UNSUPPORTED_COMPOSE_PARAM_PATTERN.search(line)
                if match is None:
                    continue
                param_name = match.group(0).split("=")[0].strip()
                key = (relative_path, index + 1, param_name)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            f"Compose parameter `{param_name}` may not be supported by the "
                            "current dependency version."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=("Verify the parameter is supported or use an alternative API."),
                        metadata={"matched_pattern": param_name},
                    )
                )
        return findings

    def _run_dark_theme_textfield_needs_explicit_text_color(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            content = "\n".join(lines)
            if _DARK_THEME_REFERENCE_PATTERN.search(content) is None:
                continue
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            for start_index, block_text in _iter_compose_call_blocks(
                sanitized_lines, _COMPOSE_TEXT_INPUT_PATTERN
            ):
                if _TEXTFIELD_COLOR_SAFE_PATTERN.search(block_text):
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "OutlinedTextField/BasicTextField in a dark-theme file lacks "
                            "explicit text color styling."
                        ),
                        location=FindingLocation(path=relative_path, line=start_index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Add `colors = ...` or `textColor` to ensure readability in dark theme."
                        ),
                        metadata={"matched_pattern": "missing-textfield-color-dark-theme"},
                    )
                )
        return findings

    def _run_proguard_r8_must_keep_generic_type_signatures(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if Path(relative_path).name not in {
                "proguard-rules.pro",
                "consumer-rules.pro",
            }:
                continue
            lines = _read_lines(context.repo_root, relative_path)
            content = "\n".join(lines)
            if _PROGUARD_GSON_RETROFIT_PATTERN.search(content) is None:
                continue
            if _PROGUARD_SIGNATURE_KEEP_PATTERN.search(content):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "ProGuard/R8 rules mention Gson or Retrofit but omit "
                        "`-keepattributes Signature`."
                    ),
                    location=FindingLocation(path=relative_path, line=1),
                    adapter_id=self.adapter_key,
                    language=RepoLanguage.ANDROID,
                    suggestion=(
                        "Add `-keepattributes Signature` to preserve generic type information."
                    ),
                    metadata={"matched_pattern": "missing-signature-keep"},
                )
            )
        return findings

    def _run_custom_flow_first_extension_is_unsafe(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            for index, line in enumerate(sanitized_lines):
                if _CUSTOM_FLOW_FIRST_PATTERN.search(line) is None:
                    continue
                window = _window_text(sanitized_lines, index, before=0, after=8)
                if _FLOW_COLLECT_PATTERN.search(window):
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=(
                                "Custom `Flow.first()` extension uses `collect` internally; "
                                "this is unsafe and may leak or hang."
                            ),
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Use the standard `kotlinx.coroutines.flow.first()` operator."
                            ),
                            metadata={"matched_pattern": "custom-flow-first-collect"},
                        )
                    )
                    break
        return findings

    def _run_okhttp_legacy_mediatype_needs_extension(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in enumerate(lines):
                if _OKHTTP_LEGACY_MEDIATYPE_PATTERN.search(line) is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Deprecated OkHttp 3.x `MediaType.parse` or `RequestBody.create` "
                            "detected; prefer OkHttp 4.x extension functions."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            'Use `"application/json".toMediaType()` and `"...".toRequestBody()` '
                            "instead."
                        ),
                        metadata={"matched_pattern": "okhttp-legacy-mediatype"},
                    )
                )
        return findings

    def _run_deep_link_routing_must_use_shared_target_parser(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            stem = Path(relative_path).stem.lower()
            if "fcm" not in stem and "main" not in stem:
                continue
            lines = _read_lines(context.repo_root, relative_path)
            for index, line in enumerate(lines):
                if _DEEP_LINK_INTENT_FIELD_PATTERN.search(line) is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Deep-link Intent parsing is performed directly in "
                            f"`{Path(relative_path).name}`; use a shared navigation helper."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Route deep-link parsing through a shared `NotificationNavigation` "
                            "or `DeepLinkParser` helper."
                        ),
                        metadata={"matched_pattern": "direct-intent-deep-link-parsing"},
                    )
                )
                break
        return findings

    def _run_keyboard_input_needs_ime_padding(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_ui_rule_surface_path(relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            if not any(_COMPOSE_TEXT_INPUT_PATTERN.search(line) for line in sanitized_lines):
                continue
            if any(re.search(r"\bimePadding\b", line) for line in sanitized_lines):
                continue
            for index, line in enumerate(sanitized_lines):
                if _COMPOSE_TEXT_INPUT_PATTERN.search(line):
                    findings.append(
                        NormalizedFinding.from_rule(
                            rule,
                            message=(
                                "TextField present without `Modifier.imePadding()`; "
                                "keyboard may cover the input."
                            ),
                            location=FindingLocation(path=relative_path, line=index + 1),
                            adapter_id=self.adapter_key,
                            language=RepoLanguage.ANDROID,
                            suggestion=(
                                "Add `Modifier.imePadding()` or wrap the screen in an "
                                "IME-aware scaffold."
                            ),
                            metadata={"matched_pattern": "missing-ime-padding"},
                        )
                    )
                    break
        return findings

    def _run_notification_deep_link_must_fetch_by_id(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            for index, line in enumerate(sanitized_lines):
                if _NOTIFICATION_DEEP_LINK_INDEX_PATTERN.search(line) is None:
                    continue
                context_window = "\n".join(sanitized_lines[max(0, index - 5) : index + 6])
                if _NOTIFICATION_DEEP_LINK_CONTEXT_PATTERN.search(context_window) is None:
                    continue
                if _NOTIFICATION_DEEP_LINK_LOAD_BY_ID_PATTERN.search(context_window):
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Notification deep link uses a stale list index instead of "
                            "fetching the entity by ID."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Use `loadById(id)` or an equivalent repository call instead of "
                            "relying on list position."
                        ),
                        metadata={"matched_pattern": "notification-index-deep-link"},
                    )
                )
                break
        return findings

    def _run_async_paginated_fetch_without_generation_guard(
        self,
        rule,
        context: AdapterContext,
        candidate_files: Sequence[str],
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for relative_path in candidate_files:
            if not _is_android_source_path(context.repo_root, relative_path):
                continue
            lines = _read_lines(context.repo_root, relative_path)
            sanitized_lines = _sanitize_code_lines(lines, preserve_kotlin_templates=True)
            joined = "\n".join(sanitized_lines)
            if not _VIEWMODEL_CLASS_PATTERN.search(joined):
                continue
            if not _PAGINATED_FETCH_PATTERN.search(joined):
                continue
            if not _ASYNC_RESULT_HANDLING_PATTERN.search(joined):
                continue
            if _GENERATION_GUARD_PATTERN.search(joined):
                continue
            for index, line in enumerate(sanitized_lines):
                if not _PAGINATED_FETCH_PATTERN.search(line):
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Paginated ViewModel fetch mutates list state after async work "
                            "without a generation guard."
                        ),
                        location=FindingLocation(path=relative_path, line=index + 1),
                        adapter_id=self.adapter_key,
                        language=RepoLanguage.ANDROID,
                        suggestion=(
                            "Track fetchGeneration/currentGeneration and bail out when "
                            "`generation != currentGeneration` after await/getOrElse."
                        ),
                        metadata={"matched_pattern": "async-paginated-fetch-without-generation"},
                    )
                )
                break
        return findings


def _is_supported_android_path(repo_root: Path, path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    if _has_excluded_path_marker(lower):
        return False
    suffix = Path(lower).suffix
    if lower.endswith("androidmanifest.xml"):
        return _path_is_under_android_module(repo_root, normalized)
    if Path(lower).name in {"proguard-rules.pro", "consumer-rules.pro"}:
        return _path_is_under_android_module(repo_root, normalized)
    return suffix in _SUPPORTED_SUFFIXES and _path_is_under_android_module(repo_root, normalized)


def _is_android_source_path(repo_root: Path, path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    if _has_excluded_path_marker(lower):
        return False
    return Path(lower).suffix in _SOURCE_SUFFIXES and _path_is_under_android_module(
        repo_root, normalized
    )


def _is_android_ui_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    return "/ui/" in f"/{lower.strip('/')}/" and Path(lower).suffix in _SOURCE_SUFFIXES


def _is_android_ui_rule_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    return _is_android_ui_surface_path(normalized) and "/ui/theme/" not in f"/{lower.strip('/')}/"


def _is_android_ui_entrypoint_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    framed_path = f"/{lower.strip('/')}/"
    return _is_android_ui_rule_surface_path(normalized) and any(
        marker in framed_path
        for marker in ("/ui/route/", "/ui/routes/", "/ui/screen/", "/ui/screens/")
    )


def _is_android_ui_viewmodel_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    framed_path = f"/{lower.strip('/')}/"
    return (
        "/ui/" in framed_path
        and Path(lower).suffix in _SOURCE_SUFFIXES
        and Path(lower).stem.endswith("viewmodel")
    )


def _is_android_ui_runtime_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return _is_android_ui_rule_surface_path(normalized) or _is_android_ui_viewmodel_path(normalized)


def _has_excluded_path_marker(path: str) -> bool:
    framed_path = f"/{path.strip('/')}/"
    return any(marker in framed_path for marker in _EXCLUDED_PATH_MARKERS)


def _path_is_under_android_module(repo_root: Path, path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    if lower.startswith("android/"):
        return True

    candidate = Path(normalized)
    if candidate.name in {"build.gradle", "build.gradle.kts"}:
        return _gradle_file_declares_android_plugin(repo_root / normalized)

    parts = candidate.parts
    if "src" in parts:
        src_index = parts.index("src")
        module_parts = parts[:src_index]
        if module_parts:
            module_root = repo_root.joinpath(*module_parts)
            marker_paths = (
                module_root / "src" / "main" / "AndroidManifest.xml",
                module_root / "src" / "debug" / "AndroidManifest.xml",
                module_root / "src" / "release" / "AndroidManifest.xml",
            )
            if any(marker.exists() for marker in marker_paths):
                return True

            return any(
                _gradle_file_declares_android_plugin(candidate)
                for candidate in (module_root / "build.gradle", module_root / "build.gradle.kts")
            )

    # Fallback for module-root files (e.g., proguard-rules.pro)
    for parent in candidate.parents:
        if parent == Path("."):
            continue
        module_root = repo_root / parent
        if any(
            _gradle_file_declares_android_plugin(candidate)
            for candidate in (module_root / "build.gradle", module_root / "build.gradle.kts")
        ):
            return True
    return False


def _read_lines(repo_root: Path, relative_path: str) -> tuple[str, ...]:
    content = (repo_root / relative_path).read_text(encoding="utf-8", errors="ignore")
    return tuple(content.splitlines())


def _sanitize_code_lines(
    lines: Sequence[str], *, preserve_kotlin_templates: bool
) -> tuple[str, ...]:
    sanitized_lines: list[str] = []
    in_block_comment = False
    in_triple_string = False
    for line in lines:
        stripped, in_block_comment, in_triple_string = _strip_non_code_segments(
            line,
            in_block_comment=in_block_comment,
            in_triple_string=in_triple_string,
            preserve_kotlin_templates=preserve_kotlin_templates,
        )
        sanitized_lines.append(stripped)
    return tuple(sanitized_lines)


def _iter_stripped_code_lines(
    lines: Sequence[str], *, preserve_kotlin_templates: bool
) -> Iterable[tuple[int, str]]:
    for index, stripped in enumerate(
        _sanitize_code_lines(lines, preserve_kotlin_templates=preserve_kotlin_templates)
    ):
        if stripped.strip():
            yield index, stripped


def _strip_non_code_segments(
    line: str,
    *,
    in_block_comment: bool,
    in_triple_string: bool,
    preserve_kotlin_templates: bool,
) -> tuple[str, bool, bool]:
    result: list[str] = []
    index = 0
    while index < len(line):
        if in_block_comment:
            comment_end = line.find("*/", index)
            if comment_end == -1:
                return "".join(result), True, in_triple_string
            index = comment_end + 2
            in_block_comment = False
            continue

        if in_triple_string:
            if preserve_kotlin_templates and line.startswith("${", index):
                expression, index = _extract_kotlin_template_expression(line, index + 2)
                result.append(expression)
                continue
            if line.startswith('"""', index):
                index += 3
                in_triple_string = False
                continue
            index += 1
            continue

        if line.startswith("/*", index):
            index += 2
            in_block_comment = True
            continue
        if line.startswith("//", index):
            break
        if line.startswith('"""', index):
            index += 3
            in_triple_string = True
            continue

        char = line[index]
        if char == '"':
            index = _consume_quoted_segment(
                line,
                index + 1,
                quote='"',
                result=result,
                preserve_kotlin_templates=preserve_kotlin_templates,
            )
            continue
        if char == "'":
            index = _consume_quoted_segment(
                line,
                index + 1,
                quote="'",
                result=None,
                preserve_kotlin_templates=False,
            )
            continue
        result.append(char)
        index += 1

    return "".join(result), in_block_comment, in_triple_string


def _consume_quoted_segment(
    line: str,
    start_index: int,
    *,
    quote: str,
    result: list[str] | None,
    preserve_kotlin_templates: bool,
) -> int:
    index = start_index
    while index < len(line):
        if line[index] == "\\":
            index += 2
            continue
        if preserve_kotlin_templates and quote == '"' and line.startswith("${", index):
            expression, index = _extract_kotlin_template_expression(line, index + 2)
            if result is not None:
                result.append(expression)
            continue
        if line[index] == quote:
            return index + 1
        index += 1
    return index


def _extract_kotlin_template_expression(line: str, start_index: int) -> tuple[str, int]:
    depth = 1
    index = start_index
    expression: list[str] = []
    while index < len(line):
        char = line[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return "".join(expression), index + 1
        expression.append(char)
        index += 1
    return "".join(expression), index


def _android_repository_boundary_hint(repo_root: Path) -> str | None:
    candidates = sorted(
        path.relative_to(repo_root).as_posix()
        for path in repo_root.glob("**/data/repository/*.kt")
        if path.is_file()
        and not _has_excluded_path_marker(path.relative_to(repo_root).as_posix().lower())
    )
    return candidates[0] if candidates else None


def _android_theme_boundary_hint(repo_root: Path) -> str | None:
    preferred_candidates = (
        "ui/theme/DesignSystem.kt",
        "ui/theme/Color.kt",
        "ui/theme/Theme.kt",
    )
    for suffix in preferred_candidates:
        matches = sorted(
            path.relative_to(repo_root).as_posix()
            for path in repo_root.glob(f"**/{suffix}")
            if path.is_file()
            and not _has_excluded_path_marker(path.relative_to(repo_root).as_posix().lower())
        )
        if matches:
            return matches[0]
    return None


def _android_navigation_boundary_hint(repo_root: Path) -> str | None:
    for pattern in (
        "**/*NotificationNavigation.kt",
        "**/*Navigation.kt",
        "**/*Routing.kt",
        "**/*Coordinator.kt",
    ):
        matches = sorted(
            path.relative_to(repo_root).as_posix()
            for path in repo_root.glob(pattern)
            if path.is_file()
            and not _has_excluded_path_marker(path.relative_to(repo_root).as_posix().lower())
        )
        if matches:
            return matches[0]
    return None


def _android_contract_artifact_paths(repo_root: Path) -> tuple[str, ...]:
    matches: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        relative_path = path.relative_to(repo_root).as_posix()
        if _has_excluded_path_marker(relative_path.lower()):
            continue
        if any(pattern.match(path.name) for pattern in _CONTRACT_ARTIFACT_NAME_PATTERNS):
            matches.append(relative_path)
    return tuple(sorted(dict.fromkeys(matches)))


def _is_android_contract_surface_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    if Path(lower).suffix not in _SOURCE_SUFFIXES:
        return False
    return any(
        marker in f"/{lower.strip('/')}/" for marker in ("/data/api/", "/data/model/", "/dto/")
    )


def _has_android_contract_signal(lines: Sequence[str]) -> bool:
    content = "\n".join(lines)
    return any(
        token in content
        for token in (
            "@GET(",
            "@POST(",
            "@PUT(",
            "@PATCH(",
            "@DELETE(",
            "@SerializedName(",
            "Response<",
        )
    )


def _android_contract_surface_kind(path: str) -> str:
    normalized = path.replace("\\", "/").lower()
    if "/data/api/" in f"/{normalized.strip('/')}/":
        return "retrofit-contract-surface"
    return "dto-contract-surface"


def _looks_like_android_dto_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    return Path(lower).suffix in _SOURCE_SUFFIXES and any(
        marker in f"/{lower.strip('/')}/" for marker in ("/data/model/", "/dto/")
    )


def _iter_android_dto_default_violations(
    lines: Sequence[str],
) -> Iterable[tuple[str, str, int]]:
    class_name: str | None = None
    constructor_depth = 0
    for index, line in enumerate(lines):
        class_match = _DTO_CLASS_DECLARATION_PATTERN.search(line)
        if class_match is not None:
            candidate_name = class_match.group("name")
            class_name = (
                None
                if _REQUEST_DTO_NAME_PATTERN.search(candidate_name) is not None
                else candidate_name
            )
            constructor_depth = line.count("(") - line.count(")")
            continue
        if class_name is None:
            continue
        constructor_depth += line.count("(") - line.count(")")
        field_match = _DTO_FIELD_LINE_PATTERN.search(line)
        if field_match is not None:
            field_type = field_match.group("type").strip()
            has_default = field_match.group("default") is not None
            if "?" not in field_type and not has_default:
                yield class_name, field_match.group("name"), index + 1
        if constructor_depth <= 0:
            class_name = None


def _is_android_navigation_boundary_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    stem = Path(normalized).stem
    return any(token in stem for token in ("navigation", "routing", "coordinator", "router"))


def _stringly_typed_state_family(lines: Sequence[str]) -> str | None:
    families: dict[str, int] = {}
    for line in lines:
        match = _STRING_STATE_CONSTANT_PATTERN.search(line)
        if match is None:
            continue
        family = match.group("family")
        families[family] = families.get(family, 0) + 1
    if not families:
        return None

    content = "\n".join(lines)
    for family, count in families.items():
        if count < 3:
            continue
        if _STRING_STATE_HOLDER_PATTERN.search(content) is None:
            continue
        if family not in content:
            continue
        if _STRING_STATE_WHEN_PATTERN.search(content) is None and f"{family}_" not in content:
            continue
        return family
    return None


def _gradle_has_variant_surfaces(lines: Sequence[str]) -> bool:
    content = "\n".join(lines)
    return "buildTypes {" in content or "productFlavors {" in content


def _iter_variant_owned_default_config_fields(
    lines: Sequence[str],
) -> Iterable[tuple[int, str, str]]:
    block_stack: list[str] = []
    for index, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if not stripped:
            continue

        match = _GRADLE_BLOCK_DECLARATION_PATTERN.search(stripped)
        if match is not None:
            block_stack.append(match.group("name"))

        field_match = _GRADLE_BUILD_CONFIG_FIELD_PATTERN.search(stripped)
        if field_match is not None and "defaultConfig" in block_stack:
            field_name = field_match.group("name")
            if _is_variant_owned_build_config_name(field_name):
                yield index + 1, field_name, "defaultConfig"

        closing_braces = stripped.count("}")
        while closing_braces > 0 and block_stack:
            block_stack.pop()
            closing_braces -= 1


def _is_variant_owned_build_config_name(field_name: str) -> bool:
    if field_name.startswith("DEFAULT_"):
        return False
    if field_name in _VARIANT_OWNED_BUILD_CONFIG_EXACT_NAMES:
        return True
    return _VARIANT_OWNED_BUILD_CONFIG_NAME_PATTERN.search(field_name) is not None


def _gradle_file_declares_android_plugin(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    content = path.read_text(encoding="utf-8", errors="ignore")
    return (
        "com.android." in content
        or re.search(r"^\s*android\s*\{", content, re.MULTILINE) is not None
    )


def _window_text(lines: Sequence[str], index: int, *, before: int, after: int) -> str:
    start = max(0, index - before)
    end = min(len(lines), index + after + 1)
    return "\n".join(lines[start:end])


def _main_thread_io_match_name(line: str) -> str | None:
    if _PREFS_COMMIT_PATTERN.search(line):
        return "shared_preferences_commit"
    if any(pattern.search(line) for pattern in _FILE_IO_PATTERNS):
        return "file_io"
    if any(pattern.search(line) for pattern in _NETWORK_IO_PATTERNS):
        return "network_io"
    return None


def _runblocking_hotpath_match_name(
    lines: Sequence[str], index: int, relative_path: str
) -> str | None:
    line = lines[index]
    if _RUNBLOCKING_PATTERN.search(line) is None:
        return None
    if _is_android_ui_surface_path(relative_path) and not _has_preview_annotation(lines, index):
        return "ui-surface"

    stem = Path(relative_path).stem.lower()
    context_window = _window_text(lines, index, before=40, after=8)
    if (
        "interceptor" in stem
        or _RUNBLOCKING_INTERCEPTOR_CLASS_PATTERN.search(context_window)
        or _RUNBLOCKING_INTERCEPT_METHOD_PATTERN.search(context_window)
    ):
        return "okhttp-interceptor"
    if (
        "authenticator" in stem
        or _RUNBLOCKING_AUTHENTICATOR_CLASS_PATTERN.search(context_window)
        or _RUNBLOCKING_AUTHENTICATE_METHOD_PATTERN.search(context_window)
    ):
        return "okhttp-authenticator"
    return None


def _unscoped_boundary_coroutine_match(
    lines: Sequence[str], index: int, relative_path: str
) -> tuple[str, str] | None:
    callback_match = _boundary_callback_match(lines, index, relative_path)
    if callback_match is None:
        return None

    boundary_name, boundary_index = callback_match
    coroutine_window = _window_text(lines, index, before=0, after=4)
    if any(token in coroutine_window for token in _BOUNDARY_COROUTINE_MANAGED_SCOPE_TOKENS):
        return None

    launch_pattern: str | None = None
    if _UNSCOPED_BOUNDARY_COROUTINE_PATTERN.search(coroutine_window) is not None:
        launch_pattern = "coroutine_scope_launch"
    elif _GLOBAL_SCOPE_BOUNDARY_COROUTINE_PATTERN.search(coroutine_window) is not None:
        launch_pattern = "global_scope_launch"
    if launch_pattern is None:
        return None

    coordination_window = _window_text(
        lines,
        boundary_index,
        before=0,
        after=min(20, len(lines) - boundary_index - 1),
    )
    if _BOUNDARY_COROUTINE_COORDINATION_PATTERN.search(coordination_window) is not None:
        return None
    return boundary_name, launch_pattern


def _boundary_callback_match(
    lines: Sequence[str], index: int, relative_path: str
) -> tuple[str, int] | None:
    start = max(0, index - 40)
    stem = Path(relative_path).stem.lower()
    for candidate_index in range(index, start - 1, -1):
        if not _line_still_scopes_match(lines, candidate_index, index):
            continue
        signature_window = _window_text(
            lines,
            candidate_index,
            before=0,
            after=min(4, index - candidate_index),
        )
        for match_name, method_pattern, owner_pattern in _BOUNDARY_CALLBACK_PATTERNS:
            if method_pattern.search(signature_window) is None:
                continue
            owner_window = _window_text(
                lines,
                candidate_index,
                before=min(40, candidate_index),
                after=1,
            )
            if owner_pattern.search(owner_window) is None and not _boundary_callback_owner_matches(
                match_name,
                stem,
            ):
                continue
            return match_name, candidate_index
    return None


def _boundary_callback_owner_matches(match_name: str, stem: str) -> bool:
    if match_name.startswith("broadcastreceiver"):
        return "receiver" in stem
    if match_name.startswith("fcm-"):
        return "messaging" in stem or "firebase" in stem or "service" in stem
    return "service" in stem


def _blocking_sync_wrapper_match(
    lines: Sequence[str], index: int, relative_path: str
) -> tuple[str, str] | None:
    if _RUNBLOCKING_PATTERN.search(_window_text(lines, index, before=0, after=3)) is None:
        return None

    function_context = _enclosing_function_context(lines, index)
    if function_context is None:
        return None
    function_index, function_name, is_suspend = function_context
    if is_suspend:
        return None

    class_context = _enclosing_class_context(lines, index)
    owner_name = class_context[1] if class_context is not None else Path(relative_path).stem
    if not _looks_like_sync_wrapper_function(function_name) and not _looks_like_sync_wrapper_owner(
        owner_name
    ):
        return None

    function_window = _window_text(
        lines,
        function_index,
        before=0,
        after=min(20, max(8, index - function_index + 8)),
    )
    matched_pattern = _blocking_sync_wrapper_async_kind(function_window)
    if matched_pattern is None:
        return None

    if _runblocking_hotpath_match_name(
        lines, index, relative_path
    ) is not None and not _looks_like_sync_wrapper_function(function_name):
        return None
    return matched_pattern, function_name


def _enclosing_function_context(lines: Sequence[str], index: int) -> tuple[int, str, bool] | None:
    start = max(0, index - 30)
    for candidate_index in range(index, start - 1, -1):
        if not _line_still_scopes_match(lines, candidate_index, index):
            continue
        window = _window_text(
            lines,
            candidate_index,
            before=0,
            after=min(4, index - candidate_index),
        )
        match = _FUNCTION_SIGNATURE_PATTERN.search(window)
        if match is None:
            continue
        return candidate_index, match.group("name"), bool(match.group("suspend"))
    return None


def _enclosing_class_context(lines: Sequence[str], index: int) -> tuple[int, str] | None:
    start = max(0, index - 60)
    for candidate_index in range(index, start - 1, -1):
        if not _line_still_scopes_match(lines, candidate_index, index):
            continue
        window = _window_text(
            lines,
            candidate_index,
            before=0,
            after=min(6, index - candidate_index),
        )
        match = _CLASS_SIGNATURE_PATTERN.search(window)
        if match is None:
            continue
        return candidate_index, match.group("name")
    return None


def _looks_like_sync_wrapper_function(name: str) -> bool:
    normalized = name.lower()
    return normalized.endswith("sync") or normalized.endswith("blocking")


def _looks_like_sync_wrapper_owner(name: str) -> bool:
    return _BLOCKING_SYNC_WRAPPER_OWNER_PATTERN.search(name) is not None


def _blocking_sync_wrapper_async_kind(window: str) -> str | None:
    if any(pattern.search(window) for pattern in _BLOCKING_SYNC_WRAPPER_DATASTORE_PATTERNS):
        return "datastore-sync-wrapper"
    if any(pattern.search(window) for pattern in _BLOCKING_SYNC_WRAPPER_NETWORK_PATTERNS):
        return "network-sync-wrapper"
    return None


def _has_preview_annotation(lines: Sequence[str], index: int) -> bool:
    start = max(0, index - 3)
    return any("@Preview" in lines[candidate_index] for candidate_index in range(start, index + 1))


def _unsafe_ui_trigger_name(lines: Sequence[str], index: int) -> str | None:
    line = lines[index]
    coroutine_window = _window_text(lines, index, before=0, after=3)
    if "CoroutineScope" in line and _UNSAFE_UI_TRIGGER_PATTERNS[1].search(coroutine_window):
        return "coroutine_scope_main"
    handler_window = _window_text(lines, index, before=0, after=4)
    if "Handler(" in line and _UNSAFE_UI_TRIGGER_PATTERNS[5].search(handler_window):
        return "handler_main_post"
    if "Handler(" in line and _UNSAFE_UI_TRIGGER_PATTERNS[6].search(handler_window):
        return "handler_main_post_runnable"
    run_on_ui_thread_window = _window_text(lines, index, before=0, after=2)
    if "runOnUiThread" in line and _UNSAFE_UI_TRIGGER_PATTERNS[3].search(run_on_ui_thread_window):
        return "run_on_ui_thread_runnable"

    for name, pattern in (
        ("global_scope_main", _UNSAFE_UI_TRIGGER_PATTERNS[0]),
        ("run_on_ui_thread", _UNSAFE_UI_TRIGGER_PATTERNS[2]),
        ("require_activity_run_on_ui_thread", _UNSAFE_UI_TRIGGER_PATTERNS[4]),
    ):
        if pattern.search(line):
            return name
    return None


def _has_worker_context(lines: Sequence[str], index: int) -> bool:
    start = max(0, index - 6)
    for candidate_index in range(start, index + 1):
        line = lines[candidate_index]
        if any(
            pattern.search(line) for pattern in _WORKER_CONTEXT_PATTERNS
        ) and _line_still_scopes_match(lines, candidate_index, index):
            return True

    scope_start = max(0, index - 40)
    for candidate_index in range(scope_start, index + 1):
        line = lines[candidate_index]
        if any(
            pattern.search(line) for pattern in _WORKER_SCOPE_PATTERNS
        ) and _line_still_scopes_match(lines, candidate_index, index):
            return True
    return False


def _has_lifecycle_guard(lines: Sequence[str], index: int) -> bool:
    window = _window_text(lines, index, before=2, after=3)
    if any(pattern.search(window) for pattern in _LIFECYCLE_SCOPE_PATTERNS):
        return True

    start = max(0, index - 2)
    end = min(len(lines), index + 4)
    relevant_lines = lines[start:end]
    for offset, line in enumerate(relevant_lines):
        stripped = line.strip()
        if re.search(
            r"if\s*\(\s*(?:!\s*(?:isAdded|isResumed)|(?:activity\?\.)?is(Finishing|Destroyed)\s*(?:==\s*true)?)\s*\)\s*return(?:@\w+)?\b",
            stripped,
        ):
            return True
        if re.search(r"if\s*\(\s*isDetached\s*\)\s*return(?:@\w+)?\b", stripped):
            return True
        if (
            stripped.startswith("if")
            and offset + 1 < len(relevant_lines)
            and re.fullmatch(r"return(?:@\w+)?", relevant_lines[offset + 1].strip())
            and (
                re.search(r"if\s*\(\s*!\s*(?:isAdded|isResumed)\b", stripped)
                or re.search(r"if\s*\(\s*isDetached\s*\)\s*$", stripped)
                or re.search(
                    r"if\s*\(\s*(?:activity\?\.)?is(Finishing|Destroyed)\s*(?:==\s*true)?\s*\)\s*$",
                    stripped,
                )
            )
        ):
            return True
    return False


def _line_still_scopes_match(lines: Sequence[str], start_index: int, end_index: int) -> bool:
    segment = "\n".join(lines[start_index : end_index + 1])
    return segment.count("{") > segment.count("}")


def _has_ui_update_nearby(lines: Sequence[str], index: int) -> bool:
    window = _window_text(lines, index, before=0, after=8)
    return any(pattern.search(window) for pattern in _UI_UPDATE_PATTERNS)


def _scrollable_compose_input_ime_gap(
    lines: Sequence[str],
) -> tuple[str, int, int] | None:
    if not any("@Composable" in line for line in lines):
        return None
    if any(any(pattern.search(line) for pattern in _COMPOSE_IME_SAFE_PATTERNS) for line in lines):
        return None
    input_lines = [
        index for index, line in enumerate(lines) if _COMPOSE_TEXT_INPUT_PATTERN.search(line)
    ]
    if not input_lines:
        return None
    interaction_present = any(
        any(pattern.search(line) for pattern in _COMPOSE_INPUT_INTERACTION_PATTERNS)
        for line in lines
    )
    if len(input_lines) < 2 and not interaction_present:
        return None
    for match_name, pattern in _COMPOSE_SCROLL_SURFACE_PATTERNS:
        for index, line in enumerate(lines):
            if not pattern.search(line):
                continue
            return (f"{match_name}_without_ime_safety", index + 1, len(input_lines))
    return None


def _iter_tiny_compose_text_sizes(lines: Sequence[str]) -> Iterable[tuple[int, str]]:
    for start_index, block_text in _iter_compose_call_blocks(lines, _COMPOSE_TEXT_PATTERN):
        match = _READABILITY_FONT_SIZE_PATTERN.search(block_text)
        if match is None:
            continue
        font_size = float(match.group("value"))
        if font_size >= _MIN_READABILITY_TEXT_SP:
            continue
        yield start_index + 1, f"{match.group('value')}.sp"


def _iter_compose_call_blocks(
    lines: Sequence[str],
    start_pattern: re.Pattern[str],
) -> Iterable[tuple[int, str]]:
    index = 0
    while index < len(lines):
        line = lines[index]
        if start_pattern.search(line) is None:
            index += 1
            continue
        start_index = index
        block_lines = [line]
        balance = line.count("(") - line.count(")")
        index += 1
        while index < len(lines) and balance > 0:
            current_line = lines[index]
            block_lines.append(current_line)
            balance += current_line.count("(") - current_line.count(")")
            index += 1
        yield start_index, "\n".join(block_lines)


def _iter_composable_default_viewmodel_parameters(
    lines: Sequence[str],
) -> Iterable[tuple[int, str, str, str]]:
    pending_annotations: list[str] = []
    pending_signature: list[tuple[int, str]] = []
    signature_balance = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if pending_signature:
            if stripped:
                pending_signature.append((index, stripped))
                signature_balance += stripped.count("(") - stripped.count(")")
            if signature_balance <= 0 and any(")" in text for _, text in pending_signature):
                match = _default_viewmodel_parameter_match(
                    pending_annotations,
                    pending_signature,
                )
                if match is not None:
                    yield match
                pending_annotations = []
                pending_signature = []
                signature_balance = 0
            continue
        if not stripped:
            pending_annotations = []
            continue
        if stripped.startswith("@"):
            pending_annotations.append(stripped)
            continue
        if _FUNCTION_SIGNATURE_PATTERN.search(stripped) is not None:
            pending_signature = [(index, stripped)]
            signature_balance = stripped.count("(") - stripped.count(")")
            if signature_balance <= 0 and ")" in stripped:
                match = _default_viewmodel_parameter_match(
                    pending_annotations,
                    pending_signature,
                )
                if match is not None:
                    yield match
                pending_annotations = []
                pending_signature = []
                signature_balance = 0
            continue
        pending_annotations = []


def _iter_composable_function_ranges(
    lines: Sequence[str],
) -> Iterable[tuple[int, str, int, int]]:
    brace_depth = 0
    pending_annotations: list[str] = []
    pending_signature: list[tuple[int, str]] = []
    pending_start_index = 0
    function_stack: list[tuple[int, str, int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if pending_signature:
            if stripped:
                pending_signature.append((index, stripped))
            if "{" in line:
                signature_text = "\n".join(text for _, text in pending_signature)
                function_name = _composable_function_name(pending_annotations, signature_text)
                body_depth = brace_depth + line.count("{") - line.count("}")
                if function_name is not None and body_depth > brace_depth:
                    function_stack.append(
                        (pending_start_index, function_name, index + 1, body_depth)
                    )
                pending_annotations = []
                pending_signature = []
        elif not stripped:
            pending_annotations = []
        elif stripped.startswith("@"):
            pending_annotations.append(stripped)
        elif _FUNCTION_SIGNATURE_PATTERN.search(stripped) is not None:
            pending_signature = [(index, stripped)]
            pending_start_index = index
            if "{" in line:
                signature_text = "\n".join(text for _, text in pending_signature)
                function_name = _composable_function_name(pending_annotations, signature_text)
                body_depth = brace_depth + line.count("{") - line.count("}")
                if function_name is not None and body_depth > brace_depth:
                    function_stack.append(
                        (pending_start_index, function_name, index + 1, body_depth)
                    )
                pending_annotations = []
                pending_signature = []
        else:
            pending_annotations = []

        brace_depth += line.count("{") - line.count("}")
        while function_stack and brace_depth < function_stack[-1][3]:
            function_start, function_name, body_start, _ = function_stack.pop()
            yield function_start, function_name, body_start, index


def _composable_function_name(annotations: Sequence[str], signature_text: str) -> str | None:
    if not annotations:
        return None
    if not any(_COMPOSABLE_ANNOTATION_PATTERN.search(line) for line in annotations):
        return None
    if any(_PREVIEW_ANNOTATION_PATTERN.search(line) for line in annotations):
        return None
    if re.search(r"^\s*private\b", signature_text):
        return None
    function_match = _FUNCTION_SIGNATURE_PATTERN.search(signature_text)
    if function_match is None:
        return None
    function_name = function_match.group("name")
    if not function_name.endswith(_UI_ENTRYPOINT_FUNCTION_SUFFIXES):
        return None
    return function_name


def _oversized_screen_composable_metrics(
    lines: Sequence[str],
) -> tuple[int, int, int, int, int]:
    code_lines = 0
    block_count = 0
    max_depth = 0
    state_count = 0
    branch_count = 0
    current_depth = 0
    for line in lines:
        open_count = line.count("{")
        close_count = line.count("}")
        current_depth += open_count
        max_depth = max(max_depth, current_depth)

        stripped = line.strip()
        if stripped and stripped not in {"{", "}"} and not stripped.startswith("@"):
            code_lines += 1
            block_count += open_count
            if _COMPOSABLE_SCREEN_STATE_PATTERN.search(stripped):
                state_count += 1
            if _COMPOSABLE_BRANCH_PATTERN.search(stripped):
                branch_count += 1

        current_depth = max(0, current_depth - close_count)
    return code_lines, block_count, max_depth, state_count, branch_count


def _is_android_secret_surface_path(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in _SOURCE_SUFFIXES or suffix in _SECRET_CONFIG_SUFFIXES


def _iter_ui_api_client_members(line: str) -> tuple[str, ...]:
    stripped = line.strip()
    if stripped.startswith("//") or stripped.startswith("import "):
        return ()
    members: list[str] = []
    for match in _UI_API_CLIENT_ACCESS_PATTERN.finditer(line):
        member = match.group("member")
        if member in _UI_DIRECT_API_CLIENT_ALLOWED_MEMBERS or not member.endswith("Api"):
            continue
        members.append(member)
    return tuple(members)


def _iter_boundary_service_locator_api_client_members(line: str) -> tuple[str, ...]:
    stripped = line.strip()
    if stripped.startswith("//") or stripped.startswith("import "):
        return ()
    members: list[str] = []
    for match in _UI_API_CLIENT_ACCESS_PATTERN.finditer(line):
        member = match.group("member")
        if member in _UI_DIRECT_API_CLIENT_ALLOWED_MEMBERS:
            continue
        members.append(member)
    return tuple(members)


def _iter_ui_transport_build_config_names(line: str) -> tuple[str, ...]:
    stripped = line.strip()
    if stripped.startswith("//") or stripped.startswith("import "):
        return ()
    names: list[str] = []
    for match in _UI_BUILD_CONFIG_ACCESS_PATTERN.finditer(line):
        name = match.group("name")
        if _looks_like_transport_build_config_name(name):
            names.append(name)
    return tuple(names)


def _looks_like_transport_build_config_name(name: str) -> bool:
    normalized = name.upper()
    if normalized in _UI_TRANSPORT_BUILD_CONFIG_EXACT_NAMES:
        return True
    tokens = tuple(part for part in normalized.split("_") if part)
    if not tokens:
        return False
    token_set = set(tokens)
    transport_markers = {"API", "BASE", "BACKEND", "GRAPHQL", "GRPC", "SERVER", "WS", "WEBSOCKET"}
    return (
        ("URL" in token_set and bool(transport_markers & token_set))
        or ("ENDPOINT" in token_set and bool(transport_markers & token_set))
        or ("HOST" in token_set and bool(transport_markers & token_set))
        or ("TENANT" in token_set and ("CODE" in token_set or "ID" in token_set))
    )


def _collect_unsafe_static_identity_fields(
    repo_root: Path,
) -> tuple[tuple[str, str, str], ...]:
    fields: list[tuple[str, str, str]] = []
    seen_keys: set[tuple[str, str]] = set()
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        relative_path = path.relative_to(repo_root).as_posix()
        if not _is_android_source_path(repo_root, relative_path):
            continue
        lines = _read_lines(repo_root, relative_path)
        sanitized_lines = _sanitize_code_lines(
            lines,
            preserve_kotlin_templates=path.suffix.lower() == ".kt",
        )
        for index in range(len(sanitized_lines)):
            field_info = _unsafe_static_identity_field(sanitized_lines, index)
            if field_info is None:
                continue
            owner_name, field_name = field_info
            key = (owner_name, field_name)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            fields.append((owner_name, field_name, relative_path))
    return tuple(fields)


def _unsafe_static_identity_field(lines: Sequence[str], index: int) -> tuple[str, str] | None:
    line = lines[index]
    kotlin_match = _KOTLIN_MUTABLE_STATIC_IDENTITY_FIELD_PATTERN.search(line)
    java_match = _JAVA_MUTABLE_STATIC_IDENTITY_FIELD_PATTERN.search(line)
    match = kotlin_match or java_match
    if match is None:
        return None
    field_name = match.group("name")
    if not _looks_like_static_identity_field_name(field_name):
        return None
    class_context = _enclosing_class_context(lines, index)
    if class_context is None:
        return None
    owner_index, owner_name = class_context
    if _looks_like_scoped_context_owner(owner_name):
        return None
    window = _window_text(
        lines,
        index,
        before=min(2, max(0, index - owner_index)),
        after=min(3, len(lines) - index - 1),
    )
    if _has_explicit_static_context_guard(window):
        return None
    if kotlin_match is not None and not _is_within_kotlin_singleton_scope(
        lines,
        index,
        owner_index,
    ):
        return None
    return owner_name, field_name


def _is_within_kotlin_singleton_scope(lines: Sequence[str], index: int, owner_index: int) -> bool:
    start = max(owner_index, index - 24)
    for candidate_index in range(index, start - 1, -1):
        if not _line_still_scopes_match(lines, candidate_index, index):
            continue
        candidate_line = lines[candidate_index]
        if _COMPANION_OBJECT_DECLARATION_PATTERN.search(candidate_line) is not None:
            return True
        if _KOTLIN_OBJECT_DECLARATION_PATTERN.search(candidate_line) is not None:
            return True
    owner_window = _window_text(
        lines,
        owner_index,
        before=0,
        after=min(4, index - owner_index),
    )
    return _KOTLIN_OBJECT_DECLARATION_PATTERN.search(owner_window) is not None


def _has_explicit_static_context_guard(window: str) -> bool:
    return any(token in window for token in _STATIC_CONTEXT_GUARD_TOKENS)


def _looks_like_static_identity_field_name(name: str) -> bool:
    token_set = set(_normalized_identifier_tokens(name))
    if not token_set:
        return False
    if "token" in token_set:
        return True
    if "tenant" in token_set and ("id" in token_set or "code" in token_set or len(token_set) == 1):
        return True
    if "branch" in token_set and ("id" in token_set or "code" in token_set or len(token_set) == 1):
        return True
    return "user" in token_set and ("id" in token_set or "code" in token_set)


def _looks_like_scoped_context_owner(name: str) -> bool:
    token_set = set(_normalized_identifier_tokens(name))
    return bool({"context", "scope", "scoped", "owner", "provider"} & token_set)


def _normalized_identifier_tokens(name: str) -> tuple[str, ...]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    normalized = normalized.replace("-", "_").lower()
    return tuple(part for part in normalized.split("_") if part)


def _iter_boundary_static_context_reads(
    line: str,
    unsafe_fields: Sequence[tuple[str, str, str]],
) -> Iterable[tuple[str, str, str]]:
    stripped = line.strip()
    if stripped.startswith("import "):
        return ()
    matches: list[tuple[str, str, str]] = []
    for owner_name, field_name, definition_path in unsafe_fields:
        access_pattern = rf"\b{re.escape(owner_name)}\s*\.\s*{re.escape(field_name)}\b"
        if re.search(access_pattern, line) is None:
            continue
        if re.search(rf"{access_pattern}\s*\(", line) is not None:
            continue
        if re.search(rf"{access_pattern}\s*(?:=(?!=)|\+=|-=|\*=|/=|%=)", line) is not None:
            continue
        matches.append((owner_name, field_name, definition_path))
    return tuple(matches)


def _looks_like_local_status_color_map(line: str, lines: Sequence[str], index: int) -> bool:
    trigger = _LOCAL_STATUS_COLOR_MAP_TRIGGER_PATTERN.search(line)
    if trigger is None:
        return False
    name = trigger.group("name").lower()
    if "status" not in name:
        return False
    block_text = _window_text(lines, index, before=0, after=8)
    return block_text.count("Color(") >= 2 and _has_semantic_status_context(lines, index)


def _has_semantic_status_context(lines: Sequence[str], index: int) -> bool:
    window = _window_text(lines, index, before=2, after=2)
    if _SEMANTIC_STATUS_TOKEN_PATTERN.search(window) is not None:
        return True
    if _SEMANTIC_STATUS_WORD_PATTERN.search(window) is not None:
        return True
    for identifier in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", window):
        if any(
            segment.lower() in _SEMANTIC_STATUS_CONTEXT_TERMS
            for segment in _split_identifier_segments(identifier)
        ):
            return True
    return False


def _split_identifier_segments(identifier: str) -> tuple[str, ...]:
    segments: list[str] = []
    for part in identifier.split("_"):
        if not part:
            continue
        segments.extend(re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|\d+", part))
    return tuple(segments)


def _secret_scan_text(relative_path: str, lines: Sequence[str], index: int) -> str:
    if Path(relative_path).suffix.lower() not in _SECRET_CONFIG_SUFFIXES:
        return lines[index]
    return _window_text(lines, index, before=3, after=2)


def _should_scan_gradle_secret_line(line: str) -> bool:
    return (
        any(token in line for token in _SECRET_FALLBACK_ENV_TOKENS)
        or _shared_match_secret_pattern(line, allow_generic_assignment=True) is not None
        or _SECRET_ASSIGNMENT_NAME_PATTERN.search(line) is not None
        or _looks_like_gradle_string_value_line(line)
    )


def _hardcoded_secret_match_name(relative_path: str, line: str, context_text: str) -> str | None:
    if Path(relative_path).suffix.lower() in _SECRET_CONFIG_SUFFIXES:
        literal_match = _extract_gradle_secret_literal(context_text, line)
        if literal_match is not None:
            name, _value = literal_match
            return f"gradle_literal:{name.lower()}"
        if any(token in line for token in _SECRET_FALLBACK_ENV_TOKENS) and (
            "?:" in line or ".orElse(" in line
        ):
            return None

    shared_match = _shared_match_secret_pattern(line, allow_generic_assignment=False)
    if shared_match is not None:
        return shared_match

    literal_assignment = _extract_literal_secret_assignment(line)
    if literal_assignment is None:
        return None
    name, _value = literal_assignment
    return f"assignment:{name.lower()}"


def _secret_fallback_match(relative_path: str, line: str, context_text: str) -> str | None:
    if Path(relative_path).suffix.lower() not in _SECRET_CONFIG_SUFFIXES:
        return None
    if not any(token in line for token in _SECRET_FALLBACK_ENV_TOKENS):
        return None

    fallback_name = _extract_gradle_config_name(context_text)
    if fallback_name is None:
        assignment = _SECRET_ASSIGNMENT_NAME_PATTERN.search(line)
        if assignment is not None:
            fallback_name = assignment.group("name")

    if not fallback_name:
        return None

    for pattern_name, pattern in _SECRET_FALLBACK_PATTERNS:
        match = pattern.search(line)
        if match is None:
            continue
        value = match.group("value").replace('\\"', '"').replace("\\'", "'").strip()
        if _shared_looks_like_placeholder(value):
            return None
        if not _looks_like_android_secret_assignment(fallback_name, value):
            return None
        return f"{pattern_name}:{fallback_name.lower()}"
    return None


def _extract_gradle_secret_literal(context_text: str, line: str) -> tuple[str, str] | None:
    name = _extract_gradle_config_name(context_text)
    if name is None:
        return None

    value_expression = line.strip().rstrip(",")
    if "${" in value_expression or any(
        token in value_expression for token in _SECRET_FALLBACK_ENV_TOKENS
    ):
        return None
    if "?: " in value_expression or ".orElse(" in value_expression:
        return None

    value = _normalize_gradle_string_literal(value_expression)
    if not value or _shared_looks_like_placeholder(value):
        return None
    if not _looks_like_android_secret_assignment(name, value):
        return None
    return name, value


def _extract_gradle_config_name(text: str) -> str | None:
    matches = tuple(_GRADLE_CONFIG_NAME_PATTERN.finditer(text))
    if not matches:
        return None
    return matches[-1].group("name")


def _looks_like_gradle_string_value_line(line: str) -> bool:
    stripped = line.strip()
    if stripped.startswith("//"):
        return False
    return stripped.count('"') >= 4 or stripped.count("'") >= 4


def _iter_viewmodel_direct_instantiations(
    lines: Sequence[str],
) -> Iterable[tuple[int, str, str]]:
    brace_depth = 0
    pending_signature: list[str] = []
    viewmodel_stack: list[tuple[str, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if viewmodel_stack and brace_depth == viewmodel_stack[-1][1]:
            dependency_type = _viewmodel_instantiation_type(lines, index)
            if dependency_type is not None:
                yield index, viewmodel_stack[-1][0], dependency_type

        if pending_signature:
            if _CLASS_DECLARATION_START_PATTERN.search(stripped) is not None:
                pending_signature = [stripped] if stripped else []
                if "{" in line:
                    viewmodel_name = _viewmodel_class_name("\n".join(pending_signature))
                    body_depth = brace_depth + line.count("{") - line.count("}")
                    if viewmodel_name is not None and body_depth > brace_depth:
                        viewmodel_stack.append((viewmodel_name, body_depth))
                    pending_signature = []
                brace_depth += line.count("{") - line.count("}")
                while viewmodel_stack and brace_depth < viewmodel_stack[-1][1]:
                    viewmodel_stack.pop()
                continue
            if stripped:
                pending_signature.append(stripped)
            if "{" in line:
                viewmodel_name = _viewmodel_class_name("\n".join(pending_signature))
                body_depth = brace_depth + line.count("{") - line.count("}")
                if viewmodel_name is not None and body_depth > brace_depth:
                    viewmodel_stack.append((viewmodel_name, body_depth))
                pending_signature = []
        elif _CLASS_DECLARATION_START_PATTERN.search(stripped) is not None:
            pending_signature = [stripped] if stripped else []
            if "{" in line:
                viewmodel_name = _viewmodel_class_name("\n".join(pending_signature))
                body_depth = brace_depth + line.count("{") - line.count("}")
                if viewmodel_name is not None and body_depth > brace_depth:
                    viewmodel_stack.append((viewmodel_name, body_depth))
                pending_signature = []

        brace_depth += line.count("{") - line.count("}")
        while viewmodel_stack and brace_depth < viewmodel_stack[-1][1]:
            viewmodel_stack.pop()


def _default_viewmodel_parameter_match(
    annotations: Sequence[str],
    signature_lines: Sequence[tuple[int, str]],
) -> tuple[int, str, str, str] | None:
    if not annotations:
        return None
    if not any(_COMPOSABLE_ANNOTATION_PATTERN.search(line) for line in annotations):
        return None
    if any(_PREVIEW_ANNOTATION_PATTERN.search(line) for line in annotations):
        return None

    signature_text = "\n".join(text for _, text in signature_lines)
    if re.search(r"^\s*private\b", signature_text):
        return None
    function_match = _FUNCTION_SIGNATURE_PATTERN.search(signature_text)
    if function_match is None:
        return None
    function_name = function_match.group("name")
    if not function_name.endswith(_UI_ENTRYPOINT_FUNCTION_SUFFIXES):
        return None

    for line_index, text in signature_lines:
        match = _DEFAULT_VIEWMODEL_PARAMETER_PATTERN.search(text)
        if match is None:
            continue
        call_name = match.group("call").split(".")[-1]
        return (
            line_index + 1,
            function_name,
            match.group("parameter"),
            f"{call_name}()",
        )

    match = _DEFAULT_VIEWMODEL_PARAMETER_PATTERN.search(signature_text)
    if match is None:
        return None
    call_name = match.group("call").split(".")[-1]
    return (
        signature_lines[0][0] + 1,
        function_name,
        match.group("parameter"),
        f"{call_name}()",
    )


def _viewmodel_class_name(signature_text: str) -> str | None:
    match = _CLASS_DECLARATION_START_PATTERN.search(signature_text)
    if match is None:
        return None
    name = match.group("name")
    if name.endswith("ViewModel"):
        return name
    if re.search(
        r"\bextends\s+(?:[A-Za-z_][A-Za-z0-9_.<>]*\.)?(?:AndroidViewModel|ViewModel)\b",
        signature_text,
    ):
        return name
    if re.search(
        r":\s*[A-Za-z0-9_<>,.()? \n]*\b(?:AndroidViewModel|ViewModel)\b",
        signature_text,
    ):
        return name
    return None


def _viewmodel_instantiation_type(lines: Sequence[str], index: int) -> str | None:
    stripped = lines[index].strip()
    if not stripped or stripped.startswith("@"):
        return None
    property_window = _window_text(
        lines,
        index,
        before=0,
        after=min(3, len(lines) - index - 1),
    )
    for pattern in (
        _VIEWMODEL_FIELD_INSTANTIATION_PATTERN,
        _VIEWMODEL_LAZY_INSTANTIATION_PATTERN,
        _VIEWMODEL_JAVA_FIELD_INSTANTIATION_PATTERN,
    ):
        match = pattern.match(property_window)
        if match is not None:
            return match.group("type")
    return None


def _boundary_direct_dependency_type(lines: Sequence[str], index: int) -> str | None:
    property_window = _window_text(
        lines,
        index,
        before=0,
        after=min(3, len(lines) - index - 1),
    )
    for pattern in (
        _BOUNDARY_DIRECT_DEPENDENCY_INSTANTIATION_PATTERN,
        _BOUNDARY_DIRECT_LAZY_DEPENDENCY_INSTANTIATION_PATTERN,
        _BOUNDARY_DIRECT_JAVA_DEPENDENCY_INSTANTIATION_PATTERN,
    ):
        match = pattern.search(property_window)
        if match is not None:
            return match.group("type")
    return None


def _iter_ui_detekt_suppressions(lines: Sequence[str]) -> Iterable[tuple[int, int, tuple[str, ...]]]:
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if stripped.startswith("//") or "Suppress" not in line:
            index += 1
            continue
        if (
            "@Suppress" not in line
            and "@file:Suppress" not in line
            and "@SuppressWarnings" not in line
        ):
            index += 1
            continue

        end_index = index
        annotation_lines = [line]
        balance = line.count("(") - line.count(")")
        while balance > 0 and end_index + 1 < len(lines) and end_index - index < 7:
            end_index += 1
            annotation_lines.append(lines[end_index])
            balance += lines[end_index].count("(") - lines[end_index].count(")")

        suppressed_rules: list[str] = []
        for match in _DETEKT_SUPPRESSION_NAME_PATTERN.finditer("\n".join(annotation_lines)):
            rule_name = match.group("name").split(".")[-1]
            if rule_name in _UI_DETEKT_SUPPRESSIONS and rule_name not in suppressed_rules:
                suppressed_rules.append(rule_name)
        if suppressed_rules and suppressed_rules != ["FunctionNaming"]:
            yield index + 1, end_index + 1, tuple(suppressed_rules)
        index = end_index + 1


def _changed_line_numbers_for_file(
    context: AdapterContext,
    relative_path: str,
    total_lines: int,
) -> set[int] | None:
    if context.mode is not ExecutionMode.DIFF:
        return None
    if not (context.repo_root / ".git").exists():
        return None

    untracked_output = _run_git_for_changed_lines(
        context.repo_root,
        ["ls-files", "--others", "--exclude-standard", "--", relative_path],
    )
    if untracked_output is None:
        return None
    if untracked_output.strip():
        return set(range(1, total_lines + 1))

    diff_output = _run_git_for_changed_lines(
        context.repo_root,
        ["diff", "--unified=0", "--", relative_path],
    )
    if diff_output is None:
        return None
    changed_lines: set[int] = set()
    for line in diff_output.splitlines():
        if not line.startswith("@@"):
            continue
        match = re.search(r"\+(\d+)(?:,(\d+))?", line)
        if match is None:
            continue
        start_line = int(match.group(1))
        line_count = int(match.group(2) or "1")
        changed_lines.update(range(start_line, start_line + line_count))
    return changed_lines


def _run_git_for_changed_lines(repo_root: Path, args: Sequence[str]) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def _iter_viewmodel_class_ranges(
    lines: Sequence[str],
) -> Iterable[tuple[int, str, int, int]]:
    brace_depth = 0
    pending_signature: list[str] = []
    pending_start_index = 0
    viewmodel_stack: list[tuple[str, int, int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if pending_signature:
            if _CLASS_DECLARATION_START_PATTERN.search(stripped) is not None:
                pending_signature = [stripped] if stripped else []
                pending_start_index = index
                if "{" in line:
                    signature_text = "\n".join(pending_signature)
                    body_depth = brace_depth + line.count("{") - line.count("}")
                    viewmodel_name = _viewmodel_class_name(signature_text)
                    if viewmodel_name is not None and body_depth > brace_depth:
                        viewmodel_stack.append(
                            (viewmodel_name, pending_start_index, index + 1, body_depth)
                        )
                    pending_signature = []
                brace_depth += line.count("{") - line.count("}")
                while viewmodel_stack and brace_depth < viewmodel_stack[-1][3]:
                    viewmodel_name, class_start, body_start, _ = viewmodel_stack.pop()
                    yield class_start, viewmodel_name, body_start, index
                continue
            if stripped:
                pending_signature.append(stripped)
            if "{" in line:
                signature_text = "\n".join(pending_signature)
                body_depth = brace_depth + line.count("{") - line.count("}")
                viewmodel_name = _viewmodel_class_name(signature_text)
                if viewmodel_name is not None and body_depth > brace_depth:
                    viewmodel_stack.append(
                        (viewmodel_name, pending_start_index, index + 1, body_depth)
                    )
                pending_signature = []
        elif _CLASS_DECLARATION_START_PATTERN.search(stripped) is not None:
            pending_signature = [stripped] if stripped else []
            pending_start_index = index
            if "{" in line:
                signature_text = "\n".join(pending_signature)
                body_depth = brace_depth + line.count("{") - line.count("}")
                viewmodel_name = _viewmodel_class_name(signature_text)
                if viewmodel_name is not None and body_depth > brace_depth:
                    viewmodel_stack.append(
                        (viewmodel_name, pending_start_index, index + 1, body_depth)
                    )
                pending_signature = []

        brace_depth += line.count("{") - line.count("}")
        while viewmodel_stack and brace_depth < viewmodel_stack[-1][3]:
            viewmodel_name, class_start, body_start, _ = viewmodel_stack.pop()
            yield class_start, viewmodel_name, body_start, index


def _is_substantial_viewmodel_body(lines: Sequence[str]) -> bool:
    code_lines: list[str] = []
    member_count = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"}:
            continue
        if stripped.startswith("@"):
            continue
        code_lines.append(stripped)
        if _VIEWMODEL_MEMBER_PATTERN.search(stripped):
            member_count += 1
    return (
        member_count >= _SUBSTANTIAL_VIEWMODEL_MIN_MEMBER_COUNT
        or len(code_lines) >= _SUBSTANTIAL_VIEWMODEL_MIN_CODE_LINES
    )


def _iter_boundary_callback_class_ranges(
    lines: Sequence[str],
) -> Iterable[tuple[int, str, tuple[str, ...], int, int]]:
    brace_depth = 0
    pending_signature: list[str] = []
    pending_start_index = 0
    class_stack: list[tuple[str, tuple[str, ...], int, int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if pending_signature:
            if stripped:
                pending_signature.append(stripped)
            if "{" in line:
                signature_text = "\n".join(pending_signature)
                body_depth = brace_depth + line.count("{") - line.count("}")
                class_info = _boundary_callback_class_info(signature_text)
                if class_info is not None and body_depth > brace_depth:
                    class_name, callback_names = class_info
                    class_stack.append(
                        (class_name, callback_names, pending_start_index, index + 1, body_depth)
                    )
                pending_signature = []
        elif _CLASS_DECLARATION_START_PATTERN.search(stripped) is not None:
            pending_signature = [stripped] if stripped else []
            pending_start_index = index
            if "{" in line:
                signature_text = "\n".join(pending_signature)
                body_depth = brace_depth + line.count("{") - line.count("}")
                class_info = _boundary_callback_class_info(signature_text)
                if class_info is not None and body_depth > brace_depth:
                    class_name, callback_names = class_info
                    class_stack.append(
                        (class_name, callback_names, pending_start_index, index + 1, body_depth)
                    )
                pending_signature = []

        brace_depth += line.count("{") - line.count("}")
        while class_stack and brace_depth < class_stack[-1][4]:
            class_name, callback_names, class_start, body_start, _ = class_stack.pop()
            yield class_start, class_name, callback_names, body_start, index


def _boundary_callback_class_info(signature_text: str) -> tuple[str, tuple[str, ...]] | None:
    match = _CLASS_DECLARATION_START_PATTERN.search(signature_text)
    if match is None:
        return None
    class_name = match.group("name")
    for type_name, callback_names in _BOUNDARY_CALLBACK_TEST_CLASS_CALLBACKS:
        if re.search(rf"\b{re.escape(type_name)}\b", signature_text):
            return class_name, callback_names
    return None


def _iter_named_function_ranges(
    lines: Sequence[str],
    *,
    required_names: Sequence[str],
    require_override: bool,
) -> Iterable[tuple[int, str, int, int]]:
    brace_depth = 0
    pending_signature: list[str] = []
    pending_start_index = 0
    function_stack: list[tuple[int, str, int, int]] = []
    required_name_set = set(required_names)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if pending_signature:
            if stripped:
                pending_signature.append(stripped)
            if "{" in line:
                signature_text = "\n".join(pending_signature)
                function_name = _named_function_signature_name(
                    signature_text,
                    required_names=required_name_set,
                    require_override=require_override,
                )
                body_depth = brace_depth + line.count("{") - line.count("}")
                if function_name is not None and body_depth > brace_depth:
                    function_stack.append(
                        (pending_start_index, function_name, index + 1, body_depth)
                    )
                pending_signature = []
        elif _FUNCTION_SIGNATURE_PATTERN.search(stripped) is not None:
            pending_signature = [stripped] if stripped else []
            pending_start_index = index
            if "{" in line:
                signature_text = "\n".join(pending_signature)
                function_name = _named_function_signature_name(
                    signature_text,
                    required_names=required_name_set,
                    require_override=require_override,
                )
                body_depth = brace_depth + line.count("{") - line.count("}")
                if function_name is not None and body_depth > brace_depth:
                    function_stack.append(
                        (pending_start_index, function_name, index + 1, body_depth)
                    )
                pending_signature = []

        brace_depth += line.count("{") - line.count("}")
        while function_stack and brace_depth < function_stack[-1][3]:
            function_start, function_name, body_start, _ = function_stack.pop()
            yield function_start, function_name, body_start, index


def _named_function_signature_name(
    signature_text: str,
    *,
    required_names: set[str],
    require_override: bool,
) -> str | None:
    if require_override and "override" not in signature_text:
        return None
    function_match = _FUNCTION_SIGNATURE_PATTERN.search(signature_text)
    if function_match is None:
        return None
    function_name = function_match.group("name")
    if function_name not in required_names:
        return None
    return function_name


def _is_meaningful_boundary_callback_body(lines: Sequence[str]) -> bool:
    code_lines = 0
    complexity_lines = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped in {"{", "}"} or stripped.startswith("@"):
            continue
        code_lines += 1
        if _COMPOSABLE_BRANCH_PATTERN.search(stripped):
            complexity_lines += 1
            continue
        if re.search(r"^\s*(?:try|catch|for|while)\b", stripped):
            complexity_lines += 1
    return code_lines >= _BOUNDARY_CALLBACK_MIN_CODE_LINES or (
        code_lines >= _BOUNDARY_CALLBACK_MIN_CODE_LINES_WITH_COMPLEXITY and complexity_lines > 0
    )


def _preferred_viewmodel_test_path(relative_path: str, viewmodel_name: str) -> str | None:
    return _preferred_android_test_path(relative_path, f"{viewmodel_name}Test")


def _viewmodel_test_candidate_paths(relative_path: str, viewmodel_name: str) -> tuple[str, ...]:
    return _android_test_candidate_paths(relative_path, f"{viewmodel_name}Test")


def _preferred_android_test_path(relative_path: str, test_stem: str) -> str | None:
    candidates = _android_test_candidate_paths(relative_path, test_stem)
    return candidates[0] if candidates else None


def _android_test_candidate_paths(relative_path: str, test_stem: str) -> tuple[str, ...]:
    normalized = relative_path.replace("\\", "/")
    path = Path(normalized)
    parts = path.parts
    if "src" not in parts:
        return ()
    src_index = parts.index("src")
    if len(parts) <= src_index + 3:
        return ()

    package_parts = parts[src_index + 3 : -1]
    preferred_language_dirs = (
        ("kotlin", "java") if path.suffix.lower() == ".kt" else ("java", "kotlin")
    )
    candidates: list[str] = []
    for source_set in ("test", "androidTest"):
        for language_dir in preferred_language_dirs:
            extension = ".kt" if language_dir == "kotlin" else ".java"
            candidate_parts = [
                *parts[:src_index],
                "src",
                source_set,
                language_dir,
                *package_parts,
                f"{test_stem}{extension}",
            ]
            candidates.append(Path(*candidate_parts).as_posix())
    return tuple(candidates)


def _find_nearby_viewmodel_test(
    repo_root: Path, relative_path: str, viewmodel_name: str
) -> str | None:
    return _find_nearby_android_test(repo_root, relative_path, f"{viewmodel_name}Test")


def _find_nearby_android_test(repo_root: Path, relative_path: str, test_stem: str) -> str | None:
    for candidate in _android_test_candidate_paths(relative_path, test_stem):
        if (repo_root / candidate).exists():
            return candidate

    normalized = relative_path.replace("\\", "/")
    path = Path(normalized)
    parts = path.parts
    if "src" not in parts:
        return None
    src_index = parts.index("src")
    module_root = repo_root.joinpath(*parts[:src_index]) if src_index > 0 else repo_root
    preferred_language_dirs = (
        ("kotlin", "java") if path.suffix.lower() == ".kt" else ("java", "kotlin")
    )
    for source_set in ("test", "androidTest"):
        for language_dir in preferred_language_dirs:
            search_root = module_root / "src" / source_set / language_dir
            if not search_root.exists():
                continue
            for extension in (".kt", ".java"):
                matches = sorted(search_root.rglob(f"{test_stem}{extension}"))
                if matches:
                    return matches[0].relative_to(repo_root).as_posix()
    return None


def _extract_literal_secret_assignment(line: str) -> tuple[str, str] | None:
    match = _SECRET_LITERAL_ASSIGNMENT_PATTERN.search(line)
    if match is None:
        return None

    name = match.group("name")
    value = (match.group("double_value") or match.group("single_value") or "").strip()
    if not value or _shared_looks_like_placeholder(value):
        return None
    if not _looks_like_android_secret_assignment(name, value):
        return None
    return name, value


def _looks_like_android_secret_assignment(name: str, value: str) -> bool:
    normalized_name = re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", name)
    normalized_name = normalized_name.replace("-", "_").replace(".", "_").lower()
    return _shared_looks_like_secret_assignment(normalized_name, value)


def _normalize_gradle_string_literal(value_expression: str) -> str:
    value = value_expression.strip().rstrip(",")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    value = value.replace('\\"', '"').replace("\\'", "'").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.strip()


def _iter_gson_nonnull_fields(
    lines: Sequence[str],
) -> Iterable[tuple[str, str, int]]:
    class_name: str | None = None
    constructor_depth = 0
    for index, line in enumerate(lines):
        class_match = _DTO_CLASS_DECLARATION_PATTERN.search(line)
        if class_match is not None:
            class_name = class_match.group("name")
            constructor_depth = line.count("(") - line.count(")")
            continue
        if class_name is None:
            continue
        constructor_depth += line.count("(") - line.count(")")
        field_match = _GSON_DATA_CLASS_FIELD_PATTERN.search(line)
        if field_match is not None:
            field_type = field_match.group("type").strip()
            has_default = field_match.group("default") is not None
            if "?" not in field_type and not has_default:
                yield class_name, field_match.group("name"), index + 1
        if constructor_depth <= 0:
            class_name = None


DEFAULT_ADAPTERS = (AndroidAdapter(),)
