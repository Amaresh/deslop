"""Android / Kotlin AST detector tests.

Go/Python/TS/Java tests stay in their own files and must stay green.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

DETECTORS = Path(__file__).resolve().parents[1] / "checkers"
sys.path.insert(0, str(DETECTORS))

from no_runblocking_hotpath import (  # noqa: E402
    detect as detect_rb,
    RULE_ID as RB_ID,
)
from no_unscoped_boundary_coroutine import (  # noqa: E402
    detect as detect_gs,
    RULE_ID as GS_ID,
)
from no_hardcoded_secret_literals import (  # noqa: E402
    detect as detect_sec,
    RULE_ID as SEC_ID,
)
from ktast_client import load_facts  # noqa: E402


# ---------- facts extractor ----------

def test_facts_home_screen_is_also_a_call():
    src = """
@Composable
fun HomeScreen() {
    Text("hi")
}
"""
    facts = load_facts(src)
    names = [c["name"] for c in facts["calls"]]
    assert "HomeScreen" in names
    fn = facts["functions"][0]
    assert fn["name"] == "HomeScreen"
    assert fn["is_composable"] is True
    assert fn["is_preview"] is False


def test_facts_preview_and_runblocking():
    src = """
@Preview
@Composable
fun HomeScreenPreview() {
    runBlocking { HomeScreen() }
}
"""
    facts = load_facts(src)
    fn = facts["functions"][0]
    assert fn["is_preview"] is True
    assert any(c["name"] == "runBlocking" for c in facts["calls"])


def test_facts_skips_tests():
    assert load_facts("fun f() {}", filename="FooTest.kt") is None
    assert load_facts("fun f() {}", filename="src/test/java/Foo.kt") is None


# ---------- android.reliability.no-runblocking-hotpath ----------

BAD_RB = [
    """
@Composable
fun InboxPane() {
    val mail = runBlocking { mailbox.fetch() }
    Text(mail.subject)
}
""",
    """
class DeskActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runBlocking { session.warm() }
    }
}
""",
    """
class InboxViewModel : ViewModel() {
    fun refresh() {
        runBlocking { mailbox.sync() }
    }
}
""",
]


NEAR_MISS_RB = [
    """
@Preview
@Composable
fun InboxPanePreview() {
    runBlocking { InboxPane() }
}
""",
    """
class InboxViewModel : ViewModel() {
    fun refresh() {
        viewModelScope.launch { mailbox.sync() }
    }
}
""",
    """
class TokenInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val token = runBlocking { store.token() }
        return chain.proceed(chain.request())
    }
}
""",
    """
class TokenAuthenticator : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        val token = runBlocking { store.rotate() }
        return response.request.newBuilder().header("Authorization", token).build()
    }
}
""",
    """
fun blockingFetch() = runBlocking { mailbox.fetch() }

@Composable
fun InboxPane() {
    Text("inbox")
}
""",
    """
class HeapRepository {
    fun insert(row: Row): Long {
        return runBlocking { db.write(row) }
    }
}
""",
]


@pytest.mark.parametrize("src", BAD_RB, ids=["composable", "activity", "viewmodel"])
def test_runblocking_bad_is_flagged(src):
    findings = detect_rb(src)
    assert len(findings) >= 1
    assert findings[0].rule_id == RB_ID


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_RB,
    ids=["preview", "viewmodelscope", "interceptor", "authenticator",
         "expr-helper", "repository"],
)
def test_runblocking_near_misses_pass(src):
    assert detect_rb(src) == []


def test_runblocking_fq_name_in_fragment():
    src = """
class InboxFragment : Fragment() {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        kotlinx.coroutines.runBlocking { mailbox.sync() }
    }
}
"""
    assert len(detect_rb(src)) >= 1


def test_runblocking_init_in_activity():
    src = """
class SplashActivity : AppCompatActivity() {
    init {
        runBlocking { preload() }
    }
}
"""
    assert len(detect_rb(src)) >= 1


def test_runblocking_custom_view():
    src = """
class MeterView(context: Context) : View(context) {
    fun bind() {
        runBlocking { sensor.read() }
    }
}
"""
    assert len(detect_rb(src)) >= 1


def test_runblocking_skips_tests():
    src = """
@Composable
fun InboxPane() {
    runBlocking { mailbox.fetch() }
}
"""
    assert detect_rb(src, filename="InboxPaneTest.kt") == []
    assert detect_rb(src, filename="src/test/kotlin/Inbox.kt") == []


def test_runblocking_does_not_flag_home_screen_self_call():
    src = """
@Composable
fun HomeScreen() {
    Text("hi")
}
"""
    assert detect_rb(src) == []


# ---------- android.reliability.no-unscoped-boundary-coroutine ----------

BAD_GS = [
    """
class SyncReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        GlobalScope.launch { uploader.flush() }
    }
}
""",
    """
class PulseService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        GlobalScope.async { pulse.send() }
        return START_STICKY
    }
}
""",
    """
class CacheJanitor {
    fun sweep() {
        GlobalScope.launch(Dispatchers.IO) { disk.gc() }
    }
}
""",
]


NEAR_MISS_GS = [
    """
class InboxViewModel : ViewModel() {
    fun refresh() {
        viewModelScope.launch { mailbox.sync() }
    }
}
""",
    """
class InboxFragment : Fragment() {
    override fun onStart() {
        lifecycleScope.launch { mailbox.sync() }
    }
}
""",
    """
@Composable
fun InboxPane() {
    val scope = rememberCoroutineScope()
    Button(onClick = { scope.launch { mailbox.sync() } }) { Text("sync") }
}
""",
    """
class SyncReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        scope.launch {
            uploader.flush()
            pending.finish()
        }
    }
}
""",
]


@pytest.mark.parametrize("src", BAD_GS, ids=["receiver", "service-async", "paren-io"])
def test_globalscope_bad_is_flagged(src):
    findings = detect_gs(src)
    assert len(findings) >= 1
    assert findings[0].rule_id == GS_ID


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_GS,
    ids=["viewmodelscope", "lifecyclescope", "remember-scope", "goasync"],
)
def test_globalscope_near_misses_pass(src):
    assert detect_gs(src) == []


def test_globalscope_fq_name():
    src = """
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        kotlinx.coroutines.GlobalScope.launch { ping() }
    }
}
"""
    assert len(detect_gs(src)) >= 1


def test_globalscope_skips_tests():
    src = """
fun f() {
    GlobalScope.launch { ping() }
}
"""
    assert detect_gs(src, filename="BootReceiverTest.kt") == []


# ---------- android.security.no-hardcoded-secret-literals ----------

BAD_SEC = [
    '''
object StripeKeys {
    const val LIVE = "sk_live_fixture-key-for-detector-ci"
}
''',
    '''
class MapsConfig {
    val apiKey = "AIzaSyDabcdefghijklmnopqrstuvwx"
}
''',
    '''
class CiUploader {
    private val accessToken = "ghr_not_prefix_but_sixteen"
}
''',
]


NEAR_MISS_SEC = [
    '''
class MapsConfig {
    val apiKey = "YOUR_API_KEY_HERE_PLEASE"
}
''',
    '''
class MapsConfig {
    val apiKey = "CHANGE_ME_ADD_A_REAL_KEY"
}
''',
    '''
class LoginPane {
    val passwordHint = "Use at least sixteen chars!"
}
''',
    '''
class Logger {
    fun bind() {
        Timber.tag("AuthSecret")
        Timber.d("login")
    }
}
''',
    '''
class DemoKeys {
    val apiKey = "short"
    val secret = "dummy-xxx-example-key-16+"
}
''',
    '''
class ProdKeys {
    val apiKey = BuildConfig.MAPS_API_KEY
}
''',
]


@pytest.mark.parametrize("src", BAD_SEC, ids=["stripe", "aiza", "ident-16"])
def test_secret_bad_is_flagged(src):
    findings = detect_sec(src)
    assert len(findings) >= 1
    assert findings[0].rule_id == SEC_ID


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_SEC,
    ids=["your_", "change-me", "ui-copy", "timber-tag", "short-dummy", "buildconfig"],
)
def test_secret_near_misses_pass(src):
    assert detect_sec(src) == []


def test_secret_pem_begin():
    src = '''
object HostKey {
    const val PEM = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAK"
}
'''
    assert len(detect_sec(src)) >= 1


def test_secret_slack_and_aws():
    src = '''
object Tokens {
    const val SLACK = "xoxb-123456789012-123456789012-ab"
    const val AWS = "AKIAIOSFODNN7EXAMPLE"
}
'''
    findings = detect_sec(src)
    lines = {f.line for f in findings}
    slack_line = next(i + 1 for i, ln in enumerate(src.splitlines()) if "xoxb-" in ln)
    aws_line = next(i + 1 for i, ln in enumerate(src.splitlines()) if "AKIA" in ln)
    assert slack_line in lines
    assert aws_line not in lines


def test_secret_sk_test():
    src = 'const val STRIPE = "sk_test_fixture-key-for-detector-ci"\n'
    assert len(detect_sec(src)) >= 1


def test_secret_github_pat():
    src = 'const val GITHUB = "github_pat_11AABCDEFG0123456789_zz"\n'
    assert len(detect_sec(src)) >= 1


def test_secret_skips_tests():
    src = 'const val LIVE = "sk_live_fixture-key-for-detector-ci"\n'
    assert detect_sec(src, filename="KeysTest.kt") == []
