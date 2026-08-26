import sys
from pathlib import Path

import pytest

DETECTORS = Path(__file__).resolve().parents[1] / "checkers"
sys.path.insert(0, str(DETECTORS))

from no_plain_string_secret_comparison import detect as detect_secret  # noqa: E402
from no_websocket_upgrader_checkorigin_allow_all import detect as detect_ws  # noqa: E402
from no_nullable_column_scanned_as_plain_value import detect as detect_null  # noqa: E402
from no_handler_rooted_background_context import detect as detect_bg  # noqa: E402
from no_handler_direct_outbound_http import detect as detect_http  # noqa: E402
from no_handler_direct_sql_execution import detect as detect_sql  # noqa: E402
from no_handler_detached_goroutine import detect as detect_go  # noqa: E402
from no_go_dynamic_sql_execution import detect as detect_dynsql  # noqa: E402
from goast_client import quoted_strings  # noqa: E402


def test_quoted_strings_trailing_backslash_does_not_raise():
    quoted_strings('"abc\\')
    quoted_strings("\\")


# ---------- go.security.no-plain-string-secret-comparation ----------

BAD_SECRET = '''func (h *Handler) checkAgentSecret(r *http.Request) bool {
	secret := h.agentSecret
	return r.Header.Get("X-Agent-Secret") == secret
}
'''
GOOD_SECRET = '''func (h *Handler) checkAgentSecret(r *http.Request) bool {
	secret := h.agentSecret
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Agent-Secret")), []byte(secret)) == 1
}
'''
NEAR_MISS_SECRET = [
    # 1: constant-time comparison (the fix)
    GOOD_SECRET,
    # 2: non-secret header comparison
    'if w.Header().Get("Content-Type") != "application/json" {\n\tt.Fatal("bad type")\n}\n',
    # 3: presence check against empty string, and role allowlist compare
    'if r.Header.Get("X-Agent-Token") == "" {\n\thttp.Error(w, "missing", 401)\n}\nif req.Role == "admin" {\n\tallow()\n}\n',
    # 4: != empty presence check (review C6)
    'if token != "" {\n\tnext()\n}\n',
    # 5: identifier that merely contains "secret"
    'if SECRETISH == other {\n\tnext()\n}\n',
    # 6: string literal containing "token", not a secret compare
    'if name == "token" {\n\tlabel()\n}\n',
    # 7: multi-comparison: first == is non-secret, second is also non-secret
    'if foo == bar && req.Role == "admin" {\n\tallow()\n}\n',
]


def test_secret_presence_neq_empty_not_flagged():
    assert detect_secret('if token != "" {\n}\n') == []


def test_secretish_identifier_not_flagged():
    assert detect_secret("if SECRETISH == other {\n}\n") == []


def test_string_literal_token_not_flagged():
    assert detect_secret('if name == "token" {\n}\n') == []


def test_cache_auth_tag_does_not_taint_err_nil():
    src = '''func store(key string) error {
	keyBuf = append(keyBuf, "|auth="...)
	baseKey := string(keyBuf)
	key := baseKey
	if err := manager.set(reqCtx, key, e, storageExpiration); err != nil {
		return err
	}
	if entry.key != entryKey {
		return nil
	}
	return nil
}
'''
    assert detect_secret(src) == []


def test_header_authorization_still_flagged():
    src = '''func check(r *http.Request, secret string) bool {
	got := r.Header.Get("Authorization")
	return got == secret
}
'''
    assert len(detect_secret(src)) >= 1


def test_auth_callout_error_string_empty_check_not_flagged():
    src = '''func wait(respCh <-chan string) {
	errStr := fmt.Sprintf("Error sending authorization request: %v", err)
	if authorized = errStr == _EMPTY_; !authorized {
		return
	}
}
'''
    assert detect_secret(src) == []


def test_nested_func_literal_does_not_flood_taint_issuer_compare():
    src = '''func processClientOrLeafCallout() {
	errStr := fmt.Sprintf("Error sending authorization request: %v", err)
	getIssuerAccount := func(arc *jwt.UserClaims, account string) (string, error) {
		jwtIssuer := arc.Issuer
		if jwtIssuer != issuer {
			return jwtIssuer, nil
		}
		return issuer, nil
	}
	_ = getIssuerAccount
	_ = errStr
}
'''
    assert detect_secret(src) == []


def test_test_file_patterns_skipped():
    src = ('func check(r *http.Request) bool {\n'
           '    return r.Header.Get("X-Agent-Secret") == secret\n'
           '}\n')
    assert detect_secret(src, filename="handler_test.go") == []
    assert detect_secret(src, filename="test_handler.go") == []
    assert len(detect_secret(src, filename="handler.go")) >= 1


@pytest.mark.parametrize("src", [BAD_SECRET], ids=["bad"])
def test_secret_bad_is_flagged(src):
    assert len(detect_secret(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_SECRET,
    ids=["good", "nm2", "nm3", "neq-empty", "secretish-id", "literal-token", "multi-cmp"],
)
def test_secret_good_and_near_misses_pass(src):
    assert detect_secret(src) == []


# ---------- go.security.no-websocket-upgrader-checkorigin-allow-all ----------

BAD_WS = 'var wsUpgrader = websocket.Upgrader{\n\tReadBufferSize:  1024,\n\tCheckOrigin:     func(r *http.Request) bool { return true },\n}\n'
GOOD_WS = '''var wsUpgrader = websocket.Upgrader{
	ReadBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser client
		}
		return origin == "https://"+r.Host
	},
}
'''
NEAR_MISS_WS = [
    # 1: validated origin (the good pair)
    GOOD_WS,
    # 2: upgrader without CheckOrigin at all
    'var wsUpgrader = websocket.Upgrader{ReadBufferSize: 1024}\n',
    # 3: multiline body that computes but has an early true for empty origin
    'var u = websocket.Upgrader{\n\tCheckOrigin: func(r *http.Request) bool {\n\t\torigin := r.Header.Get("Origin")\n\t\treturn origin == allowed\n\t},\n}\n',
]


def test_ws_bad_is_flagged():
    findings = detect_ws(BAD_WS)
    assert len(findings) == 1
    assert findings[0].line == 3


@pytest.mark.parametrize("src", NEAR_MISS_WS)
def test_ws_good_and_near_misses_pass(src):
    assert detect_ws(src) == []


# ---------- go.reliability.no-nullable-column-scanned-as-plain-value ----------

BAD_NULL = '''func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT m.id, m.sender_id, r2.name
		 FROM chat_messages m
		 LEFT JOIN riders r2 ON m.sender_id = r2.id`)
	var id, bikeID2 string
	var senderName string
	for rows.Next() {
		rows.Scan(&id, &bikeID2, &senderName)
	}
}
'''
GOOD_NULL = '''func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT m.id, m.sender_id, r2.name
		 FROM chat_messages m
		 LEFT JOIN riders r2 ON m.sender_id = r2.id`)
	var id string
	var bikeID2 sql.NullString
	for rows.Next() {
		rows.Scan(&id, &bikeID2, &senderName)
	}
}
'''
NEAR_MISS_NULL = [
    # 1: null-aware scan after a LEFT JOIN (the good pair)
    GOOD_NULL,
    # 2: plain scalar scan but simple single-table query — nothing nullable in play
    '''func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	row := h.db.QueryRowContext(r.Context(), `SELECT id FROM rides WHERE rider_id = $1`, riderID)
	var id string
	row.Scan(&id)
}
''',
    # 3: grouped plain decls present but never fed to Scan; Scan uses Null types only
    '''func (h *Handler) other(w http.ResponseWriter, r *http.Request) {
	_ = h.db.QueryRowContext(r.Context(), `SELECT a FROM x LEFT JOIN y ON y.x = x.id`)
	var a, b string
	var name sql.NullString
	rows.Scan(&name)
	_ = a + b
}
''',
]


@pytest.mark.parametrize("src", [BAD_NULL])
def test_null_bad_is_flagged(src):
    findings = detect_null(src)
    assert len(findings) == 1
    # ordinal mapping: senderName <- r2.name (nullable LEFT JOIN side);
    # bikeID2 <- m.sender_id (base table, NOT nullable) must not be named
    assert "senderName" in findings[0].message
    assert "bikeID2" not in findings[0].message


@pytest.mark.parametrize("src", NEAR_MISS_NULL)
def test_null_good_and_near_misses_pass(src):
    assert detect_null(src) == []


# ---------- go.architecture.no-handler-rooted-background-context ----------

BAD_BG = '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go work(context.Background())
}
'''

NEAR_MISS_BG = [
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go work(r.Context())
}
''',
    '''func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	_ = ctx
	_ = stop
}
''',
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	exitProcess(context.Background(), log)
}
''',
]


def test_bg_bad_is_flagged():
    assert len(detect_bg(BAD_BG)) >= 1


@pytest.mark.parametrize("src", NEAR_MISS_BG, ids=["r-context", "main-signal", "exit-process"])
def test_bg_good_and_near_misses_pass(src):
    assert detect_bg(src) == []


# ---------- go.architecture.no-handler-direct-outbound-http ----------

BAD_HTTP = '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("https://upstream.example")
	_ = resp
	_ = err
}
'''

NEAR_MISS_HTTP = [
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://upstream.example", nil)
	resp, err := http.DefaultClient.Do(req)
	_ = resp
	_ = err
}
''',
    '''func fetch() {
	http.Get("https://upstream.example")
}
''',
]


def test_http_bad_is_flagged():
    assert len(detect_http(BAD_HTTP)) >= 1


@pytest.mark.parametrize("src", NEAR_MISS_HTTP, ids=["with-context", "helper-not-handler"])
def test_http_good_and_near_misses_pass(src):
    assert detect_http(src) == []


# ---------- go.architecture.no-handler-direct-sql-execution ----------

BAD_SQL = '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT id FROM rides WHERE rider_id = $1`, riderID)
	_ = rows
	_ = err
}
'''

NEAR_MISS_SQL = [
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	item, err := h.repo.Query(r.Context(), riderID)
	_ = item
	_ = err
}
''',
    '''func (s *Store) List(ctx context.Context) error {
	_, err := s.db.QueryContext(ctx, `SELECT id FROM rides`)
	return err
}
''',
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	_ = q
	w.WriteHeader(http.StatusNoContent)
}
''',
]


def test_sql_bad_is_flagged():
    assert len(detect_sql(BAD_SQL)) >= 1


def test_sql_begin_in_handler_is_flagged():
    src = '''func catalog(w http.ResponseWriter, r *http.Request) {
	tx, err := h.db.Begin()
	_ = tx
	_ = err
}
'''
    assert len(detect_sql(src)) >= 1


def test_sql_test_file_skipped():
    assert detect_sql(BAD_SQL, filename="handler_test.go") == []


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_SQL,
    ids=["repo-query", "store-not-handler", "url-query"],
)
def test_sql_good_and_near_misses_pass(src):
    assert detect_sql(src) == []


def test_sql_execcontext_in_handler_flagged():
    src = '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.db.ExecContext(r.Context(), `INSERT INTO rides (id) VALUES ($1)`, id)
}
'''
    assert len(detect_sql(src)) >= 1


# ---------- go.architecture.no-handler-detached-goroutine ----------

BAD_GO = '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go h.audit()
}
'''

NEAR_MISS_GO = [
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go process(r.Context())
}
''',
    '''func worker() {
	go process()
}
''',
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go func() {
		<-r.Context().Done()
	}()
}
''',
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go work(ctx)
}
''',
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go h.server.ListenAndServe()
}
''',
]


def test_go_bad_is_flagged():
    assert len(detect_go(BAD_GO)) >= 1


def test_go_bare_process_in_handler_flagged():
    src = '''func catalog(w http.ResponseWriter, r *http.Request) {
	go process()
}
'''
    assert len(detect_go(src)) >= 1


def test_go_test_file_skipped():
    assert detect_go(BAD_GO, filename="handler_test.go") == []


def test_go_copyright_header_file_still_parses():
    src = '''// Copyright 2015 Example Authors
package handler

import "net/http"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go h.audit()
}
'''
    assert len(detect_go(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_GO,
    ids=["r-context", "non-handler", "done-lit", "ctx-arg", "listen"],
)
def test_go_good_and_near_misses_pass(src):
    assert detect_go(src) == []


# ---------- go.security.no-dynamic-sql-execution ----------

BAD_DYNSQL = '''func (s *Store) Get(id string) error {
	_, err := s.db.Query("SELECT * FROM rides WHERE id = " + id)
	return err
}
'''

NEAR_MISS_DYNSQL = [
    '''func (s *Store) Get(id string) error {
	_, err := s.db.Query(`SELECT * FROM rides WHERE id = $1`, id)
	return err
}
''',
    '''func (s *Store) Get(id string) error {
	_, err := s.db.Query("SELECT * FROM rides WHERE id = ?", id)
	return err
}
''',
    '''func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("q")
}
''',
    '''func (s *Store) Page(limit int) error {
	_, err := s.db.Query(`SELECT id FROM rides LIMIT $1`, limit+1)
	return err
}
''',
]


def test_dynsql_bad_is_flagged():
    assert len(detect_dynsql(BAD_DYNSQL)) >= 1


def test_dynsql_sprintf_flagged():
    src = '''func (s *Store) Get(name string) error {
	_, err := s.db.Exec(fmt.Sprintf("INSERT INTO rides (name) VALUES ('%s')", name))
	return err
}
'''
    assert len(detect_dynsql(src)) >= 1


def test_dynsql_querycontext_second_arg_flagged():
    src = '''func (s *Store) Get(ctx context.Context, table string) error {
	_, err := s.db.QueryContext(ctx, "SELECT * FROM " + table)
	return err
}
'''
    assert len(detect_dynsql(src)) >= 1


def test_dynsql_assign_then_query_flagged():
    src = '''func (s *Store) Get(id string) error {
	q := "SELECT * FROM rides WHERE id = " + id
	_, err := s.db.Query(q)
	return err
}
'''
    assert len(detect_dynsql(src)) >= 1


def test_dynsql_builder_write_then_string_flagged():
    src = '''func (s *Store) Get(id string) error {
	var b strings.Builder
	b.WriteString("SELECT * FROM rides WHERE id = '")
	b.WriteString(id)
	_, err := s.db.Query(b.String())
	return err
}
'''
    assert len(detect_dynsql(src)) >= 1


def test_dynsql_test_file_skipped():
    assert detect_dynsql(BAD_DYNSQL, filename="store_test.go") == []


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_DYNSQL,
    ids=["raw-dollar", "interp-question", "url-query", "bound-plus"],
)
def test_dynsql_good_and_near_misses_pass(src):
    assert detect_dynsql(src) == []

