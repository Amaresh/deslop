import sys
from pathlib import Path

import pytest

DETECTORS = Path(__file__).resolve().parents[1] / "checkers"
sys.path.insert(0, str(DETECTORS))

from no_service_layer_transactional_external_io import (  # noqa: E402
    detect as detect_tx,
    RULE_ID as TX_ID,
)
from no_service_layer_rest_template_without_timeout_shaping import (  # noqa: E402
    detect as detect_rt,
    RULE_ID as RT_ID,
)
from no_jpql_null_or_lower_on_optional_filter import (  # noqa: E402
    detect as detect_jpql,
    RULE_ID as JPQL_ID,
)
from no_query_string_concatenation import (  # noqa: E402
    detect as detect_q,
    RULE_ID as Q_ID,
)
from no_unbounded_findall_without_pagination import (  # noqa: E402
    detect as detect_findall,
    RULE_ID as FINDALL_ID,
)
from no_controller_direct_repository_access import (  # noqa: E402
    detect as detect_ctrl,
    RULE_ID as CTRL_ID,
)
from no_eager_to_many_fetch import (  # noqa: E402
    detect as detect_eager,
    RULE_ID as EAGER_ID,
)
from no_java_raw_pii_logging import (  # noqa: E402
    detect as detect_pii,
    RULE_ID as PII_ID,
)
from no_secret_fallback_literal import (  # noqa: E402
    detect as detect_secret,
    RULE_ID as SECRET_ID,
)
from no_file_upload_without_validation import (  # noqa: E402
    detect as detect_upload,
    RULE_ID as UPLOAD_ID,
)
from no_n_plus_one_without_entity_graph import (  # noqa: E402
    detect as detect_n1,
    RULE_ID as N1_ID,
)
from no_after_commit_dispatch_from_after_commit_listener import (  # noqa: E402
    detect as detect_after_commit,
    RULE_ID as AFTER_COMMIT_ID,
)


# ---------- java.architecture.no-service-layer-transactional-external-io ----------

BAD_TX = '''
package example.billing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
class InvoiceDispatchService {
    private final MessagingClient messagingClient;
    InvoiceDispatchService(MessagingClient messagingClient) {
        this.messagingClient = messagingClient;
    }
    @Transactional
    void processQueuedInvoice(String phone) {
        messagingClient.send(phone, "sms", "invoice-ready");
    }
}
'''

GOOD_TX = '''
package example.billing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
class InvoicePersistService {
    private final InvoiceRepository invoiceRepository;
    InvoicePersistService(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }
    @Transactional
    void persistQueuedInvoice(Invoice invoice) {
        invoiceRepository.save(invoice);
    }
    void sendQueuedInvoice(String phone, MessagingClient messagingClient) {
        messagingClient.send(phone, "sms", "invoice-ready");
    }
}
'''

NEAR_MISS_TX = [
    GOOD_TX,
    '''
package example.billing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
class InvoicePreviewService {
    private final MessagingClient messagingClient;
    InvoicePreviewService(MessagingClient messagingClient) {
        this.messagingClient = messagingClient;
    }
    @Transactional(readOnly = true)
    void previewNotification(String phone) {
        messagingClient.send(phone, "sms", "invoice-preview");
    }
}
''',
    '''
package example.billing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
class AttributeService {
    @Transactional
    void copyAttrs(java.util.Map<String, String> attrs) {
        attrs.put("status", "queued");
    }
}
''',
    '''
package example.billing;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
class ChunkService {
    private final Buffer buffer;
    ChunkService(Buffer buffer) { this.buffer = buffer; }
    @Transactional
    void flushBuffer() {
        buffer.send();
    }
}
''',
]


def test_tx_bad_is_flagged():
    findings = detect_tx(BAD_TX)
    assert len(findings) >= 1
    assert findings[0].rule_id == TX_ID
    assert any("send" in f.message for f in findings)


def test_tx_http_get_for_object_flagged():
    src = '''
package example.billing;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
class SettlementService {
    private final RestTemplate restTemplate;
    @Transactional
    void settle() {
        restTemplate.getForObject("https://example.test", String.class);
    }
}
'''
    assert len(detect_tx(src)) >= 1


def test_tx_s3_flagged():
    src = '''
package example.billing;
import org.springframework.transaction.annotation.Transactional;
class ArchiveService {
    private final AmazonS3 amazonS3;
    @Transactional
    void archive(byte[] pdf) {
        amazonS3.putObject("bucket", pdf);
    }
}
'''
    assert len(detect_tx(src)) >= 1


def test_tx_class_level_transactional_flagged():
    src = '''
package example.billing;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
@Transactional
class AccountService {
    private final RestTemplate restTemplate;
    void pay() {
        restTemplate.exchange("/pay", null, null, String.class);
    }
}
'''
    assert len(detect_tx(src)) >= 1


def test_tx_test_file_skipped():
    assert detect_tx(BAD_TX, filename="InvoiceDispatchServiceTest.java") == []
    assert len(detect_tx(BAD_TX, filename="InvoiceDispatchService.java")) >= 1


@pytest.mark.parametrize("src", NEAR_MISS_TX, ids=["good", "readonly", "map-put", "random-send"])
def test_tx_good_and_near_misses_pass(src):
    assert detect_tx(src) == []


# ---------- rest-template timeout shaping ----------

BAD_RT = '''
package example.integration;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
@Service
class PartnerSyncService {
    private final RestTemplate restTemplate = new RestTemplate();
}
'''

GOOD_RT = '''
package example.integration;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
@Service
class PartnerGatewayService {
    private final RestTemplate restTemplate;
    PartnerGatewayService() {
        this.restTemplate = new RestTemplate();
        this.restTemplate.setRequestFactory(buildRequestFactory());
    }
    private Object buildRequestFactory() { return new Object(); }
}
'''

NEAR_MISS_RT = [
    GOOD_RT,
    '''
package example.integration;
import org.springframework.web.client.RestTemplate;
class LedgerClientService {
    RestTemplate template(Object requestFactory) {
        return new RestTemplate(requestFactory);
    }
}
''',
    '''
package example.integration;
import org.springframework.web.client.RestClient;
class InventoryClientService {
    private final RestClient restClient = RestClient.builder()
            .requestFactory(new Object())
            .build();
}
''',
    '''
package example.integration;
import org.springframework.web.reactive.function.client.WebClient;
class QuoteStreamService {
    WebClient client() {
        return WebClient.builder().responseTimeout(java.time.Duration.ofSeconds(2)).build();
    }
}
''',
]


def test_rt_bad_is_flagged():
    findings = detect_rt(BAD_RT)
    assert len(findings) >= 1
    assert findings[0].rule_id == RT_ID


def test_rt_builder_without_timeout_flagged():
    src = '''
package example.integration;
import org.springframework.web.client.RestClient;
class CatalogClientService {
    private final RestClient restClient = RestClient.builder().build();
}
'''
    assert len(detect_rt(src)) >= 1


def test_rt_webclient_create_flagged():
    src = '''
package example.integration;
import org.springframework.web.reactive.function.client.WebClient;
class StreamService {
    WebClient client() {
        return WebClient.create();
    }
}
'''
    assert len(detect_rt(src)) >= 1


def test_rt_test_file_skipped():
    assert detect_rt(BAD_RT, filename="PartnerSyncServiceTest.java") == []


@pytest.mark.parametrize("src", NEAR_MISS_RT, ids=["good", "ctor-factory", "restclient-rf", "webclient-timeout"])
def test_rt_good_and_near_misses_pass(src):
    assert detect_rt(src) == []


# ---------- java.reliability.no-jpql-null-or-lower-on-optional-filter ----------

BAD_JPQL = '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE :status IS NULL OR LOWER(i.status) = LOWER(:status)")
    java.util.List<Invoice> findByStatus(String status);
}
'''

GOOD_JPQL = '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE :status = '' OR LOWER(i.status) = LOWER(:status)")
    java.util.List<Invoice> findByStatus(String status);
}
'''

NEAR_MISS_JPQL = [
    GOOD_JPQL,
    '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE :status IS NULL OR i.status = :status")
    java.util.List<Invoice> findByStatus(String status);
}
''',
    '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE LOWER(i.status) = LOWER(:status)")
    java.util.List<Invoice> findByStatus(String status);
}
''',
]


def test_jpql_bad_is_flagged():
    findings = detect_jpql(BAD_JPQL)
    assert len(findings) >= 1
    assert findings[0].rule_id == JPQL_ID
    assert "IS NULL OR" in findings[0].message


def test_jpql_concat_literals_flagged():
    src = '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface CustomerRepository {
    @Query(
            "SELECT c FROM Customer c "
                    + "WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))")
    java.util.List<Customer> findByStatus(String status);
}
'''
    assert len(detect_jpql(src)) == 1


def test_jpql_text_block_flagged():
    src = '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface CustomerRepository {
    @Query("""
            SELECT c FROM Customer c
            WHERE :status IS NULL OR LOWER(c.status) = LOWER(:status)
            """)
    java.util.List<Customer> findByStatus(String status);
}
'''
    assert len(detect_jpql(src)) == 1


def test_jpql_same_file_identifier_concat_flagged():
    src = '''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface CustomerRepository {
    String QUERY = "SELECT c FROM Customer c ";
    String WHERE = "WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))";

    @Query(QUERY + "WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))")
    java.util.List<Customer> findByStatus(String status);

    @Query(QUERY + WHERE)
    java.util.List<Customer> findByStatusAgain(String status);
}
'''
    assert len(detect_jpql(src)) == 2


def test_jpql_cross_file_constants_flagged(tmp_path):
    repo = tmp_path / "src" / "main" / "java" / "example" / "repo"
    repo.mkdir(parents=True)
    (repo / "Queries.java").write_text('''
package example.repo;
public final class Queries {
    public static final String WHERE =
            "WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))";
}
'''.strip(), encoding="utf-8")
    path = repo / "CustomerRepository.java"
    path.write_text('''
package example.repo;
import org.springframework.data.jpa.repository.Query;
public interface CustomerRepository {
    String QUERY = "SELECT c FROM Customer c ";

    @Query(Queries.WHERE)
    java.util.List<Customer> findByStatus(String status);

    @Query(QUERY + Queries.WHERE)
    java.util.List<Customer> findByStatusAgain(String status);
}
'''.strip(), encoding="utf-8")
    findings = detect_jpql(path.read_text(encoding="utf-8"), filename=str(path))
    assert len(findings) == 2
    assert all(item.rule_id == JPQL_ID for item in findings)


def test_jpql_test_file_skipped():
    assert detect_jpql(BAD_JPQL, filename="InvoiceRepositoryTest.java") == []
    assert len(detect_jpql(BAD_JPQL, filename="InvoiceRepository.java")) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_JPQL,
    ids=["empty-sentinel", "null-or-without-lower", "lower-without-null-or"],
)
def test_jpql_good_and_near_misses_pass(src):
    assert detect_jpql(src) == []


# ---------- java.jpa.no-query-string-concatenation ----------

BAD_Q = '''
package example.catalog;
import org.springframework.data.jpa.repository.Query;
interface ProductRepository {
    String ENTITY = "Product";
    @Query("SELECT p FROM " + ENTITY + " p WHERE p.sku = :sku")
    Object findBySku(String sku);
}
'''

GOOD_Q = '''
package example.catalog;
import org.springframework.data.jpa.repository.Query;
interface OfferRepository {
    @Query("SELECT o FROM Offer o WHERE o.status = :status")
    Object findByStatus(String status);
}
'''

NEAR_MISS_Q = [
    GOOD_Q,
    '''
package example.catalog;
import org.springframework.data.jpa.repository.Query;
interface CategoryRepository {
    @Query("SELECT c FROM Category c " + "WHERE c.active = true AND c.name = :name")
    Object findActiveByName(String name);
}
''',
    '''
package example.catalog;
class ProductLabelService {
    String labelFor(String sku, String name) {
        return "Product " + name + " (" + sku + ")";
    }
}
''',
    '''
package example.catalog;
import jakarta.persistence.Column;
class Product {
    static final String SIZE = "64";
    @Column(columnDefinition = "varchar(" + SIZE + ")")
    String sku;
}
''',
    '''
package example.catalog;
class SourceLabel {
    String fromSource(String source) {
        return " from source [" + source + "]";
    }
}
''',
    '''
package example.catalog;
class RecoverLog {
    void recovered(String description) {
        addStatus("Recovered from IO failure on " + description);
    }
    void addStatus(String msg) {}
}
''',
]


def test_q_bad_is_flagged():
    findings = detect_q(BAD_Q)
    assert len(findings) >= 1
    assert findings[0].rule_id == Q_ID


def test_q_create_query_flagged():
    src = '''
package example.catalog;
import jakarta.persistence.EntityManager;
class ProductQueryService {
    private final EntityManager entityManager;
    Object byType(String entity) {
        return entityManager.createQuery("select e from " + entity + " e");
    }
}
'''
    assert len(detect_q(src)) >= 1


def test_q_assigned_native_query_flagged():
    src = '''
package example.catalog;
import jakarta.persistence.EntityManager;
class OfferNativeQueryService {
    private final EntityManager entityManager;
    Object recentOffers(String table) {
        String sql = "select * from " + table + " where active = 1";
        return entityManager.createNativeQuery(sql);
    }
}
'''
    assert len(detect_q(src)) >= 1


def test_q_test_file_skipped():
    assert detect_q(BAD_Q, filename="ProductRepositoryTest.java") == []


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_Q,
    ids=["named-params", "literal-concat", "non-sql", "other-ann", "english-from", "from-io-failure"],
)
def test_q_good_and_near_misses_pass(src):
    assert detect_q(src) == []


# ---------- java.reliability.no-unbounded-findall-without-pagination ----------

BAD_FINDALL = '''
package example.catalog;
import org.springframework.stereotype.Service;
@Service
class OfferExportService {
    private final OfferRepository offerRepository;
    OfferExportService(OfferRepository offerRepository) {
        this.offerRepository = offerRepository;
    }
    java.util.List<Offer> exportAll() {
        return offerRepository.findAll();
    }
}
'''

NEAR_MISS_FINDALL = [
    '''
package example.catalog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
@Service
class OfferBrowseService {
    private final OfferRepository offerRepository;
    Page<Offer> page(Pageable pageable) {
        return offerRepository.findAll(pageable);
    }
}
''',
    '''
package example.modules;
import java.lang.module.ModuleFinder;
class ModuleIndex {
    int systemModuleCount() {
        return ModuleFinder.ofSystem().findAll().size();
    }
}
''',
    '''
package example.catalog;
class OfferRepository {
    java.util.Collection<Offer> findAll() {
        return java.util.List.of();
    }
}
''',
]


def test_findall_bad_is_flagged():
    findings = detect_findall(BAD_FINDALL)
    assert len(findings) >= 1
    assert findings[0].rule_id == FINDALL_ID


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_FINDALL,
    ids=["pageable", "module-finder", "interface-decl"],
)
def test_findall_good_and_near_misses_pass(src):
    assert detect_findall(src) == []


def test_findall_test_file_skipped():
    assert detect_findall(BAD_FINDALL, filename="OfferExportServiceTest.java") == []


# ---------- java.architecture.no-controller-direct-repository-access ----------

BAD_CTRL = '''
package example.clinic;
import org.springframework.stereotype.Controller;
@Controller
class VetController {
    private final VetRepository vetRepository;
    VetController(VetRepository vetRepository) {
        this.vetRepository = vetRepository;
    }
}
'''

NEAR_MISS_CTRL = [
    '''
package example.clinic;
import org.springframework.web.bind.annotation.RestController;
@RestController
class AccountController {
    private final AccountService accountService;
    AccountController(AccountService accountService) {
        this.accountService = accountService;
    }
}
''',
    '''
package example.clinic;
import org.springframework.stereotype.Service;
@Service
class BillingService {
    private final InvoiceRepository invoiceRepository;
    BillingService(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }
}
''',
]


def test_ctrl_bad_is_flagged():
    findings = detect_ctrl(BAD_CTRL)
    assert len(findings) >= 1
    assert findings[0].rule_id == CTRL_ID


@pytest.mark.parametrize("src", NEAR_MISS_CTRL, ids=["service-collab", "service-class"])
def test_ctrl_good_and_near_misses_pass(src):
    assert detect_ctrl(src) == []


# ---------- java.performance.no-eager-to-many-fetch ----------

BAD_EAGER = '''
package example.clinic;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
@Entity
class Owner {
    @OneToMany(cascade = jakarta.persistence.CascadeType.ALL, fetch = FetchType.EAGER)
    private java.util.Set<Pet> pets;
    @ManyToMany(fetch = FetchType.EAGER)
    private java.util.Set<Tag> tags;
}
'''

NEAR_MISS_EAGER = [
    '''
package example.clinic;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
@Entity
class Owner {
    @OneToMany
    private java.util.Set<Pet> pets;
}
''',
    '''
package example.clinic;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToOne;
@Entity
class Pet {
    @ManyToOne(fetch = FetchType.EAGER)
    private Owner owner;
}
''',
]


def test_eager_bad_is_flagged():
    findings = detect_eager(BAD_EAGER)
    assert len(findings) >= 2
    assert findings[0].rule_id == EAGER_ID


@pytest.mark.parametrize("src", NEAR_MISS_EAGER, ids=["default-lazy", "many-to-one"])
def test_eager_good_and_near_misses_pass(src):
    assert detect_eager(src) == []


# ---------- java.security.no-raw-pii-logging ----------

BAD_PII = '''
package example.notify;
class RecipientMailer {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(RecipientMailer.class);
    void mail(String email) {
        log.info("sending notice to {}", email);
    }
}
'''

NEAR_MISS_PII = [
    '''
package example.notify;
class AuditLogger {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuditLogger.class);
    void audit(String userId) {
        log.info("user {}", userId);
    }
}
''',
    '''
package example.notify;
class GmailLogger {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GmailLogger.class);
    void note(String userId) {
        log.info("routed via gmail for {}", userId);
    }
}
''',
    '''
package example.notify;
class ConstLogger {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ConstLogger.class);
    void note() {
        log.info("channel {}", Message.EMAIL);
    }
}
''',
    '''
package example.notify;
class RedactLogger {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(RedactLogger.class);
    void note(String email) {
        log.info("recipient {}", redact(email));
    }
    String redact(String value) { return "***"; }
}
''',
    '''
package example.notify;
class GetterLogger {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GetterLogger.class);
    void note(Recipient recipient) {
        log.info("{} email notification has been send to {}", "BACKUP", recipient.getEmail());
    }
}
''',
]


def test_pii_bad_is_flagged():
    findings = detect_pii(BAD_PII)
    assert len(findings) >= 1
    assert findings[0].rule_id == PII_ID
    assert any("email" in f.message for f in findings)


def test_pii_phone_number_flagged():
    src = '''
package example.notify;
class SmsLogger {
    private final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SmsLogger.class);
    void send(String phoneNumber) {
        logger.warn("otp to {}", phoneNumber);
    }
}
'''
    assert len(detect_pii(src)) >= 1


def test_pii_test_file_skipped():
    assert detect_pii(BAD_PII, filename="RecipientMailerTest.java") == []
    assert len(detect_pii(BAD_PII, filename="RecipientMailer.java")) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_PII,
    ids=["userId", "gmail", "constant", "redact", "getEmail"],
)
def test_pii_good_and_near_misses_pass(src):
    assert detect_pii(src) == []


# ---------- java.security.no-secret-fallback-literal ----------

BAD_SECRET = '''
package example.config;
import org.springframework.beans.factory.annotation.Value;
class ApiClientProperties {
    @Value("${api.key:sk-live-abcdef12}")
    private String apiKey;
}
'''

NEAR_MISS_SECRET = [
    '''
package example.config;
import org.springframework.beans.factory.annotation.Value;
class HttpClientProperties {
    @Value("${http.timeout:5000}")
    private int timeout;
}
''',
    '''
package example.config;
import org.springframework.beans.factory.annotation.Value;
class ServerProperties {
    @Value("${server.port:8080}")
    private int port;
}
''',
    '''
package example.config;
import org.springframework.beans.factory.annotation.Value;
class ApiClientProperties {
    @Value("${api.key:CHANGE_ME}")
    private String apiKey;
}
''',
    '''
package example.config;
import org.springframework.beans.factory.annotation.Value;
class ApiClientProperties {
    @Value("${api.key:${API_KEY}}")
    private String apiKey;
}
''',
    '''
package example.config;
class VendorProbe {
    boolean android() {
        return System.getProperty("java.vendor", "").contains("android");
    }
}
''',
]


def test_secret_bad_is_flagged():
    findings = detect_secret(BAD_SECRET)
    assert len(findings) >= 1
    assert findings[0].rule_id == SECRET_ID


def test_secret_getproperty_flagged():
    src = '''
package example.config;
class JwtSettings {
    String secret() {
        return System.getProperty("jwt.secret", "insecure-dev-secret");
    }
}
'''
    assert len(detect_secret(src)) >= 1


def test_secret_getenv_orelse_flagged():
    src = '''
package example.config;
class TokenSettings {
    String token() {
        return java.util.Optional.ofNullable(System.getenv("API_SECRET"))
                .orElse("insecure-fallback");
    }
}
'''
    assert len(detect_secret(src)) >= 1


def test_secret_test_file_skipped():
    assert detect_secret(BAD_SECRET, filename="ApiClientPropertiesTest.java") == []


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_SECRET,
    ids=["timeout", "port", "changeme", "nested-placeholder", "vendor-empty"],
)
def test_secret_good_and_near_misses_pass(src):
    assert detect_secret(src) == []


# ---------- java.correctness.no-file-upload-without-validation ----------

BAD_UPLOAD = '''
package example.upload;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
@RestController
class AvatarController {
    @PostMapping("/avatar")
    public void upload(MultipartFile file) {
        store(file);
    }
    void store(MultipartFile file) {}
}
'''

NEAR_MISS_UPLOAD = [
    '''
package example.upload;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
@RestController
class AvatarController {
    @PostMapping("/avatar")
    public void upload(MultipartFile file) {
        if (file.getSize() > 1_000_000L) {
            return;
        }
        if (file.getContentType() == null) {
            return;
        }
        store(file);
    }
    void store(MultipartFile file) {}
}
''',
    '''
package example.upload;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
@RestController
class AvatarController {
    @PostMapping("/avatar")
    public void upload(MultipartFile file) {
        java.nio.file.Files.probeContentType(java.nio.file.Path.of(file.getName()));
        store(file);
    }
    void store(MultipartFile file) {}
}
''',
    '''
package example.upload;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
@Service
class AvatarStoreService {
    public void store(MultipartFile file) {
        persist(file);
    }
    void persist(MultipartFile file) {}
}
''',
    '''
package example.upload;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
@RestController
class AvatarController {
    @PostMapping("/avatar")
    void upload(MultipartFile file) {
        store(file);
    }
    void store(MultipartFile file) {}
}
''',
]


def test_upload_bad_is_flagged():
    findings = detect_upload(BAD_UPLOAD)
    assert len(findings) >= 1
    assert findings[0].rule_id == UPLOAD_ID


def test_upload_put_commons_flagged():
    src = '''
package example.upload;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.commons.CommonsMultipartFile;
@RestController
class ResumeController {
    @PutMapping("/resume")
    public void replace(CommonsMultipartFile file) {
        store(file);
    }
    void store(CommonsMultipartFile file) {}
}
'''
    assert len(detect_upload(src)) >= 1


def test_upload_test_file_skipped():
    assert detect_upload(BAD_UPLOAD, filename="AvatarControllerTest.java") == []
    assert len(detect_upload(BAD_UPLOAD, filename="AvatarController.java")) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_UPLOAD,
    ids=["size-type", "probe-content-type", "service", "package-private"],
)
def test_upload_good_and_near_misses_pass(src):
    assert detect_upload(src) == []


# ---------- java.performance.no-n-plus-one-without-entity-graph ----------

BAD_N1 = '''
package example.billing;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Invoice {
    @OneToMany
    private List<InvoiceLine> lines;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    Page<Invoice> findByAccountId(Long accountId, Pageable pageable);
}
'''

GOOD_N1_GRAPH = '''
package example.billing;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Invoice {
    @OneToMany
    private List<InvoiceLine> lines;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    @EntityGraph(attributePaths = "lines")
    Page<Invoice> findByAccountId(Long accountId, Pageable pageable);
}
'''

NEAR_MISS_N1 = [
    GOOD_N1_GRAPH,
    '''
package example.billing;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

@Entity
class Invoice {
    @OneToMany
    private List<InvoiceLine> lines;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    @Query("select i from Invoice i join fetch i.lines where i.accountId = :id")
    java.util.List<Invoice> findByAccountId(Long id);
}
''',
    '''
package example.billing;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Invoice {
    @OneToMany(fetch = FetchType.EAGER)
    private List<InvoiceLine> lines;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    Page<Invoice> findByAccountId(Long accountId, Pageable pageable);
}
''',
    '''
package example.billing;

import jakarta.persistence.Entity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Invoice {
    private String accountId;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    Page<Invoice> findByAccountId(Long accountId, Pageable pageable);
}
''',
    '''
package example.billing;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Invoice {
    @OneToMany
    private List<InvoiceLine> lines;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    Optional<Invoice> findById(Long id);
}
''',
    '''
package example.billing;

import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

@Entity
class Invoice {
    @OneToMany
    private List<InvoiceLine> lines;
}

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    default List<Invoice> findAllWithEagerRelationships() {
        return findAll();
    }
    default Page<Invoice> findAllWithEagerRelationships(Pageable pageable) {
        return findAll(pageable);
    }
}
''',
]


def test_n1_bad_is_flagged():
    findings = detect_n1(BAD_N1)
    assert len(findings) >= 1
    assert findings[0].rule_id == N1_ID
    assert "N+1" in findings[0].message


def test_n1_inherited_findall_on_empty_repo():
    src = '''
package example.billing;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.Set;
import org.springframework.data.jpa.repository.JpaRepository;
@Entity
class Account {
    @OneToMany
    private Set<Card> cards;
}
public interface AccountRepository extends JpaRepository<Account, Long> {
}
'''
    findings = detect_n1(src)
    assert len(findings) == 1
    assert "inherits findAll" in findings[0].message


def test_n1_sibling_entity_by_name(tmp_path):
    domain = tmp_path / "domain"
    repos = tmp_path / "repository"
    domain.mkdir()
    repos.mkdir()
    (domain / "Shipment.java").write_text('''
package example.ship.domain;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import java.util.List;
@Entity
public class Shipment {
    @OneToMany
    private List<Parcel> parcels;
}
''', encoding="utf-8")
    repo = repos / "ShipmentRepository.java"
    repo.write_text('''
package example.ship.repository;
import example.ship.domain.Shipment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
public interface ShipmentRepository extends JpaRepository<Shipment, Long> {
    Page<Shipment> findByWarehouse(String warehouse, Pageable pageable);
}
''', encoding="utf-8")
    findings = detect_n1(repo.read_text(encoding="utf-8"), filename=str(repo))
    assert len(findings) >= 1
    assert findings[0].rule_id == N1_ID


def test_n1_missing_entity_file_is_silent(tmp_path):
    repo = tmp_path / "GhostRepository.java"
    repo.write_text('''
package example.ghost;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
public interface GhostRepository extends JpaRepository<Ghost, Long> {
    Page<Ghost> findByName(String name, Pageable pageable);
}
''', encoding="utf-8")
    assert detect_n1(repo.read_text(encoding="utf-8"), filename=str(repo)) == []


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_N1,
    ids=["entity-graph", "join-fetch", "eager-only", "no-collections", "find-by-id", "eager-name"],
)
def test_n1_good_and_near_misses_pass(src):
    assert detect_n1(src) == []


# ---------- java.reliability.no-after-commit-dispatch-from-after-commit-listener ----------

BAD_AFTER_COMMIT = [
    '''
package example.billing;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.event.TransactionPhase;
class InvoicePaidListener {
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    void onPaid(InvoicePaidEvent event) {
        sideEffectExecutor.dispatchAfterCommitCoalescing(
            "invoice-paid", () -> notifier.send(event.id()));
    }
}
''',
    '''
package example.billing;
import org.springframework.transaction.event.TransactionalEventListener;
class InvoicePaidListener {
    @TransactionalEventListener
    void onPaid(InvoicePaidEvent event) {
        scheduler.scheduleAfterCommit(() -> notifier.send(event.id()));
    }
}
''',
    '''
package example.billing;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.TransactionSynchronizationManager;
class InvoicePaidListener {
    @TransactionalEventListener
    void onPaid(InvoicePaidEvent event) {
        TransactionSynchronizationManager.registerSynchronization(sync);
    }
}
''',
]

NEAR_MISS_AFTER_COMMIT = [
    '''
package example.billing;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.event.TransactionPhase;
class InvoicePaidListener {
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    void onPaid(InvoicePaidEvent event) {
        notifier.send(event.id());
    }
}
''',
    '''
package example.billing;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.event.TransactionPhase;
class InvoicePaidListener {
    @TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
    void onPaid(InvoicePaidEvent event) {
        sideEffectExecutor.dispatchAfterCommitCoalescing(
            "invoice-paid", () -> notifier.send(event.id()));
    }
}
''',
    '''
package example.billing;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.event.TransactionPhase;
class InvoicePaidListener {
    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    void onPaid(InvoicePaidEvent event) {
        scheduler.scheduleAfterCommit(() -> notifier.send(event.id()));
    }
}
''',
    '''
package example.billing;
class InvoicePaidListener {
    void onPaid(InvoicePaidEvent event) {
        sideEffectExecutor.dispatchAfterCommitCoalescing(
            "invoice-paid", () -> notifier.send(event.id()));
    }
}
''',
]


@pytest.mark.parametrize(
    "src",
    BAD_AFTER_COMMIT,
    ids=["dispatchAfterCommit", "scheduleAfterCommit", "registerSynchronization"],
)
def test_after_commit_dispatch_bad_is_flagged(src):
    hits = detect_after_commit(src)
    assert len(hits) >= 1
    assert hits[0].rule_id == AFTER_COMMIT_ID


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_AFTER_COMMIT,
    ids=["direct-send", "before-commit", "after-rollback", "no-listener"],
)
def test_after_commit_dispatch_near_misses_pass(src):
    assert detect_after_commit(src) == []


def test_after_commit_dispatch_test_file_skipped():
    assert detect_after_commit(BAD_AFTER_COMMIT[0], filename="ListenerTest.java") == []

