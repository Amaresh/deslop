package example.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClient;

@Service
class PaymentService {
    private final MessagingClient messagingClient;
    private final RestTemplate restTemplate = new RestTemplate();

    PaymentService(MessagingClient messagingClient) {
        this.messagingClient = messagingClient;
    }

    @Transactional
    void processQueued(String phone) {
        messagingClient.send(phone, "sms", "template");
        restTemplate.getForObject("https://example.test/api", String.class);
    }

    @Transactional(readOnly = true)
    void preview(String phone) {
        messagingClient.send(phone, "sms", "template");
    }

    void dispatchLater(String phone) {
        messagingClient.send(phone, "sms", "template");
    }
}

class ClientConfig {
    RestTemplate shaped() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setRequestFactory(new Object());
        return restTemplate;
    }

    RestClient restClient() {
        return RestClient.builder().requestFactory(new Object()).build();
    }
}

interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE i.status = :status")
    Object named(String status);

    @Query("SELECT i FROM Invoice i WHERE i.status = " + status)
    Object concat(String status);
}

class QueryRunner {
    Object run(Object entityManager, String entity) {
        return entityManager.createQuery("select e from " + entity);
    }
}
