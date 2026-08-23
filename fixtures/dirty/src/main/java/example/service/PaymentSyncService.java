package example.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
class PaymentSyncService {
    private final RestTemplate restTemplate = new RestTemplate();
}
