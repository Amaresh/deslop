package example.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
class PartnerService {
    private final RestTemplate restTemplate;

    PartnerService() {
        this.restTemplate = new RestTemplate();
        this.restTemplate.setRequestFactory(buildRequestFactory());
    }

    private Object buildRequestFactory() {
        return new Object();
    }
}
