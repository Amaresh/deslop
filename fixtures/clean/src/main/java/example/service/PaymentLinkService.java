package example.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class PaymentLinkService {
    private final MessagingClient messagingClient;

    PaymentLinkService(MessagingClient messagingClient) {
        this.messagingClient = messagingClient;
    }

    @Transactional
    void persistQueuedPaymentLink() {}

    void sendQueuedPaymentLink() {
        messagingClient.send("+15550100432", "sms", "template");
    }
}

class MessagingClient {
    void send(String phone, String channel, String kind) {}
}
