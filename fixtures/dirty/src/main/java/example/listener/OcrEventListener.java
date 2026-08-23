package example.listener;

import org.springframework.transaction.event.TransactionalEventListener;

class OcrEventListener {
    @TransactionalEventListener
    void onUploaded(OcrUploadedEvent event) {
        dispatchCoalescingTransactional(event.getId(), () -> runOcr(event));
    }
}
