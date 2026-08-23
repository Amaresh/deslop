package example.listener;

import org.springframework.transaction.event.TransactionalEventListener;

class OcrEventListener {
    @TransactionalEventListener
    void onUploaded(OcrUploadedEvent event) {
        dispatchCoalescing(event.getId(), () -> runOcr(event));
    }
}
