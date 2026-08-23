package example.listener;

import org.springframework.transaction.event.TransactionalEventListener;

class OcrEventListener {
    @TransactionalEventListener
    void onUploaded(OcrUploadedEvent event) {
        queueOcrAfterCommit(event.getId(), () -> runOcr(event));
    }
}
