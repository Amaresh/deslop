package example.listener;

import org.springframework.transaction.event.TransactionalEventListener;

class OcrEventListener {
    @TransactionalEventListener
    void onUploaded(OcrUploadedEvent event) {
        runOcrAfterCommit(event.getId(), () -> runOcr(event));
    }
}
