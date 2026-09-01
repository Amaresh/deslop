package example.listener;

import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

class AfterCommitDispatchListener {
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    void onPaid(InvoicePaidEvent event) {
        sideEffectExecutor.dispatchAfterCommitCoalescing(
            "invoice-paid", () -> notifier.send(event.id()));
    }
}
