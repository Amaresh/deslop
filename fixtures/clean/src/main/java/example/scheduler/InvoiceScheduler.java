package example.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
class InvoiceScheduler {
    private final AccountDirectory accountDirectory;
    private final SyncRunner syncRunner;
    private final InvoiceSyncService invoiceSyncService;

    InvoiceScheduler(
            AccountDirectory accountDirectory,
            SyncRunner syncRunner,
            InvoiceSyncService invoiceSyncService) {
        this.accountDirectory = accountDirectory;
        this.syncRunner = syncRunner;
        this.invoiceSyncService = invoiceSyncService;
    }

    @Scheduled(fixedDelay = 60000)
    void syncActiveAccounts() {
        for (Long tenantId : accountDirectory.findActiveAccountIds()) {
            syncRunner.runForTenant(tenantId, () -> invoiceSyncService.syncTenant(tenantId));
        }
    }
}

interface AccountDirectory {
    Iterable<Long> findActiveAccountIds();
}

interface SyncRunner {
    void runForTenant(Long tenantId, Runnable work);
}

interface InvoiceSyncService {
    void syncTenant(Long tenantId);
}
