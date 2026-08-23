package example.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
class TenantInvoiceScheduler {
    private final TenantDirectory tenantDirectory;
    private final TenantRunner tenantRunner;
    private final InvoiceSyncService invoiceSyncService;

    TenantInvoiceScheduler(
            TenantDirectory tenantDirectory,
            TenantRunner tenantRunner,
            InvoiceSyncService invoiceSyncService) {
        this.tenantDirectory = tenantDirectory;
        this.tenantRunner = tenantRunner;
        this.invoiceSyncService = invoiceSyncService;
    }

    @Scheduled(fixedDelay = 60000)
    void syncActiveTenants() {
        for (Long tenantId : tenantDirectory.findActiveTenantIds()) {
            tenantRunner.runForTenant(tenantId, () -> invoiceSyncService.syncTenant(tenantId));
        }
    }
}

interface TenantDirectory {
    Iterable<Long> findActiveTenantIds();
}

interface TenantRunner {
    void runForTenant(Long tenantId, Runnable work);
}

interface InvoiceSyncService {
    void syncTenant(Long tenantId);
}
