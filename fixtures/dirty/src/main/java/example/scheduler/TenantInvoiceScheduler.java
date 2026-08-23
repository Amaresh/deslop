package example.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
class TenantInvoiceScheduler {
    private final TenantDirectory tenantDirectory;
    private final InvoiceSyncService invoiceSyncService;

    TenantInvoiceScheduler(TenantDirectory tenantDirectory, InvoiceSyncService invoiceSyncService) {
        this.tenantDirectory = tenantDirectory;
        this.invoiceSyncService = invoiceSyncService;
    }

    @Scheduled(fixedDelay = 60000)
    void syncActiveTenants() {
        for (TenantAccount tenant : tenantDirectory.findActiveTenants()) {
            invoiceSyncService.syncTenant(tenant.getTenantId());
        }
    }
}

interface TenantDirectory {
    Iterable<TenantAccount> findActiveTenants();
}

interface InvoiceSyncService {
    void syncTenant(Long tenantId);
}

interface TenantAccount {
    Long getTenantId();
}
