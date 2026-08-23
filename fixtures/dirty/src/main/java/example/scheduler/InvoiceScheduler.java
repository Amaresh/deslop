package example.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
class InvoiceScheduler {
    private final AccountDirectory accountDirectory;
    private final InvoiceSyncService invoiceSyncService;

    InvoiceScheduler(AccountDirectory accountDirectory, InvoiceSyncService invoiceSyncService) {
        this.accountDirectory = accountDirectory;
        this.invoiceSyncService = invoiceSyncService;
    }

    @Scheduled(fixedDelay = 60000)
    void syncActiveAccounts() {
        for (Account account : accountDirectory.findActiveAccounts()) {
            invoiceSyncService.syncTenant(account.getTenantId());
        }
    }
}

interface AccountDirectory {
    Iterable<Account> findActiveAccounts();
}

interface InvoiceSyncService {
    void syncTenant(Long tenantId);
}

interface Account {
    Long getTenantId();
}
