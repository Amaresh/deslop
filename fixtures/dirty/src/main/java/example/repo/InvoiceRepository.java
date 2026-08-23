package example.repo;

import org.springframework.data.jpa.repository.Query;

public interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE :status IS NULL OR LOWER(i.status) = LOWER(:status)")
    java.util.List<Invoice> findByStatus(String status);
}
