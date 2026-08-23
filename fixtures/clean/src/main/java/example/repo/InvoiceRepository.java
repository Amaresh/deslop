package example.repo;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface InvoiceRepository {
    @Query("SELECT i FROM Invoice i WHERE :status = '' OR LOWER(i.status) = LOWER(:status)")
    java.util.List<Invoice> findByStatus(@Param("status") String status);
}
