package example.repo;

import example.model.Customer;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CustomerRepository extends JpaRepository<Customer, Long> {

    @Query(
            "SELECT c FROM Customer c "
                    + "WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))")
    List<Customer> findByStatus(@Param("status") String status);
}
