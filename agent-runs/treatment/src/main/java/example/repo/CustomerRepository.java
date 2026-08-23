package example.repo;

import example.model.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CustomerRepository extends JpaRepository<Customer, Long> {

    @Query("SELECT c FROM Customer c WHERE :status = '' OR LOWER(c.status) = LOWER(:status)")
    List<Customer> findByStatus(@Param("status") String status);
}
