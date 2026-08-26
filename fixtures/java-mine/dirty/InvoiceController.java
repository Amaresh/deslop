package example.web;
import org.springframework.web.bind.annotation.RestController;
@RestController
class InvoiceController {
    private final InvoiceRepository invoices;
    InvoiceController(InvoiceRepository invoices) {
        this.invoices = invoices;
    }
}
