package example.web;
import org.springframework.web.bind.annotation.RestController;
@RestController
class InvoiceController {
    private final InvoiceService invoices;
    InvoiceController(InvoiceService invoices) {
        this.invoices = invoices;
    }
}
