package example.catalog;
import org.springframework.stereotype.Service;
@Service
class OfferExportService {
    private final OfferRepository offerRepository;
    OfferExportService(OfferRepository offerRepository) {
        this.offerRepository = offerRepository;
    }
    java.util.List<Offer> exportAll() {
        return offerRepository.findAll();
    }
}
