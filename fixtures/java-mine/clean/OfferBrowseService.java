package example.catalog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
@Service
class OfferBrowseService {
    private final OfferRepository offerRepository;
    Page<Offer> page(Pageable pageable) {
        return offerRepository.findAll(pageable);
    }
}
