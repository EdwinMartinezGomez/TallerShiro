package co.edu.uptc.TallerShiro.services.impl;

import co.edu.uptc.TallerShiro.model.Product;
import co.edu.uptc.TallerShiro.repository.ProductRepository;
import co.edu.uptc.TallerShiro.services.ProductService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ProductServiceImpl implements ProductService {

    private final ProductRepository repository;

    public ProductServiceImpl(ProductRepository repository) {
        this.repository = repository;
        // sample data
        repository.save(new Product(null, "Camiseta", "Camiseta blanca", 29.99));
        repository.save(new Product(null, "Pantalón", "Pantalón azul", 49.9));
    }

    @Override
    public List<Product> listAll() {
        return repository.findAll();
    }

    @Override
    public Optional<Product> getById(Long id) {
        return repository.findById(id);
    }

    @Override
    public Product save(Product product) {
        return repository.save(product);
    }

    @Override
    public void delete(Long id) {
        repository.deleteById(id);
    }
}
