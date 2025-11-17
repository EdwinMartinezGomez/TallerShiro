package co.edu.uptc.TallerShiro.services;

import co.edu.uptc.TallerShiro.model.Product;

import java.util.List;
import java.util.Optional;

public interface ProductService {
    List<Product> listAll();
    Optional<Product> getById(Long id);
    Product save(Product product);
    void delete(Long id);
}
