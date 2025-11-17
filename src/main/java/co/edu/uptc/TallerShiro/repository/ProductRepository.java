package co.edu.uptc.TallerShiro.repository;

import co.edu.uptc.TallerShiro.model.Product;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Repository
public class ProductRepository {
    private final Map<Long, Product> storage = new ConcurrentHashMap<>();
    private final AtomicLong idGenerator = new AtomicLong(0);

    public List<Product> findAll() {
        ArrayList<Product> list = new ArrayList<>(storage.values());
        list.sort(Comparator.comparing(Product::getId));
        return list;
    }

    public Optional<Product> findById(Long id) {
        return Optional.ofNullable(storage.get(id));
    }

    public Product save(Product product) {
        if (product.getId() == null) {
            product.setId(idGenerator.incrementAndGet());
        }
        storage.put(product.getId(), product);
        return product;
    }

    public void deleteById(Long id) {
        storage.remove(id);
    }

    public void clear() {
        storage.clear();
        idGenerator.set(0);
    }
}
