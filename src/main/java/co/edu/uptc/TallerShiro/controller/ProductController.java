package co.edu.uptc.TallerShiro.controller;

import co.edu.uptc.TallerShiro.model.Product;
import co.edu.uptc.TallerShiro.services.ProductService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/products")
public class ProductController {

    private final ProductService service;

    public ProductController(ProductService service) {
        this.service = service;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("products", service.listAll());
        return "products/list";
    }

    @GetMapping("/new")
    public String createForm(Model model) {
        model.addAttribute("product", new Product());
        return "products/form";
    }

    @PostMapping
    public String save(@ModelAttribute Product product) {
        service.save(product);
        return "redirect:/products";
    }

    @GetMapping("/edit/{id}")
    public String editForm(@PathVariable Long id, Model model) {
        Product p = service.getById(id).orElse(new Product());
        model.addAttribute("product", p);
        return "products/form";
    }

    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Long id) {
        service.delete(id);
        return "redirect:/products";
    }

    @GetMapping("/{id}")
    public String details(@PathVariable Long id, Model model) {
        Product p = service.getById(id).orElse(null);
        model.addAttribute("product", p);
        return "products/details";
    }
}
