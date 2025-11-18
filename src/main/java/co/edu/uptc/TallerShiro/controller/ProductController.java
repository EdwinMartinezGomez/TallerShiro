package co.edu.uptc.TallerShiro.controller;

import co.edu.uptc.TallerShiro.model.Product;
import co.edu.uptc.TallerShiro.services.ProductService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.authz.annotation.RequiresPermissions;
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

    @GetMapping({"/", "/list"})
    @RequiresPermissions("product:read")
    public String list(Model model) {
        Subject currentUser = SecurityUtils.getSubject();
        model.addAttribute("products", service.listAll());
        model.addAttribute("currentUser", currentUser.getPrincipal());
        model.addAttribute("isAuthenticated", currentUser.isAuthenticated());
        model.addAttribute("isAdmin", currentUser.hasRole("admin"));
        return "products/list";
    }

    @GetMapping("/new")
    @RequiresPermissions("product:create")
    public String createForm(Model model) {
        model.addAttribute("product", new Product());
        model.addAttribute("isNew", true);
        return "products/form";
    }

    @PostMapping
    @RequiresPermissions("product:create")
    public String save(@ModelAttribute Product product) {
        service.save(product);
        return "redirect:/products/list";
    }

    @GetMapping("/edit/{id}")
    @RequiresPermissions("product:update")
    public String editForm(@PathVariable Long id, Model model) {
        Product p = service.getById(id).orElse(new Product());
        model.addAttribute("product", p);
        model.addAttribute("isNew", false);
        return "products/form";
    }

    @GetMapping("/delete/{id}")
    @RequiresPermissions("product:delete")
    public String delete(@PathVariable Long id) {
        service.delete(id);
        return "redirect:/products/list";
    }

    @GetMapping("/{id}")
    @RequiresPermissions("product:read")
    public String details(@PathVariable Long id, Model model) {
        Subject currentUser = SecurityUtils.getSubject();
        Product p = service.getById(id).orElse(null);
        model.addAttribute("product", p);
        model.addAttribute("currentUser", currentUser.getPrincipal());
        model.addAttribute("isAuthenticated", currentUser.isAuthenticated());
        model.addAttribute("isAdmin", currentUser.hasRole("admin"));
        return "products/details";
    }
}
