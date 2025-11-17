package co.edu.uptc.TallerShiro.controller;

import co.edu.uptc.TallerShiro.model.User;
import co.edu.uptc.TallerShiro.services.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

/**
 * Controlador para páginas informativas y de demostración
 */
@Controller
@RequestMapping("/info")
public class InfoController {

    private final UserService userService;

    public InfoController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Página de información sobre hashing de contraseñas
     */
    // Hashing info page removed per project configuration (prints moved to initializer)

    /**
     * Página de usuarios registrados (solo para admin)
     */
    @GetMapping("/users")
    public String showUsers(Model model) {
        Subject currentUser = SecurityUtils.getSubject();

        if (!currentUser.isAuthenticated()) {
            return "redirect:/login";
        }

        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        model.addAttribute("currentUser", currentUser.getPrincipal());

        return "users-list";
    }
}
