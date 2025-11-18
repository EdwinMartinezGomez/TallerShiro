package co.edu.uptc.TallerShiro.controller;

import co.edu.uptc.TallerShiro.model.User;
import co.edu.uptc.TallerShiro.services.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresPermissions;
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
    @RequiresRoles("admin")
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

    /**
     * Muestra información de la sesión Shiro/HTTP
     */
    @GetMapping("/session")
    @RequiresPermissions("session:view")
    public String showSessionInfo(Model model) {
        Subject currentUser = SecurityUtils.getSubject();
        org.apache.shiro.session.Session session = currentUser.getSession(false);

        if (session == null) {
            model.addAttribute("message", "No hay sesión activa");
            return "session-info";
        }

        model.addAttribute("sessionId", session.getId());
        model.addAttribute("creationTime", session.getStartTimestamp());
        model.addAttribute("lastAccessTime", session.getLastAccessTime());
        model.addAttribute("timeout", session.getTimeout());
        model.addAttribute("principal", currentUser.getPrincipal());

        return "session-info";
    }
}
