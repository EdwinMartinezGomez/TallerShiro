package co.edu.uptc.TallerShiro.controller;

import co.edu.uptc.TallerShiro.model.User;
import co.edu.uptc.TallerShiro.services.UserService;
import co.edu.uptc.TallerShiro.util.PasswordHashingUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

/**
 * Controlador para manejar autenticación y autorización con Shiro
 * Implementa login con contraseñas hasheadas y registro de usuarios
 */
@Controller
public class AuthenticationController {

    private final UserService userService;

    public AuthenticationController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Muestra la página de login
     */
    @GetMapping("/login")
    public String showLoginPage() {
        Subject currentUser = SecurityUtils.getSubject();
        // Si ya está autenticado, redirige a products
        if (currentUser.isAuthenticated()) {
            return "redirect:/products/list";
        }
        return "login";
    }

    /**
     * Procesa el login del usuario con contraseñas hasheadas
     */
    @PostMapping("/login")
    public String login(@RequestParam String username, 
                        @RequestParam String password,
                        RedirectAttributes redirectAttributes,
                        HttpServletRequest request) {
        Subject currentUser = SecurityUtils.getSubject();

        // Si ya está autenticado, redirige a products
        if (currentUser.isAuthenticated()) {
            return "redirect:/products/list";
        }

        try {
            // Validar entrada
            if (username == null || username.trim().isEmpty() || 
                password == null || password.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Usuario y contraseña son requeridos");
                return "redirect:/login";
            }

            // Verificar que el usuario exista en BD
            Optional<User> userOpt = userService.findByUsername(username);
            if (userOpt.isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Usuario o contraseña inválidos");
                return "redirect:/login";
            }

            User user = userOpt.get();

            // Verificar que esté activo
            if (!user.isActive()) {
                redirectAttributes.addFlashAttribute("error", "Usuario desactivado");
                return "redirect:/login";
            }

            // Verificar la contraseña contra el hash
            PasswordHashingUtil.HashingAlgorithm algorithm = 
                getAlgorithmFromString(user.getHashAlgorithm());
            
            boolean passwordMatches = PasswordHashingUtil.verifyPassword(
                password, 
                user.getPasswordHash(), 
                algorithm
            );

            if (!passwordMatches) {
                redirectAttributes.addFlashAttribute("error", "Usuario o contraseña inválidos");
                return "redirect:/login";
            }

            // Ensure servlet HTTP session exists before login so the container will issue a
            // JSESSIONID and Shiro's ServletContainerSessionManager can associate the
            // Subject with the HttpSession during login processing.
            var httpSession = request.getSession(true);
            System.out.println("[Auth] HttpSession id (pre-login): " + httpSession.getId());

            // Crea un token con las credenciales
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            // Do not set rememberMe here to avoid remember-only identity which may cause
            // authorization checks to see an anonymous/remembered subject without a session.
            token.setRememberMe(false);

            // Intenta autenticar con Shiro
            currentUser.login(token);

            // After login, log diagnostic info. Avoid calling Subject.getSession(true)
            // because if Shiro is not using an HTTP-compatible SessionContext it throws.
            try {
                System.out.println("[Auth] Subject principal: " + currentUser.getPrincipal());
                System.out.println("[Auth] isAuthenticated: " + currentUser.isAuthenticated());
            } catch (Exception ex) {
                System.out.println("[Auth] Diagnostic logging failed: " + ex.getMessage());
            }

            // Store username in servlet session for convenience
            System.out.println("[Auth] HttpSession id (post-login): " + httpSession.getId());
            httpSession.setAttribute("username", username);
            
            redirectAttributes.addFlashAttribute("success", "¡Bienvenido, " + username + "!");
            return "redirect:/products/list";
            
        } catch (AuthenticationException e) {
            redirectAttributes.addFlashAttribute("error", "Error de autenticación: " + e.getMessage());
            return "redirect:/login";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error inesperado: " + e.getMessage());
            return "redirect:/login";
        }
    }

    /**
     * Muestra la página de registro
     */
    @GetMapping("/register")
    public String showRegisterPage() {
        Subject currentUser = SecurityUtils.getSubject();
        if (currentUser.isAuthenticated()) {
            return "redirect:/products/list";
        }
        return "register";
    }

    /**
     * Procesa el registro de un nuevo usuario
     */
    @PostMapping("/register")
    public String register(@RequestParam String username,
                          @RequestParam String password,
                          @RequestParam String passwordConfirm,
                          @RequestParam String email,
                          @RequestParam String fullName,
                          RedirectAttributes redirectAttributes) {
        try {
            // Validaciones
            if (username == null || username.trim().length() < 3) {
                redirectAttributes.addFlashAttribute("error", "El usuario debe tener al menos 3 caracteres");
                return "redirect:/register";
            }

            if (userService.userExists(username)) {
                redirectAttributes.addFlashAttribute("error", "El usuario ya existe");
                return "redirect:/register";
            }

            if (password == null || password.length() < 6) {
                redirectAttributes.addFlashAttribute("error", "La contraseña debe tener al menos 6 caracteres");
                return "redirect:/register";
            }

            if (!password.equals(passwordConfirm)) {
                redirectAttributes.addFlashAttribute("error", "Las contraseñas no coinciden");
                return "redirect:/register";
            }

            if (email == null || !email.contains("@")) {
                redirectAttributes.addFlashAttribute("error", "Email inválido");
                return "redirect:/register";
            }

            // Registrar el usuario (el rol por defecto se maneja dentro del servicio)
            userService.registerUser(username, password, email, fullName);

            redirectAttributes.addFlashAttribute("success", 
                "Registro exitoso. Bienvenido " + username + "! Inicia sesión ahora.");
            return "redirect:/login";

        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/register";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Error al registrar: " + e.getMessage());
            return "redirect:/register";
        }
    }

    /**
     * Realiza el logout del usuario
     */
    @GetMapping("/logout")
    public String logout(RedirectAttributes redirectAttributes, HttpServletRequest request) {
        Subject currentUser = SecurityUtils.getSubject();
        try {
            if (currentUser.isAuthenticated()) {
                currentUser.logout();
            }
        } catch (Exception e) {
            // ignore logout exceptions but log if needed
        }

        // Also invalidate the servlet session and remove the username attribute so
        // SessionSubjectFilter cannot recreate an authenticated Subject from it.
        try {
            var session = request.getSession(false);
            if (session != null) {
                session.removeAttribute("username");
                session.invalidate();
            }
        } catch (Exception e) {
            // ignore
        }

        redirectAttributes.addFlashAttribute("success", "Sesión cerrada correctamente");
        return "redirect:/login";
    }

    /**
     * Página de error cuando el usuario no tiene permisos
     */
    @GetMapping("/error")
    public String showErrorPage() {
        return "error";
    }

    /**
     * Convierte el nombre del algoritmo a enum
     */
    private PasswordHashingUtil.HashingAlgorithm getAlgorithmFromString(String algorithmName) {
        for (PasswordHashingUtil.HashingAlgorithm algorithm : PasswordHashingUtil.HashingAlgorithm.values()) {
            if (algorithm.getDisplayName().equalsIgnoreCase(algorithmName)) {
                return algorithm;
            }
        }
        return PasswordHashingUtil.HashingAlgorithm.BCRYPT;
    }
}
