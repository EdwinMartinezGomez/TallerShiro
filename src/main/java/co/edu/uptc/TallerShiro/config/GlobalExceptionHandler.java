package co.edu.uptc.TallerShiro.config;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Manejador global para limpiar logs y respuestas cuando Shiro lanza excepciones de autorización.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(UnauthenticatedException.class)
    public String handleUnauthenticated(UnauthenticatedException ex, HttpServletRequest request, RedirectAttributes redirectAttributes) {
        // Registro conciso
        logger.warn("[Shiro] Unauthenticated request to {}: {}", request.getRequestURI(), ex.getMessage());
        // Redirigir al login con mensaje corto
        redirectAttributes.addFlashAttribute("error", "Debe iniciar sesión para acceder a esa página.");
        return "redirect:/login";
    }

    @ExceptionHandler(AuthorizationException.class)
    public String handleAuthorization(AuthorizationException ex, HttpServletRequest request, Model model) {
        Object principal = null;
        try {
            principal = SecurityUtils.getSubject().getPrincipal();
        } catch (Exception ignored) {
        }

        logger.warn("[Shiro] Access denied to {} for principal={}: {}", request.getRequestURI(), principal, ex.getMessage());

        // Pasar mensaje conciso a la vista de error
        model.addAttribute("errorMessage", "No tiene permisos para acceder a esta página.");
        return "error";
    }
}
