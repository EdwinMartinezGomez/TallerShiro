package co.edu.uptc.TallerShiro.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.ThreadContext;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Filter that binds a Shiro Subject to the current thread based on a "username"
 * attribute stored in the servlet HttpSession. This helps authorization checks
 * (annotations like @RequiresPermissions) find an identity when the Shiro web
 * filter is not available or when the Subject wasn't persisted automatically.
 */
@Component
@Order(1)
public class SessionSubjectFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpSession session = req.getSession(false);

        Subject bound = null;
        try {
            Subject current = SecurityUtils.getSubject();
            boolean needsBind = (current == null || current.getPrincipal() == null || !current.isAuthenticated());
            if (needsBind && session != null) {
                Object usernameObj = session.getAttribute("username");
                if (usernameObj instanceof String) {
                    String username = (String) usernameObj;
                    SimplePrincipalCollection principals = new SimplePrincipalCollection(username, "DatabaseRealm");
                    Subject subject = new Subject.Builder(SecurityUtils.getSecurityManager())
                            .principals(principals)
                            .authenticated(true)
                            .buildSubject();
                    ThreadContext.bind(subject);
                    bound = subject;
                }
            }

            chain.doFilter(request, response);
        } finally {
            if (bound != null) {
                ThreadContext.unbindSubject();
            }
        }
    }
}
