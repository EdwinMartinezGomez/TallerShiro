package co.edu.uptc.TallerShiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Enumeration;

@RestController
public class DebugController {

    @GetMapping("/debug/subject")
    public Map<String, Object> subjectInfo(HttpServletRequest request) {
        Subject subject = SecurityUtils.getSubject();
        Map<String, Object> info = new HashMap<>();
        info.put("principal", subject.getPrincipal());
        info.put("isAuthenticated", subject.isAuthenticated());
        info.put("isRemembered", subject.isRemembered());

        try {
            var session = subject.getSession(false);
            if (session != null) {
                info.put("shiroSessionId", session.getId());
                info.put("shiroSessionStart", session.getStartTimestamp());
                info.put("shiroSessionLastAccess", session.getLastAccessTime());
            } else {
                info.put("shiroSession", "<no-session>");
            }
        } catch (Exception e) {
            info.put("shiroSessionError", e.getMessage());
        }

        // Also include the servlet HttpSession id (if any) so we can compare Shiro session
        // and servlet session ids and check cookie propagation.
        try {
            var httpSession = request.getSession(false);
            if (httpSession != null) {
                info.put("servletSessionId", httpSession.getId());
            } else {
                info.put("servletSession", "<no-servlet-session>");
            }
        } catch (Exception e) {
            info.put("servletSessionError", e.getMessage());
        }

        // Request cookies
        Map<String, Object> cookies = new HashMap<>();
        Cookie[] cs = request.getCookies();
        if (cs != null) {
            for (Cookie c : cs) {
                cookies.put(c.getName(), c.getValue());
            }
        }
        info.put("requestCookies", cookies);

        // Request headers (a few useful ones)
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String hn = headerNames.nextElement();
            headers.put(hn, request.getHeader(hn));
        }
        info.put("requestHeaders", headers);

        return info;
    }
}
