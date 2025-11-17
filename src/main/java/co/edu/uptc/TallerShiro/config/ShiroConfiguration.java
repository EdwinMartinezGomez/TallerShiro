package co.edu.uptc.TallerShiro.config;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuración de Apache Shiro para la autenticación y autorización
 * Integra DatabaseRealm que usa contraseñas hasheadas en la BD
 */
@Configuration
public class ShiroConfiguration {

    /**
     * Usa DatabaseRealm que verifica contraseñas hasheadas en la base de datos
     * Este Realm verifica la contraseña ingresada contra el hash almacenado
     */
    @Bean
    public Realm realm(DatabaseRealm databaseRealm, HashedCredentialsMatcher credentialsMatcher) {
        databaseRealm.setCredentialsMatcher(credentialsMatcher);
        return databaseRealm;
    }

    /**
     * Configura el SecurityManager de Shiro
     */
    @Bean
    public SecurityManager securityManager(Realm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        // Use the servlet container session manager so Shiro sessions map to JSESSIONID
        securityManager.setSessionManager(new ServletContainerSessionManager());
        // Bind to SecurityUtils so static accessors (SecurityUtils.getSubject()) work
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }

    /**
     * Configura los filtros de seguridad de Shiro
     * Define qué rutas están protegidas y qué roles se requieren
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        filterFactoryBean.setSecurityManager(securityManager);

        // Define las rutas protegidas y sus filtros
        Map<String, String> filterChainDefinitionMap = new HashMap<>();
        
        // Rutas públicas - acceso sin autenticación
        filterChainDefinitionMap.put("/", "anon");
        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/css/**", "anon");
        filterChainDefinitionMap.put("/js/**", "anon");
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/register", "anon");
        filterChainDefinitionMap.put("/h2-console/**", "anon");
        
        // Rutas protegidas - requieren autenticación
        filterChainDefinitionMap.put("/products/list", "authc");
        filterChainDefinitionMap.put("/products/new", "authc");
        filterChainDefinitionMap.put("/products/create", "authc");
        filterChainDefinitionMap.put("/products/edit/**", "authc");
        filterChainDefinitionMap.put("/products/delete/**", "authc");
        
        // Rutas protegidas - requieren autenticación
        filterChainDefinitionMap.put("/info/users", "authc");
        
        // Cualquier otra ruta requiere autenticación
        filterChainDefinitionMap.put("/**", "authc");
        
        filterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        
        // Configura la página de login
        filterFactoryBean.setLoginUrl("/login");
        filterFactoryBean.setSuccessUrl("/products/list");
        filterFactoryBean.setUnauthorizedUrl("/error");
        
        return filterFactoryBean;
    }
}
