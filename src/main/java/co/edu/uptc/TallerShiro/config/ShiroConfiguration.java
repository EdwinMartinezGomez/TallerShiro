package co.edu.uptc.TallerShiro.config;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
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
        // Registrar solo el Realm de base de datos (usa hashes y la tabla users creada por DataInitializer)
        securityManager.setRealm(realm);
        // Use the servlet container session manager so Shiro sessions map to the servlet HttpSession (JSESSIONID)
        securityManager.setSessionManager(new ServletContainerSessionManager());
        // Bind to SecurityUtils so static accessors (SecurityUtils.getSubject()) work
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }

    /**
     * Crea un IniRealm que cargue `classpath:shiro.ini` para usuarios/roles/permiso declarados en el archivo.
     * Este realm es conveniente para demos o cuando quieres definir roles/permiso en configuración.
     */


    /**
     * Configura los filtros de seguridad de Shiro
     * Define qué rutas están protegidas y qué roles se requieren
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        filterFactoryBean.setSecurityManager(securityManager);

        // Define las rutas protegidas y sus filtros
        // Use LinkedHashMap to preserve insertion order so specific rules are applied before /**
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        
        // Rutas públicas - acceso sin autenticación
        filterChainDefinitionMap.put("/", "anon");
        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/css/**", "anon");
        filterChainDefinitionMap.put("/js/**", "anon");
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/register", "anon");
        filterChainDefinitionMap.put("/h2-console/**", "anon");
        // Debug endpoints (public) to inspect Subject/session during troubleshooting
        filterChainDefinitionMap.put("/debug/**", "anon");
        
        // Rutas protegidas - requieren autenticación y luego permisos/roles
        filterChainDefinitionMap.put("/products/list", "authc, perms[product:read]");
        filterChainDefinitionMap.put("/products/", "authc, perms[product:read]");
        filterChainDefinitionMap.put("/products/*", "authc, perms[product:read]");
        filterChainDefinitionMap.put("/products/new", "authc, perms[product:create]");
        // El path /products se usa para POST (crear). Requerimos autenticación y el método POST será
        // verificado por la anotación @RequiresPermissions en el controlador.
        filterChainDefinitionMap.put("/products", "authc");
        filterChainDefinitionMap.put("/products/edit/**", "authc, perms[product:update]");
        filterChainDefinitionMap.put("/products/delete/**", "authc, perms[product:delete]");

        // Info endpoints
        filterChainDefinitionMap.put("/info/users", "authc, roles[admin]");
        filterChainDefinitionMap.put("/info/session", "authc, perms[session:view]");
        
        // Cualquier otra ruta requiere autenticación
        filterChainDefinitionMap.put("/**", "authc");
        
        filterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        
        // Configura la página de login
        filterFactoryBean.setLoginUrl("/login");
        filterFactoryBean.setSuccessUrl("/products/list");
        filterFactoryBean.setUnauthorizedUrl("/error");
        
        return filterFactoryBean;
    }

    

    /**
     * Habilita soporte para las anotaciones @RequiresRoles y @RequiresPermissions
     */
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }

    /**
     * Lifecycle processor para Shiro, necesario para inicializar/destroy beans correctamente
     * y asegurar que la creación de proxies para las anotaciones funcione en el orden correcto.
     */
    @Bean
    public static LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }
}
