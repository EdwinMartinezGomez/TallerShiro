package co.edu.uptc.TallerShiro.config;

import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * Configuración alternativa de Shiro usando JdbcRealm
 * Esta clase proporciona un bean de JdbcRealm que puede usarse en lugar de IniRealm
 * 
 * Para activar JdbcRealm, modifica ShiroConfiguration para usar este bean
 */
@Configuration
public class JdbcRealmConfiguration {

    /**
     * Configura un JdbcRealm que obtiene usuarios y roles de la base de datos
     * 
     * Requiere las siguientes tablas en la base de datos:
     * 
     * CREATE TABLE users (
     *     id INT PRIMARY KEY AUTO_INCREMENT,
     *     username VARCHAR(255) UNIQUE NOT NULL,
     *     password VARCHAR(255) NOT NULL
     * );
     * 
     * CREATE TABLE user_roles (
     *     id INT PRIMARY KEY AUTO_INCREMENT,
     *     username VARCHAR(255),
     *     role_name VARCHAR(255),
     *     FOREIGN KEY (username) REFERENCES users(username)
     * );
     * 
     * CREATE TABLE roles_permissions (
     *     id INT PRIMARY KEY AUTO_INCREMENT,
     *     role_name VARCHAR(255),
     *     permission VARCHAR(255)
     * );
     */
    @Bean
    @ConditionalOnProperty(
        name = "shiro.realm.type",
        havingValue = "jdbc"
    )
    public JdbcRealm jdbcRealm(DataSource dataSource) {
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(dataSource);
        
        // Consultas SQL personalizadas para obtener usuarios y roles
        // Estas son las consultas por defecto de JdbcRealm
        jdbcRealm.setAuthenticationQuery("SELECT password FROM users WHERE username = ?");
        jdbcRealm.setUserRolesQuery("SELECT role_name FROM user_roles WHERE username = ?");
        jdbcRealm.setPermissionsQuery("SELECT permission FROM roles_permissions WHERE role_name = ?");
        
        // Habilita búsqueda de permisos
        jdbcRealm.setPermissionsLookupEnabled(true);
        
        return jdbcRealm;
    }
}
