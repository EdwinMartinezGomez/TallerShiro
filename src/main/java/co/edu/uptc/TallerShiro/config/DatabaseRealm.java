package co.edu.uptc.TallerShiro.config;

import co.edu.uptc.TallerShiro.model.User;
import co.edu.uptc.TallerShiro.repository.UserRepository;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Realm personalizado para Shiro que usa la base de datos de la aplicación
 * Maneja autenticación con contraseñas hasheadas
 */
@Component
public class DatabaseRealm extends AuthorizingRealm {

    private final UserRepository userRepository;

    public DatabaseRealm(UserRepository userRepository) {
        this.userRepository = userRepository;
        setName("DatabaseRealm");
    }

    /**
     * Obtiene la información de autorización (roles y permisos) del usuario
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // Obtener el username del subject autenticado
        String username = (String) principals.getPrimaryPrincipal();

        // Buscar el usuario en la BD
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return null;
        }


        // Crear la información de autorización
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        // Definición de roles y permisos (simple mapeo en memoria para la demo)
        // Roles: admin, seller, user
        // Permisos: product:create, product:read, product:update, product:delete, user:view, user:manage, session:view

        // Mapear usuarios a roles (tomando el rol guardado en la entidad User si existe)
        Set<String> userRoles = new HashSet<>();
        String roleFromDb = null;
        try {
            roleFromDb = userOpt.get().getRole();
        } catch (Exception ignored) {
        }

        if (roleFromDb != null && !roleFromDb.isBlank()) {
            userRoles.add(roleFromDb.toLowerCase());
        } else {
            // Fallback: heurística por username
            if ("admin".equalsIgnoreCase(username)) {
                userRoles.add("admin");
            } else if ("vendedor".equalsIgnoreCase(username) || "seller".equalsIgnoreCase(username)) {
                userRoles.add("seller");
            } else {
                userRoles.add("user");
            }
        }

        // Asignar roles
        info.setRoles(userRoles);

        // Mapear roles a permisos
        Set<String> permissions = new HashSet<>();
        for (String role : userRoles) {
            switch (role) {
                case "admin":
                    permissions.add("product:create");
                    permissions.add("product:read");
                    permissions.add("product:update");
                    permissions.add("product:delete");
                    permissions.add("user:view");
                    permissions.add("user:manage");
                    permissions.add("session:view");
                    break;
                case "seller":
                    permissions.add("product:create");
                    permissions.add("product:read");
                    permissions.add("product:update");
                    permissions.add("session:view");
                    break;
                case "user":
                    permissions.add("product:read");
                    permissions.add("session:view");
                    break;
                default:
                    break;
            }
        }

        info.setStringPermissions(permissions);

        return info;
    }

    /**
     * Autentica el usuario (verifica username y password)
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();

        // Buscar el usuario en la BD
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new UnknownAccountException("Usuario no encontrado: " + username);
        }

        User user = userOpt.get();

        // Verificar que el usuario esté activo
        if (!user.isActive()) {
            throw new DisabledAccountException("Usuario desactivado: " + username);
        }

        // Obtener la contraseña de la BD
        String passwordHash = user.getPasswordHash();

        // Retornar la información de autenticación con el hash
        SimpleAuthenticationInfo authInfo = new SimpleAuthenticationInfo(
            username,           // principal (identificador del usuario)
            passwordHash,       // credentials (contraseña hasheada)
            getName()           // realm name
        );

        return authInfo;
    }

    /**
     * Retorna el matcher de credenciales que verifica la contraseña hasheada
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }


    
}
