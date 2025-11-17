package co.edu.uptc.TallerShiro.config;

import co.edu.uptc.TallerShiro.repository.UserRepository;
import co.edu.uptc.TallerShiro.util.PasswordHashingUtil;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.springframework.stereotype.Component;

/**
 * Verificador personalizado de credenciales para Shiro
 * Compara la contraseña ingresada con el hash almacenado en BD
 */
@Component
public class HashedCredentialsMatcher implements CredentialsMatcher {

    private final UserRepository userRepository;

    public HashedCredentialsMatcher(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        String passwordIngresada = String.valueOf(upToken.getPassword());

        // Obtener el usuario de la BD para conocer el algoritmo usado
        boolean isPasswordValid = userRepository.findByUsername(username)
            .map(user -> {
                // Obtener el hash almacenado
                Object storedPassword = info.getCredentials();
                String storedHash = storedPassword.toString();

                // Obtener el algoritmo usado
                PasswordHashingUtil.HashingAlgorithm algorithm = 
                    getAlgorithmFromString(user.getHashAlgorithm());

                // Verificar la contraseña
                return PasswordHashingUtil.verifyPassword(passwordIngresada, storedHash, algorithm);
            })
            .orElse(false);

        return isPasswordValid;
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
