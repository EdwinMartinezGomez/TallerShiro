package co.edu.uptc.TallerShiro.services.impl;

import co.edu.uptc.TallerShiro.model.User;
import co.edu.uptc.TallerShiro.repository.UserRepository;
import co.edu.uptc.TallerShiro.services.UserService;
import co.edu.uptc.TallerShiro.util.PasswordHashingUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Implementación del servicio de usuarios con autenticación segura
 */
@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    // Algoritmo de hashing a usar por defecto
    private static final PasswordHashingUtil.HashingAlgorithm DEFAULT_ALGORITHM = 
        PasswordHashingUtil.HashingAlgorithm.BCRYPT;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User registerUser(String username, String password, String email, String fullName) {
        // Validar que el usuario no exista
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("El usuario ya existe: " + username);
        }

        // Validar contraseña
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("La contraseña debe tener al menos 6 caracteres");
        }

        // Hashear la contraseña
        PasswordHashingUtil.PasswordHash passwordHash = 
            PasswordHashingUtil.hashPassword(password, DEFAULT_ALGORITHM);

        // Crear y guardar el usuario
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordHash.getHash());
        user.setHashAlgorithm(DEFAULT_ALGORITHM.getDisplayName());
        user.setEmail(email);
        user.setFullName(fullName);
        user.setActive(true);
        // no roles field anymore
        user.setActive(true);

        return userRepository.save(user);
    }

    @Override
    public boolean authenticateUser(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return false;
        }

        User user = userOpt.get();

        // Verificar que el usuario esté activo
        if (!user.isActive()) {
            return false;
        }

        // Obtener el algoritmo usado
        PasswordHashingUtil.HashingAlgorithm algorithm = getAlgorithmFromString(user.getHashAlgorithm());

        // Verificar la contraseña
        return PasswordHashingUtil.verifyPassword(password, user.getPasswordHash(), algorithm);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public void updatePassword(Long userId, String newPassword) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        if (newPassword == null || newPassword.length() < 6) {
            throw new IllegalArgumentException("La contraseña debe tener al menos 6 caracteres");
        }

        PasswordHashingUtil.PasswordHash passwordHash = 
            PasswordHashingUtil.hashPassword(newPassword, DEFAULT_ALGORITHM);

        user.setPasswordHash(passwordHash.getHash());
        user.setHashAlgorithm(DEFAULT_ALGORITHM.getDisplayName());

        userRepository.save(user);
    }

    @Override
    public boolean userExists(String username) {
        return userRepository.existsByUsername(username);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
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
        return DEFAULT_ALGORITHM;
    }
}
