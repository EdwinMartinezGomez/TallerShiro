package co.edu.uptc.TallerShiro.services;

import co.edu.uptc.TallerShiro.model.User;

import java.util.Optional;

/**
 * Servicio para gestión de usuarios
 * Maneja autenticación y creación de usuarios con hashing seguro
 */
public interface UserService {
    /**
     * Registra un nuevo usuario
     */
    User registerUser(String username, String password, String email, String fullName);

    /**
     * Autentica un usuario
     */
    boolean authenticateUser(String username, String password);

    /**
     * Obtiene un usuario por nombre
     */
    Optional<User> findByUsername(String username);

    /**
     * Obtiene un usuario por id
     */
    Optional<User> findById(Long id);

    /**
     * Actualiza contraseña de un usuario
     */
    void updatePassword(Long userId, String newPassword);

    /**
     * Verifica si un usuario existe
     */
    boolean userExists(String username);

    /**
     * Obtiene todos los usuarios
     */
    java.util.List<User> getAllUsers();

    /**
     * Elimina un usuario
     */
    void deleteUser(Long userId);
}
