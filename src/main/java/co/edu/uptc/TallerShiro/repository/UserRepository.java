package co.edu.uptc.TallerShiro.repository;

import co.edu.uptc.TallerShiro.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repositorio para la entidad User
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Busca un usuario por su nombre de usuario
     */
    Optional<User> findByUsername(String username);

    /**
     * Busca un usuario por su email
     */
    Optional<User> findByEmail(String email);

    /**
     * Verifica si un usuario existe
     */
    boolean existsByUsername(String username);
}
