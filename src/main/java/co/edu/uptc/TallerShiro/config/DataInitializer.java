package co.edu.uptc.TallerShiro.config;

import co.edu.uptc.TallerShiro.model.User;
import co.edu.uptc.TallerShiro.repository.UserRepository;
import co.edu.uptc.TallerShiro.util.PasswordHashingUtil;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Inicializador de base de datos con usuarios de prueba
 * Crea usuarios con contraseñas hasheadas seguras
 */
@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initializeData(UserRepository userRepository) {
        return args -> {
            // Verificar si ya existen usuarios
            if (userRepository.count() > 0) {
                return; // No inicializar si ya hay datos
            }

            // Data initializer: creating sample users (no console debug prints)

            // Usuario 1: Admin
            User admin = new User();
            admin.setUsername("admin");
            PasswordHashingUtil.PasswordHash adminHash = PasswordHashingUtil.hashPassword(
                "admin123", 
                PasswordHashingUtil.HashingAlgorithm.BCRYPT
            );
            admin.setPasswordHash(adminHash.getHash());
            admin.setHashAlgorithm(adminHash.getAlgorithm().getDisplayName());
            // no roles
            admin.setEmail("admin@tallershiro.com");
            admin.setFullName("Administrador del Sistema");
            admin.setRole("admin");
            admin.setActive(true);
            userRepository.save(admin);
            printUserInfo("admin", "admin123", adminHash);

            // Usuario 2: Vendedor
            User vendedor = new User();
            vendedor.setUsername("vendedor");
            PasswordHashingUtil.PasswordHash vendedorHash = PasswordHashingUtil.hashPassword(
                "vendedor123", 
                PasswordHashingUtil.HashingAlgorithm.BCRYPT
            );
            vendedor.setPasswordHash(vendedorHash.getHash());
            vendedor.setHashAlgorithm(vendedorHash.getAlgorithm().getDisplayName());
            // no roles
            vendedor.setEmail("vendedor@tallershiro.com");
            vendedor.setFullName("Juan Vendedor García");
            vendedor.setRole("seller");
            vendedor.setActive(true);
            userRepository.save(vendedor);
            printUserInfo("vendedor", "vendedor123", vendedorHash);

            // Usuario 3: Usuario normal
            User user1 = new User();
            user1.setUsername("user1");
            PasswordHashingUtil.PasswordHash user1Hash = PasswordHashingUtil.hashPassword(
                "password123", 
                PasswordHashingUtil.HashingAlgorithm.BCRYPT
            );
            user1.setPasswordHash(user1Hash.getHash());
            user1.setHashAlgorithm(user1Hash.getAlgorithm().getDisplayName());
            // no roles
            user1.setEmail("user1@tallershiro.com");
            user1.setFullName("María Usuario Rodríguez");
            user1.setRole("user");
            user1.setActive(true);
            userRepository.save(user1);
            printUserInfo("user1", "password123", user1Hash);

            // Usuario 4: Otro usuario
            User user2 = new User();
            user2.setUsername("user2");
            PasswordHashingUtil.PasswordHash user2Hash = PasswordHashingUtil.hashPassword(
                "password456", 
                PasswordHashingUtil.HashingAlgorithm.BCRYPT
            );
            user2.setPasswordHash(user2Hash.getHash());
            user2.setHashAlgorithm(user2Hash.getAlgorithm().getDisplayName());
            // no roles
            user2.setEmail("user2@tallershiro.com");
            user2.setFullName("Carlos Usuario López");
            user2.setRole("user");
            user2.setActive(true);
            userRepository.save(user2);
            printUserInfo("user2", "password456", user2Hash);

            // Initialization complete
        };
    }

    /**
     * Imprime la información del usuario creado
     */
    private void printUserInfo(String username, String password, PasswordHashingUtil.PasswordHash hash) {
        System.out.println();
        System.out.println("👤 Usuario: " + username);
        System.out.println("🔑 Contraseña: " + password);
        System.out.println("🔐 Algoritmo: " + hash.getAlgorithm().getDisplayName());
        System.out.println("📝 Hash: " + hash.getHash());
        System.out.println("📏 Longitud del hash: " + hash.getHash().length() + " caracteres");
        
        // Verificar que el hash es válido
        boolean isValid = PasswordHashingUtil.verifyPassword(
            password, 
            hash.getHash(), 
            hash.getAlgorithm()
        );
        System.out.println("✓ Verificación: " + (isValid ? "✅ EXITOSA" : "❌ FALLIDA"));
    }
}
