package co.edu.uptc.TallerShiro.util;

import at.favre.lib.crypto.bcrypt.BCrypt;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Utilidad para hashing seguro de contraseñas
 * Soporta múltiples algoritmos: BCrypt, Argon2, PBKDF2, SHA-512
 */
public class PasswordHashingUtil {

    // Enum para elegir el algoritmo de hashing
    public enum HashingAlgorithm {
        BCRYPT("BCrypt"),
        ARGON2("Argon2"),
        SPRING_BCRYPT("Spring BCrypt"),
        SHA512_SALTED("SHA-512 Salteado");

        private final String displayName;

        HashingAlgorithm(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Hashea una contraseña usando BCrypt (favre.lib)
     * Algoritmo moderno y seguro, recomendado para aplicaciones nuevas
     * 
     * @param password contraseña en texto plano
     * @return hash de la contraseña en formato string
     */
    public static String hashWithBCrypt(String password) {
        return hashWithBCrypt(password, 12);
    }

    /**
     * BCrypt with configurable cost (log rounds)
     */
    public static String hashWithBCrypt(String password, int cost) {
        byte[] hashedPassword = BCrypt.withDefaults().hash(cost, password.toCharArray());
        return new String(hashedPassword);
    }

    /**
     * Verifica una contraseña contra su hash BCrypt
     * 
     * @param password contraseña en texto plano
     * @param hashedPassword hash almacenado
     * @return true si la contraseña es correcta, false si no
     */
    public static boolean verifyBCrypt(String password, String hashedPassword) {
        return BCrypt.verifyer().verify(password.toCharArray(), hashedPassword.getBytes()).verified;
    }

    /**
     * Hashea una contraseña usando Argon2
     * Algoritmo muy seguro, ganador de Password Hashing Competition
     * Más lento que BCrypt pero más resistente a ataques
     * 
     * @param password contraseña en texto plano
     * @return hash de la contraseña
     */
    public static String hashWithArgon2(String password) {
        // default recommended parameters
        return hashWithArgon2(password, 2, 65536, 1);
    }

    /**
     * Argon2 with configurable iterations, memory (KB) and parallelism
     */
    public static String hashWithArgon2(String password, int iterations, int memoryKb, int parallelism) {
        Argon2 argon2 = Argon2Factory.create();
        return argon2.hash(iterations, memoryKb, parallelism, password.toCharArray());
    }

    /**
     * Verifica una contraseña contra su hash Argon2
     * 
     * @param password contraseña en texto plano
     * @param hashedPassword hash almacenado
     * @return true si la contraseña es correcta, false si no
     */
    public static boolean verifyArgon2(String password, String hashedPassword) {
        Argon2 argon2 = Argon2Factory.create();
        try {
            return argon2.verify(hashedPassword, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }

    /**
     * Hashea una contraseña usando Spring Security BCrypt
     * Versión integrada de Spring Framework
     * 
     * @param password contraseña en texto plano
     * @return hash de la contraseña
     */
    public static String hashWithSpringBCrypt(String password) {
        return hashWithSpringBCrypt(password, 12);
    }

    public static String hashWithSpringBCrypt(String password, int strength) {
        PasswordEncoder encoder = new BCryptPasswordEncoder(strength);
        return encoder.encode(password);
    }

    /**
     * Verifica una contraseña contra su hash Spring BCrypt
     * 
     * @param password contraseña en texto plano
     * @param hashedPassword hash almacenado
     * @return true si la contraseña es correcta, false si no
     */
    public static boolean verifySpringBCrypt(String password, String hashedPassword) {
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(password, hashedPassword);
    }

    /**
     * Hashea una contraseña usando SHA-512 con salt
     * Algoritmo más antiguo pero aún aceptable con suficientes iteraciones
     * 
     * @param password contraseña en texto plano
     * @param salt salt para la contraseña (se genera automáticamente si es null)
     * @return hash en formato "salt:hash"
     */
    public static String hashWithSHA512Salted(String password, String salt) {
        if (salt == null) {
            salt = generateSalt();
        }
        
        String hash = hashSHA512(password + salt);
        return salt + ":" + hash;
    }

    /**
     * Verifica una contraseña contra su hash SHA-512 salteado
     * 
     * @param password contraseña en texto plano
     * @param hashedPassword hash almacenado en formato "salt:hash"
     * @return true si la contraseña es correcta, false si no
     */
    public static boolean verifySHA512Salted(String password, String hashedPassword) {
        String[] parts = hashedPassword.split(":");
        if (parts.length != 2) {
            return false;
        }
        
        String salt = parts[0];
        String hash = parts[1];
        String computedHash = hashSHA512(password + salt);
        
        return hash.equals(computedHash);
    }

    /**
     * Genera un hash SHA-512
     * 
     * @param input texto a hashear
     * @return hash SHA-512
     */
    private static String hashSHA512(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-512");
            byte[] digest = md.digest(input.getBytes());
            return bytesToHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512 no disponible", e);
        }
    }

    /**
     * Genera un salt aleatorio
     * 
     * @return salt en formato hexadecimal
     */
    private static String generateSalt() {
        byte[] salt = new byte[16];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(salt);
        return bytesToHex(salt);
    }

    /**
     * Convierte un array de bytes a string hexadecimal
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Hashea una contraseña con el algoritmo especificado
     * 
     * @param password contraseña en texto plano
     * @param algorithm algoritmo a usar
     * @return objeto con el hash y información del algoritmo
     */
    public static PasswordHash hashPassword(String password, HashingAlgorithm algorithm) {
        String hash;
        
        switch (algorithm) {
            case BCRYPT:
                hash = hashWithBCrypt(password);
                break;
            case ARGON2:
                hash = hashWithArgon2(password);
                break;
            case SPRING_BCRYPT:
                hash = hashWithSpringBCrypt(password);
                break;
            case SHA512_SALTED:
                hash = hashWithSHA512Salted(password, null);
                break;
            default:
                throw new IllegalArgumentException("Algoritmo no soportado: " + algorithm);
        }
        
        return new PasswordHash(hash, algorithm);
    }

    /**
     * Measures how long (milliseconds) it takes to hash the given password
     * using the specified algorithm and parameters. Useful to compare weak vs strong.
     */
    public static long measureHashTimeMillis(String password, HashingAlgorithm algorithm, Object... params) {
        long start = System.nanoTime();
        switch (algorithm) {
            case BCRYPT:
                int cost = params.length > 0 && params[0] instanceof Integer ? (Integer) params[0] : 12;
                hashWithBCrypt(password, cost);
                break;
            case ARGON2:
                int iterations = params.length > 0 && params[0] instanceof Integer ? (Integer) params[0] : 2;
                int memoryKb = params.length > 1 && params[1] instanceof Integer ? (Integer) params[1] : 65536;
                int parallelism = params.length > 2 && params[2] instanceof Integer ? (Integer) params[2] : 1;
                hashWithArgon2(password, iterations, memoryKb, parallelism);
                break;
            case SPRING_BCRYPT:
                int strength = params.length > 0 && params[0] instanceof Integer ? (Integer) params[0] : 12;
                hashWithSpringBCrypt(password, strength);
                break;
            case SHA512_SALTED:
                hashWithSHA512Salted(password, null);
                break;
            default:
                throw new IllegalArgumentException("Algoritmo no soportado: " + algorithm);
        }
        long end = System.nanoTime();
        return (end - start) / 1_000_000;
    }

    /**
     * Compare a weak and a strong hashing configuration and return a short report.
     */
    public static String compareWeakVsStrong(String password) {
        // Weak: SHA-512 salted (fast)
        long weakMs = measureHashTimeMillis(password, HashingAlgorithm.SHA512_SALTED);

        // Strong: Argon2 moderate params
        long strongMs = measureHashTimeMillis(password, HashingAlgorithm.ARGON2, 3, 131072, 1);

        StringBuilder sb = new StringBuilder();
        sb.append("Weak (SHA-512 salted) time: ").append(weakMs).append(" ms\n");
        sb.append("Strong (Argon2: iter=3, mem=128MB) time: ").append(strongMs).append(" ms\n");
        sb.append("Recommendation: use Argon2 or bcrypt with high cost for production.\n");
        return sb.toString();
    }

    /**
     * Verifica una contraseña contra su hash
     * 
     * @param password contraseña en texto plano
     * @param hash hash almacenado
     * @param algorithm algoritmo a usar
     * @return true si es correcta, false si no
     */
    public static boolean verifyPassword(String password, String hash, HashingAlgorithm algorithm) {
        switch (algorithm) {
            case BCRYPT:
                return verifyBCrypt(password, hash);
            case ARGON2:
                return verifyArgon2(password, hash);
            case SPRING_BCRYPT:
                return verifySpringBCrypt(password, hash);
            case SHA512_SALTED:
                return verifySHA512Salted(password, hash);
            default:
                throw new IllegalArgumentException("Algoritmo no soportado: " + algorithm);
        }
    }

    /**
     * Clase que encapsula un hash de contraseña con su algoritmo
     */
    public static class PasswordHash {
        private final String hash;
        private final HashingAlgorithm algorithm;

        public PasswordHash(String hash, HashingAlgorithm algorithm) {
            this.hash = hash;
            this.algorithm = algorithm;
        }

        public String getHash() {
            return hash;
        }

        public HashingAlgorithm getAlgorithm() {
            return algorithm;
        }

        @Override
        public String toString() {
            return "PasswordHash{" +
                    "algorithm=" + algorithm.getDisplayName() +
                    ", hash='" + hash + '\'' +
                    '}';
        }
    }
}
