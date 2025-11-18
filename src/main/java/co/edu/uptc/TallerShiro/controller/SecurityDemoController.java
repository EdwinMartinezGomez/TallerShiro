package co.edu.uptc.TallerShiro.controller;

import co.edu.uptc.TallerShiro.util.PasswordHashingUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class SecurityDemoController {

    @GetMapping("/security/hash/compare")
    public Map<String, Object> compare(@RequestParam(required = false, defaultValue = "password123") String pwd) {
        Map<String, Object> result = new HashMap<>();
        result.put("comparisonReport", PasswordHashingUtil.compareWeakVsStrong(pwd));

        // Also return timings individually for client use
        long bcrypt10 = PasswordHashingUtil.measureHashTimeMillis(pwd, PasswordHashingUtil.HashingAlgorithm.BCRYPT, 10);
        long bcrypt14 = PasswordHashingUtil.measureHashTimeMillis(pwd, PasswordHashingUtil.HashingAlgorithm.BCRYPT, 14);
        long argonLow = PasswordHashingUtil.measureHashTimeMillis(pwd, PasswordHashingUtil.HashingAlgorithm.ARGON2, 2, 65536, 1);
        long argonHigh = PasswordHashingUtil.measureHashTimeMillis(pwd, PasswordHashingUtil.HashingAlgorithm.ARGON2, 3, 131072, 1);

        result.put("bcrypt_cost_10_ms", bcrypt10);
        result.put("bcrypt_cost_14_ms", bcrypt14);
        result.put("argon2_low_ms", argonLow);
        result.put("argon2_high_ms", argonHigh);
        return result;
    }
}
