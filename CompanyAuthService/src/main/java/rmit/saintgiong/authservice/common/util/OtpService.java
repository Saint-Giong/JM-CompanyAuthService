package rmit.saintgiong.authservice.common.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Service for generating, storing, and verifying OTPs (One-Time Passwords).
 * OTPs are stored in Redis with a configurable TTL (default: 2 minutes).
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class OtpService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String OTP_PREFIX = "otp:";
    private static final int OTP_LENGTH = 6;
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * -- GETTER --
     *  Gets the configured OTP TTL in seconds.
     *
     * @return The OTP TTL in seconds
     */
    @Getter
    @Value("${otp.ttl-seconds:120}")  // Default: 2 minutes
    private long otpTtlSeconds;

    /**
     * Generates a random 6-digit OTP for the given company ID.
     * The OTP is stored in Redis with a TTL of 2 minutes.
     *
     * @param companyId The company ID to associate with the OTP
     * @return The generated 6-digit OTP
     */
    public String generateOtp(UUID companyId) {
        // Generate a random 6-digit OTP
        String otp = generateRandomOtp();
        
        // Store OTP in Redis with TTL
        String key = OTP_PREFIX + companyId.toString();
        redisTemplate.opsForValue().set(key, otp, otpTtlSeconds, TimeUnit.SECONDS);
        
        log.debug("Generated OTP for company {}: {} (expires in {} seconds)", companyId, otp, otpTtlSeconds);
        return otp;
    }

    /**
     * Verifies the provided OTP against the stored OTP for the given company ID.
     *
     * @param companyId The company ID
     * @param otp       The OTP to verify
     * @return true if the OTP matches and is valid, false otherwise
     */
    public boolean verifyOtp(UUID companyId, String otp) {
        String key = OTP_PREFIX + companyId.toString();
        String storedOtp = redisTemplate.opsForValue().get(key);
        
        if (storedOtp == null) {
            log.debug("No OTP found for company {} (expired or not generated)", companyId);
            return false;
        }
        
        boolean isValid = storedOtp.equals(otp);
        if (isValid) {
            // Consume the OTP after successful verification
            redisTemplate.delete(key);
            log.debug("OTP verified successfully for company {}", companyId);
        } else {
            log.debug("Invalid OTP provided for company {}", companyId);
        }
        
        return isValid;
    }

    /**
     * Verifies the provided OTP against the stored OTP for the given company ID.
     *
     * @param companyId The company ID
     * @return The new generated 6-digit OTP
     */
    public String invalidateExistingAndGenerateNewOtp(UUID companyId) {

        //Invalidate
        String key = OTP_PREFIX + companyId.toString();
        redisTemplate.delete(key);
        log.debug("Invalidated OTP for company {}", companyId);


        //Generate new OTP
        String otp = generateRandomOtp();
        redisTemplate.opsForValue().set(key, otp, otpTtlSeconds, TimeUnit.SECONDS);
        log.debug("Generated OTP for company {}: {} (expires in {} seconds)", companyId, otp, otpTtlSeconds);

        return otp;
    }



    //Generate 6 digit random OTP
    private String generateRandomOtp() {
        int otp = secureRandom.nextInt(900000) + 100000; // Generates number between 100000 and 999999
        return String.valueOf(otp);
    }
}
