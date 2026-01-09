package rmit.saintgiong.authservice.common.utils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.common.dto.otp.ActivationPairDto;
import rmit.saintgiong.authservice.common.exception.otp.OtpHourlyLimitExceededException;
import rmit.saintgiong.authservice.common.exception.otp.OtpResendCooldownException;
import rmit.saintgiong.authservice.common.exception.otp.OtpVerificationLockedException;
import tools.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
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
    private static final String OTP_ATTEMPTS_PREFIX = "otp:attempts:";
    private static final String OTP_RESEND_COOLDOWN_PREFIX = "otp:resend-cooldown:";
    private static final String OTP_SENT_HOURLY_PREFIX = "otp:sent-hour:";

    private static final int OTP_LENGTH = 6;
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final DateTimeFormatter HOUR_KEY_FORMATTER =
            DateTimeFormatter.ofPattern("yyyyMMddHH");

    /**
     * -- GETTER --
     *  Gets the configured OTP TTL in seconds.
     *
     * @return The OTP TTL in seconds
     */
    @Getter
    @Value("${otp.ttl-seconds:120}")  // Default: 2 minutes
    private long otpTtlSeconds;

    @Value("${otp.max-verification-attempts:5}")
    private int maxVerificationAttempts;

    @Value("${otp.resend-cooldown-seconds:60}")
    private long resendCooldownSeconds;

    @Value("${otp.max-per-hour:5}")
    private int maxOtpsPerHour;

    private final ObjectMapper objectMapper;

    /**
     * Generates a random 6-digit OTP for the given company ID.
     * Enforces hourly send limit and resend cooldown.
     * The OTP is stored in Redis with configured TTL.
     *
     * @param companyId The company ID to associate with the OTP
     * @return generated 6-digit OTP
     */
    public ActivationPairDto generateOtp(UUID companyId, String activationToken) {
        enforceHourlyLimit(companyId);
        enforceResendCooldown(companyId);

        // Generate a random 6-digit OTP
        String otp = generateRandomOtp();

        ActivationPairDto activationPairDto = new ActivationPairDto(otp, activationToken);
        String jsonString = objectMapper.writeValueAsString(activationPairDto);

        // Store OTP in Redis with TTL
        String key = OTP_PREFIX + companyId;
        redisTemplate.opsForValue().set(key, jsonString, otpTtlSeconds, TimeUnit.SECONDS);

        // Reset attempts counter for this fresh OTP
        resetVerificationAttempts(companyId);

        // Record rate limiting metadata
        incrementOtpSentPerHour(companyId);
        startResendCooldown(companyId);

        log.debug("Generated OTP for company {} (TTL {}s)", companyId, otpTtlSeconds);
        return activationPairDto;
    }

    /**
     * Verifies the provided OTP against the stored OTP for the given company ID.
     * Enforces a maximum number of attempts before lockout for the current OTP.
     *
     * @param companyId The company ID
     * @param otp       The OTP to verify
     * @return true if the OTP matches and is valid, false otherwise
     */
    public boolean verifyOtp(UUID companyId, String otp) {
        String attemptsKey = OTP_ATTEMPTS_PREFIX + companyId;

        // Check existing attempts to enforce lockout
        String attemptsStr = redisTemplate.opsForValue().get(attemptsKey);
        if (attemptsStr != null) {
            try {
                long attempts = Long.parseLong(attemptsStr);
                if (attempts >= maxVerificationAttempts) {
                    throw new OtpVerificationLockedException(
                            "Too many invalid OTP attempts. Please request a new OTP.");
                }
            } catch (NumberFormatException ignore) {
                // fall through and treat as 0 attempts
            }
        }

        // Increment attempts (first call will create the key)
        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (attempts != null && attempts == 1L) {
            // Tie attempts TTL to OTP lifetime
            redisTemplate.expire(attemptsKey, otpTtlSeconds, TimeUnit.SECONDS);
        }

        if (attempts != null && attempts > maxVerificationAttempts) {
            throw new OtpVerificationLockedException(
                    "Too many invalid OTP attempts. Please request a new OTP.");
        }

        String key = OTP_PREFIX + companyId;
        String activationPairString = redisTemplate.opsForValue().get(key);

        if (activationPairString == null) {
            // OTP expired or never issued
            log.debug("No OTP found for company {}", companyId);
            return false;
        }

        ActivationPairDto activationPairDto = objectMapper.readValue(activationPairString, ActivationPairDto.class);

        boolean isValid = activationPairDto.getOtp().equals(otp);
        if (isValid) {
            // On success, consume OTP and clear attempts
            redisTemplate.delete(key);
            redisTemplate.delete(attemptsKey);
        } else {
            log.debug("Invalid OTP provided for company {} (attempt #{})", companyId, attempts);
        }

        return isValid;
    }

    /**
     * Verifies the provided activation token against the stored token for the given company ID.
     *
     * @param companyId       The company ID
     * @param activationToken The activation token to verify
     * @return true if the token matches and is valid, false otherwise
     */
    public boolean verifyActivationToken(UUID companyId, String activationToken) {
        String key = OTP_PREFIX + companyId;
        String activationPairString = redisTemplate.opsForValue().get(key);

        if (activationPairString == null) {
            // Token expired or never issued
            log.debug("No activation token found for company {}", companyId);
            return false;
        }

        try {
            ActivationPairDto activationPairDto = objectMapper.readValue(activationPairString, ActivationPairDto.class);

            boolean isValid = activationPairDto.getActivationToken().equals(activationToken);
            if (isValid) {
                // On success, consume token and clear attempts
                redisTemplate.delete(key);
                redisTemplate.delete(OTP_ATTEMPTS_PREFIX + companyId);
            } else {
                log.debug("Invalid activation token provided for company {}", companyId);
            }

            return isValid;
        } catch (Exception e) {
            log.error("Error verifying activation token for company {}", companyId, e);
            return false;
        }
    }

    /**
     * Invalidates existing OTP (if any) and generates a new one.
     * Respects the same resend cooldown and hourly limits.
     *
     * @param companyId The company ID
     * @return The new generated 6-digit OTP
     */
    public ActivationPairDto invalidateExistingAndGenerateNewOtp(UUID companyId, String activationToken) {

        // Enforce resend rules
        enforceHourlyLimit(companyId);
        enforceResendCooldown(companyId);

        // Invalidate existing OTP + attempts
        String key = OTP_PREFIX + companyId;
        redisTemplate.delete(key);
        resetVerificationAttempts(companyId);

        // Generate a random 6-digit OTP
        String otp = generateRandomOtp();
        ActivationPairDto activationPairDto = new ActivationPairDto(otp, activationToken);
        String jsonString = objectMapper.writeValueAsString(activationPairDto);

        redisTemplate.opsForValue().set(key, jsonString, otpTtlSeconds, TimeUnit.SECONDS);

        // Record rate limiting metadata
        incrementOtpSentPerHour(companyId);
        startResendCooldown(companyId);

        return activationPairDto;
    }

    // Rate limiting helpers

    private void enforceResendCooldown(UUID companyId) {
        String key = OTP_RESEND_COOLDOWN_PREFIX + companyId;
        Boolean exists = redisTemplate.hasKey(key);
        if (Boolean.TRUE.equals(exists)) {
            throw new OtpResendCooldownException(
                    "Please wait before requesting another OTP.");
        }
    }

    private void startResendCooldown(UUID companyId) {
        String key = OTP_RESEND_COOLDOWN_PREFIX + companyId;
        // set only if absent, with expiry
        redisTemplate.opsForValue().setIfAbsent(
                key,
                "1",
                resendCooldownSeconds,
                TimeUnit.SECONDS
        );
    }

    private void enforceHourlyLimit(UUID companyId) {
        String key = buildHourlyKey(companyId);
        String countStr = redisTemplate.opsForValue().get(key);
        if (countStr == null) {
            return;
        }
        try {
            long count = Long.parseLong(countStr);
            if (count >= maxOtpsPerHour) {
                throw new OtpHourlyLimitExceededException(
                        "Maximum number of OTPs per hour exceeded. Please try again later.");
            }
        } catch (NumberFormatException ignore) {
            // ignore bad value and allow
        }
    }

    private void incrementOtpSentPerHour(UUID companyId) {
        String key = buildHourlyKey(companyId);
        Long value = redisTemplate.opsForValue().increment(key);
        if (value != null && value == 1L) {
            // first OTP in this hour: expire at the end of the current UTC hour
            long secondsLeftInHour = secondsUntilNextHour();
            redisTemplate.expire(key, secondsLeftInHour, TimeUnit.SECONDS);
        }
    }

    private String buildHourlyKey(UUID companyId) {
        String hourBucket = LocalDateTime.now(ZoneOffset.UTC).format(HOUR_KEY_FORMATTER);
        return OTP_SENT_HOURLY_PREFIX + companyId + ":" + hourBucket;
    }

    private long secondsUntilNextHour() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        LocalDateTime nextHour = now.plusHours(1).withMinute(0).withSecond(0).withNano(0);
        return Duration.between(now, nextHour).getSeconds();
    }

    private void resetVerificationAttempts(UUID companyId) {
        String attemptsKey = OTP_ATTEMPTS_PREFIX + companyId;
        redisTemplate.delete(attemptsKey);
    }

    //Generate 6 digit random OTP
    private String generateRandomOtp() {
        int otp = secureRandom.nextInt(900000) + 100000; // Generates number between 100000 and 999999
        return String.valueOf(otp);
    }
}
