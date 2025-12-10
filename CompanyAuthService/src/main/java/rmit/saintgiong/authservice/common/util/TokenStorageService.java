package rmit.saintgiong.authservice.common.util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Service for managing token storage in Redis.
 * Uses blocklist approach for access tokens (store revoked tokens).
 * Uses whitelist approach for refresh tokens (store valid tokens).
 * Stores activation tokens for account activation.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenStorageService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String ACCESS_TOKEN_BLOCKLIST_PREFIX = "blocklist:access:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String ACTIVATION_TOKEN_PREFIX = "activation_token:";
    private static final String USER_REFRESH_TOKENS_PREFIX = "user_tokens:refresh:";

    @Value("${jwe.access-token-ttl-seconds:900}")
    private long accessTokenTtlSeconds;

    @Value("${jwe.refresh-token-ttl-seconds:604800}")
    private long refreshTokenTtlSeconds;

    @Value("${jwe.activation-token-ttl-seconds:86400}")
    private long activationTokenTtlSeconds;

    // ==================== ACCESS TOKEN BLOCKLIST ====================

    /**
     * Adds an access token to the blocklist (for revocation).
     * The token is stored until its original expiration time.
     *
     * @param tokenId          Unique token identifier (jti)
     * @param remainingTtl     Remaining TTL in seconds until token expires
     */
    public void blockAccessToken(String tokenId, long remainingTtl) {
        if (remainingTtl <= 0) {
            // Token already expired, no need to block
            return;
        }
        String key = ACCESS_TOKEN_BLOCKLIST_PREFIX + tokenId;
        redisTemplate.opsForValue().set(key, "blocked", remainingTtl, TimeUnit.SECONDS);
        log.debug("Added access token {} to blocklist with TTL {} seconds", tokenId, remainingTtl);
    }

    /**
     * Checks if an access token is in the blocklist (revoked).
     *
     * @param tokenId The token ID to check
     * @return true if the token is blocked/revoked, false otherwise
     */
    public boolean isAccessTokenBlocked(String tokenId) {
        String key = ACCESS_TOKEN_BLOCKLIST_PREFIX + tokenId;
        Boolean exists = redisTemplate.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }

    // ==================== REFRESH TOKEN WHITELIST ====================

    /**
     * Stores a refresh token in Redis (whitelist approach).
     *
     * @param tokenId   Unique token identifier (jti)
     * @param userId    The user/company ID
     * @param token     The actual token string
     */
    public void storeRefreshToken(String tokenId, UUID userId, String token) {
        String key = REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.opsForValue().set(key, token, refreshTokenTtlSeconds, TimeUnit.SECONDS);
        
        // Store under user's refresh tokens for bulk revocation
        String userTokensKey = USER_REFRESH_TOKENS_PREFIX + userId;
        redisTemplate.opsForSet().add(userTokensKey, tokenId);
        redisTemplate.expire(userTokensKey, refreshTokenTtlSeconds, TimeUnit.SECONDS);
        
        log.debug("Stored refresh token {} for user {}", tokenId, userId);
    }

    /**
     * Validates if a refresh token exists and is valid in Redis.
     *
     * @param tokenId The token ID to validate
     * @return true if the token exists, false otherwise
     */
    public boolean isRefreshTokenValid(String tokenId) {
        String key = REFRESH_TOKEN_PREFIX + tokenId;
        Boolean exists = redisTemplate.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }

    /**
     * Revokes a refresh token by removing it from Redis.
     *
     * @param tokenId The token ID to revoke
     */
    public void revokeRefreshToken(String tokenId) {
        String key = REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.delete(key);
        log.debug("Revoked refresh token {}", tokenId);
    }

    // ==================== ACTIVATION TOKEN ====================

    /**
     * Stores an activation token in Redis.
     *
     * @param tokenId   Unique token identifier (UUID)
     * @param companyId The company ID to be activated
     * @param email     The company email
     */
    public void storeActivationToken(String tokenId, UUID companyId, String email) {
        String key = ACTIVATION_TOKEN_PREFIX + tokenId;
        // Store companyId:email as the value for easy lookup
        String value = companyId.toString() + ":" + email;
        redisTemplate.opsForValue().set(key, value, activationTokenTtlSeconds, TimeUnit.SECONDS);
        
        log.debug("Stored activation token {} for company {}", tokenId, companyId);
    }

    /**
     * Retrieves activation token data and parses it into company ID and email.
     *
     * @param tokenId The activation token ID
     * @return Array containing [companyId, email] or null if not found
     */
    public String[] getActivationTokenData(String tokenId) {
        String key = ACTIVATION_TOKEN_PREFIX + tokenId;
        String value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            return null;
        }
        return value.split(":", 2);
    }

    /**
     * Consumes (deletes) an activation token after successful activation.
     *
     * @param tokenId The activation token ID
     */
    public void consumeActivationToken(String tokenId) {
        String key = ACTIVATION_TOKEN_PREFIX + tokenId;
        redisTemplate.delete(key);
        log.debug("Consumed activation token {}", tokenId);
    }

    // ==================== BULK OPERATIONS ====================

    /**
     * Revokes all refresh tokens for a specific user (logout from all devices).
     * Also blocks all current access tokens until they expire.
     *
     * @param userId              The user/company ID
     * @param accessTokenIds      List of access token IDs to block
     * @param accessTokenTtlLeft  Remaining TTL for access tokens
     */
    public void revokeAllUserTokens(UUID userId, java.util.List<String> accessTokenIds, long accessTokenTtlLeft) {
        // Block all access tokens
        if (accessTokenIds != null) {
            for (String tokenId : accessTokenIds) {
                blockAccessToken(tokenId, accessTokenTtlLeft);
            }
        }
        
        // Revoke all refresh tokens
        String refreshTokensKey = USER_REFRESH_TOKENS_PREFIX + userId;
        var refreshTokenIds = redisTemplate.opsForSet().members(refreshTokensKey);
        if (refreshTokenIds != null) {
            for (String tokenId : refreshTokenIds) {
                redisTemplate.delete(REFRESH_TOKEN_PREFIX + tokenId);
            }
        }
        redisTemplate.delete(refreshTokensKey);
        
        log.info("Revoked all tokens for user {}", userId);
    }

    /**
     * Revokes all refresh tokens for a specific user.
     *
     * @param userId The user/company ID
     */
    public void revokeAllRefreshTokens(UUID userId) {
        String refreshTokensKey = USER_REFRESH_TOKENS_PREFIX + userId;
        var refreshTokenIds = redisTemplate.opsForSet().members(refreshTokensKey);
        if (refreshTokenIds != null) {
            for (String tokenId : refreshTokenIds) {
                redisTemplate.delete(REFRESH_TOKEN_PREFIX + tokenId);
            }
        }
        redisTemplate.delete(refreshTokensKey);
        
        log.info("Revoked all refresh tokens for user {}", userId);
    }

    // ==================== UTILITY METHODS ====================

    /**
     * Gets the TTL for access tokens.
     *
     * @return TTL in seconds
     */
    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    /**
     * Gets the TTL for refresh tokens.
     *
     * @return TTL in seconds
     */
    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    /**
     * Gets the TTL for activation tokens.
     *
     * @return TTL in seconds
     */
    public long getActivationTokenTtlSeconds() {
        return activationTokenTtlSeconds;
    }
}
