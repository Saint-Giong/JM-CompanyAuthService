package rmit.saintgiong.authservice.common.utils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

// Service for managing token storage in Redis.
// Uses blocklist approach for access tokens (store revoked tokens).
// Uses whitelist approach for refresh tokens (store valid tokens).
// Stores activation tokens for account activation.
@Service
@Slf4j
@RequiredArgsConstructor
public class TokenStorageService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String ACCESS_TOKEN_BLOCKLIST_PREFIX = "blocklist:access:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_REFRESH_TOKENS_PREFIX = "user_tokens:refresh:";
    private static final String USED_REFRESH_TOKEN_PREFIX = "used_refresh_token:";

    @Value("${jwe.access-token-ttl-seconds:900}")
    private long accessTokenTtlSeconds;

    @Value("${jwe.refresh-token-ttl-seconds:604800}")
    private long refreshTokenTtlSeconds;

    // =============================== Access Token Blocklist ===============================

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

    // =============================== Refresh Token Whitelist ===============================

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
     * Revokes a refresh token by removing it from Redis and marking it as used.
     *
     * @param tokenId The token ID to revoke
     */
    public void revokeRefreshToken(String tokenId) {
        String key = REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.delete(key);
        
        // Mark token as used for reuse detection
        String usedKey = USED_REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.opsForValue().set(usedKey, "used", refreshTokenTtlSeconds, TimeUnit.SECONDS);
        
        log.debug("Revoked refresh token {} and marked as used", tokenId);
    }

    /**
     * Checks if a refresh token has been previously used (reuse detection).
     *
     * @param tokenId The token ID to check
     * @return true if the token was previously used, false otherwise
     */
    public boolean isRefreshTokenUsed(String tokenId) {
        String usedKey = USED_REFRESH_TOKEN_PREFIX + tokenId;
        Boolean exists = redisTemplate.hasKey(usedKey);
        return Boolean.TRUE.equals(exists);
    }

    /**
     * Revokes all refresh tokens for a user (used when token reuse is detected).
     * This invalidates all sessions for the user as a security measure.
     *
     * @param userId The user ID whose tokens should be revoked
     */
    public void revokeAllUserRefreshTokens(UUID userId) {
        String userTokensKey = USER_REFRESH_TOKENS_PREFIX + userId;
        java.util.Set<String> tokenIds = redisTemplate.opsForSet().members(userTokensKey);
        
        if (tokenIds != null && !tokenIds.isEmpty()) {
            for (String tokenId : tokenIds) {
                String key = REFRESH_TOKEN_PREFIX + tokenId;
                redisTemplate.delete(key);
                
                // Mark as used for reuse detection
                String usedKey = USED_REFRESH_TOKEN_PREFIX + tokenId;
                redisTemplate.opsForValue().set(usedKey, "used", refreshTokenTtlSeconds, TimeUnit.SECONDS);
            }
            redisTemplate.delete(userTokensKey);
            log.info("Revoked all {} refresh tokens for user {}", tokenIds.size(), userId);
        }
    }
}
