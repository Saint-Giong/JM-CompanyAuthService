package rmit.saintgiong.authservice.common.utils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authservice.common.config.JweConfig;

import java.util.Set;
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

    private final JweConfig jweConfig;
    private final RedisTemplate<String, String> redisTemplate;

    private static final String BLOCKLIST_ACCESS_TOKEN_PREFIX = "blocklist:access_token:";
    private static final String STORED_REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_REFRESH_TOKEN_PREFIX = "user:refresh_token:";
    private static final String REVOKED_REFRESH_TOKEN_PREFIX = "revoked:refresh_token:";

    // =============================== Access Token Blocklist ===============================
    /**
     * Adds an access token to the blocklist (for revocation).
     * The token is stored until its original expiration time.
     *
     * @param tokenId      Unique token identifier (jti)
     * @param remainingTtl Remaining TTL in seconds until token expires
     */
    public void blockAccessToken(String tokenId, long remainingTtl) {
        if (remainingTtl <= 0) {
            // Token already expired, no need to block
            return;
        }
        if (isAccessTokenBlocked(tokenId)) {
            String blockedRefreshKey = BLOCKLIST_ACCESS_TOKEN_PREFIX + tokenId;
            redisTemplate.opsForValue().set(blockedRefreshKey, "blocked", remainingTtl, TimeUnit.SECONDS);
            log.debug("Added access token {} to blocklist with TTL {} seconds", tokenId, remainingTtl);
        }
    }

    /**
     * Checks if an access token is in the blocklist (revoked).
     *
     * @param tokenId The token ID to check
     * @return true if the token is blocked/revoked, false otherwise
     */
    public boolean isAccessTokenBlocked(String tokenId) {
        String key = BLOCKLIST_ACCESS_TOKEN_PREFIX + tokenId;
        Boolean exists = redisTemplate.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }

    // =============================== Refresh Token Whitelist ===============================
    /**
     * Stores a refresh token in Redis (whitelist approach).
     *
     * @param tokenId Unique token identifier (jti)
     * @param userId  The user/company ID
     * @param token   The actual token string
     */
    public void storeNewRefreshToken(String tokenId, UUID userId, String token) {
        String refreshKey = STORED_REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.opsForValue().set(refreshKey, token, jweConfig.getRefreshTokenTtlSeconds(), TimeUnit.SECONDS);

        // Store under user's refresh tokens for bulk revocation
        String userTokenKey = USER_REFRESH_TOKEN_PREFIX + userId;
        redisTemplate.opsForSet().add(userTokenKey, tokenId);
        redisTemplate.expire(userTokenKey, jweConfig.getRefreshTokenTtlSeconds(), TimeUnit.SECONDS);

        log.debug("Stored refresh token {} for user {}", tokenId, userId);
    }

    /**
     * Validates if a refresh token exists and is valid in Redis.
     *
     * @param tokenId The token ID to validate
     * @return true if the token exists, false otherwise
     */
    public boolean isRefreshTokenExisted(String tokenId) {
        String key = STORED_REFRESH_TOKEN_PREFIX + tokenId;
        Boolean isExisted = redisTemplate.hasKey(key);
        return Boolean.TRUE.equals(isExisted);
    }

    /**
     * Revokes a refresh token by removing it from Redis and marking it as used.
     *
     * @param tokenId The token ID to revoke
     */
    public void revokeRefreshToken(String tokenId) {
        String key = STORED_REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.delete(key);

        // Mark token as used for reuse detection
        String revokedMarkedKey = REVOKED_REFRESH_TOKEN_PREFIX + tokenId;
        redisTemplate.opsForValue().set(revokedMarkedKey, "revoked", jweConfig.getRefreshTokenTtlSeconds(), TimeUnit.SECONDS);

        log.debug("Revoked refresh token {} and marked as revoked", tokenId);
    }

    /**
     * Checks if a refresh token has been previously used (reuse detection).
     *
     * @param tokenId The token ID to check
     * @return true if the token was previously used, false otherwise
     */
    public boolean isRefreshTokenRevoked(String tokenId) {
        String revokedRefreshKey = REVOKED_REFRESH_TOKEN_PREFIX + tokenId;
        Boolean isExistedAsRevoked = redisTemplate.hasKey(revokedRefreshKey);
        return Boolean.TRUE.equals(isExistedAsRevoked);
    }

    /**
     * Revokes all refresh tokens for a user (used when token reuse is detected).
     * This invalidates all sessions for the user as a security measure.
     *
     * @param userId The user ID whose tokens should be revoked
     */
    public void revokeAllUserRefreshTokens(UUID userId) {
        String userTokenKey = USER_REFRESH_TOKEN_PREFIX + userId;
        Set<String> tokenIdList = redisTemplate.opsForSet().members(userTokenKey);

        if (tokenIdList != null && !tokenIdList.isEmpty()) {
            for (String tokenId : tokenIdList) {
                String refreshKey = STORED_REFRESH_TOKEN_PREFIX + tokenId;
                redisTemplate.delete(refreshKey);

                String revokedRefreshKey = REVOKED_REFRESH_TOKEN_PREFIX + tokenId;
                redisTemplate.opsForValue().set(revokedRefreshKey, "revoked", jweConfig.getRefreshTokenTtlSeconds(), TimeUnit.SECONDS);
            }
            redisTemplate.delete(userTokenKey);
            log.info("Revoked all {} refresh tokens for user {}", tokenIdList.size(), userId);
        }
    }
}
