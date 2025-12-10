package rmit.saintgiong.authservice.common.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authservice.common.auth.Role;
import rmit.saintgiong.authservice.common.auth.TokenType;
import rmit.saintgiong.authservice.common.dto.TokenClaimsDto;
import rmit.saintgiong.authservice.common.dto.TokenPairDto;
import rmit.saintgiong.authservice.common.exception.TokenExpiredException;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service for generating and validating JWE (JSON Web Encryption) tokens.
 * Integrates with Redis for token storage and validation.
 */
@Service
@Slf4j
public class JweTokenService {

    @Value("${jwe.public-key-path}")
    private String publicKeyPath;

    @Value("${jwe.private-key-path}")
    private String privateKeyPath;

    @Value("${jwe.issuer}")
    private String issuer;

    @Value("${jwe.access-token-ttl-seconds:900}")  // Default: 15 minutes
    private long accessTokenTtlSeconds;

    @Value("${jwe.refresh-token-ttl-seconds:604800}")  // Default: 7 days
    private long refreshTokenTtlSeconds;

    @Value("${jwe.activation-token-ttl-seconds:86400}")  // Default: 24 hours
    private long activationTokenTtlSeconds;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private final RsaKeyLoader keyLoader;
    private final ResourceLoader resourceLoader;
    private final TokenStorageService tokenStorageService;

    public JweTokenService(RsaKeyLoader keyLoader, ResourceLoader resourceLoader, TokenStorageService tokenStorageService) {
        this.keyLoader = keyLoader;
        this.resourceLoader = resourceLoader;
        this.tokenStorageService = tokenStorageService;
    }

    @PostConstruct
    public void init() throws Exception {
        // Load keys from file paths (supports classpath: and file: prefixes)
        Resource publicKeyResource = resourceLoader.getResource(publicKeyPath);
        Resource privateKeyResource = resourceLoader.getResource(privateKeyPath);
        
        String publicKeyPem = new String(publicKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String privateKeyPem = new String(privateKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        
        this.publicKey = keyLoader.loadPublicKey(publicKeyPem);
        this.privateKey = keyLoader.loadPrivateKey(privateKeyPem);
        
        log.info("JWE Token Service initialized with issuer: {}", issuer);
        log.info("Access token TTL: {} seconds, Refresh token TTL: {} seconds, Activation token TTL: {} seconds", 
                accessTokenTtlSeconds, refreshTokenTtlSeconds, activationTokenTtlSeconds);
    }

    /**
     * Generates a token pair (access + refresh) for a user upon successful login.
     * Access tokens are NOT stored in Redis (verified via signature + blocklist check).
     * Refresh tokens ARE stored in Redis (whitelist approach).
     *
     * @param userId The user/company ID
     * @param email  The user email
     * @param role   The user role
     * @return TokenPairDto containing both tokens and their expiration info
     */
    public TokenPairDto generateTokenPair(UUID userId, String email, Role role) {
        try {
            String accessTokenId = UUID.randomUUID().toString();
            String refreshTokenId = UUID.randomUUID().toString();
            
            String accessToken = generateToken(userId, email, role, TokenType.ACCESS, accessTokenTtlSeconds, accessTokenId);
            String refreshToken = generateToken(userId, email, role, TokenType.REFRESH, refreshTokenTtlSeconds, refreshTokenId);

            // Only store refresh token in Redis (whitelist approach)
            // Access token is verified via JWE decryption + blocklist check
            tokenStorageService.storeRefreshToken(refreshTokenId, userId, refreshToken);

            return TokenPairDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .accessTokenExpiresIn(accessTokenTtlSeconds)
                    .refreshTokenExpiresIn(refreshTokenTtlSeconds)
                    .tokenType("Bearer")
                    .build();
        } catch (JOSEException e) {
            log.error("Failed to generate token pair for user: {}", userId, e);
            throw new RuntimeException("Token generation failed", e);
        }
    }



    /**
     * Refreshes an access token using a valid refresh token.
     * Old refresh token is revoked and new tokens are generated.
     *
     * @param refreshToken The refresh token
     * @return New TokenPairDto with fresh access token and rotated refresh token
     */
    public TokenPairDto refreshAccessToken(String refreshToken) {
        TokenClaimsDto claims = validateAndDecrypt(refreshToken);

        // Verify this is a refresh token
        if (claims.getType() != TokenType.REFRESH) {
            throw new InvalidTokenException("Invalid token type: expected REFRESH token");
        }

        // Verify token exists in Redis (not revoked)
        String oldRefreshTokenId = claims.getJti();
        if (!tokenStorageService.isRefreshTokenValid(oldRefreshTokenId)) {
            throw new InvalidTokenException("Refresh token has been revoked or expired");
        }

        // Generate new access token 
        try {
            String newAccessTokenId = UUID.randomUUID().toString();
            String newRefreshTokenId = UUID.randomUUID().toString();
            
            String newAccessToken = generateToken(
                    claims.getSub(), 
                    claims.getEmail(), 
                    claims.getRole(), 
                    TokenType.ACCESS, 
                    accessTokenTtlSeconds,
                    newAccessTokenId
            );

            // Rotate refresh token
            String newRefreshToken = generateToken(
                    claims.getSub(),
                    claims.getEmail(),
                    claims.getRole(),
                    TokenType.REFRESH,
                    refreshTokenTtlSeconds,
                    newRefreshTokenId
            );

            // Revoke old refresh token and store new refresh token
            tokenStorageService.revokeRefreshToken(oldRefreshTokenId);
            tokenStorageService.storeRefreshToken(newRefreshTokenId, claims.getSub(), newRefreshToken);

            return TokenPairDto.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .accessTokenExpiresIn(accessTokenTtlSeconds)
                    .refreshTokenExpiresIn(refreshTokenTtlSeconds)
                    .tokenType("Bearer")
                    .build();
        } catch (JOSEException e) {
            log.error("Failed to refresh token for user: {}", claims.getSub(), e);
            throw new RuntimeException("Token refresh failed", e);
        }
    }

    /**
     * Validates an access token and returns the claims if valid.
     * Checks if the token is in the blocklist (revoked).
     *
     * @param accessToken The access token to validate
     * @return TokenClaimsDto containing the token claims
     */
    public TokenClaimsDto validateAccessToken(String accessToken) {
        TokenClaimsDto claims = validateAndDecrypt(accessToken);

        // Verify this is an access token
        if (claims.getType() != TokenType.ACCESS) {
            throw new InvalidTokenException("Invalid token type: expected ACCESS token");
        }

        // Check if token is in the blocklist (revoked)
        String tokenId = claims.getJti();
        if (tokenStorageService.isAccessTokenBlocked(tokenId)) {
            throw new InvalidTokenException("Access token has been revoked");
        }

        return claims;
    }

    /**
     * Revokes all tokens for a specific user (logout from all devices).
     * Note: For access tokens, the caller should provide the current access token
     * to add it to the blocklist.
     *
     * @param userId The user/company ID
     */
    public void revokeAllUserTokens(UUID userId) {
        tokenStorageService.revokeAllRefreshTokens(userId);
    }

    /**
     * Revokes a specific access token by adding it to the blocklist.
     *
     * @param accessToken The access token to revoke
     */
    public void revokeAccessToken(String accessToken) {
        TokenClaimsDto claims = validateAndDecrypt(accessToken);
        long now = Instant.now().getEpochSecond();
        long remainingTtl = claims.getExp() - now;
        tokenStorageService.blockAccessToken(claims.getJti(), remainingTtl);
    }

    /**
     * Revokes a specific refresh token.
     *
     * @param refreshToken The refresh token to revoke
     */
    public void revokeRefreshToken(String refreshToken) {
        TokenClaimsDto claims = validateAndDecrypt(refreshToken);
        tokenStorageService.revokeRefreshToken(claims.getJti());
    }

    /**
     * Generates a single JWE token with the specified parameters.
     */
    private String generateToken(UUID userId, String email, Role role, TokenType tokenType, long ttlSeconds, String tokenId) 
            throws JOSEException {
        
        long now = Instant.now().getEpochSecond();
        long exp = now + ttlSeconds;

        // Build JWE Header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .type(JOSEObjectType.JOSE)
                .issuer(issuer)
                .customParam("iat", now)
                .customParam("exp", exp)
                .build();

        // Build Payload with user identity info (encrypted, not visible to clients)
        Map<String, Object> payloadMap = new LinkedHashMap<>();
        payloadMap.put("sub", userId.toString());
        payloadMap.put("email", email);
        payloadMap.put("role", role.name());
        payloadMap.put("type", tokenType.name());
        payloadMap.put("jti", tokenId);

        Payload payload = new Payload(payloadMap);

        // Create and encrypt JWE
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new RSAEncrypter(publicKey));

        return jweObject.serialize();
    }

    /**
     * Decrypts and validates a JWE token.
     */
    private TokenClaimsDto validateAndDecrypt(String jweString) {
        try {
            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(new RSADecrypter(privateKey));

            // Validate expiration from header
            Number exp = (Number) jweObject.getHeader().getCustomParam("exp");
            if (exp != null) {
                long now = Instant.now().getEpochSecond();
                if (now > exp.longValue()) {
                    throw new TokenExpiredException("Token has expired");
                }
            }

            // Extract payload
            Map<String, Object> payloadMap = jweObject.getPayload().toJSONObject();

            // Get header claims
            Number iat = (Number) jweObject.getHeader().getCustomParam("iat");
            String iss = jweObject.getHeader().getIssuer();

            return TokenClaimsDto.builder()
                    .sub(UUID.fromString((String) payloadMap.get("sub")))
                    .email((String) payloadMap.get("email"))
                    .role(Role.valueOf((String) payloadMap.get("role")))
                    .type(TokenType.valueOf((String) payloadMap.get("type")))
                    .jti((String) payloadMap.get("jti"))
                    .iat(iat != null ? iat.longValue() : 0)
                    .exp(exp != null ? exp.longValue() : 0)
                    .iss(iss)
                    .build();

        } catch (TokenExpiredException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            throw new InvalidTokenException("Invalid or malformed token");
        }
    }

    /**
     * Inspects a token and returns all components (for debugging).
     */
    public Map<String, Object> inspectToken(String jweString) {
        try {
            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(new RSADecrypter(privateKey));

            Map<String, Object> report = new LinkedHashMap<>();
            report.put("header", jweObject.getHeader().toJSONObject());
            report.put("payload", jweObject.getPayload().toJSONObject());
            report.put("encrypted_key", jweObject.getEncryptedKey() != null ? 
                    jweObject.getEncryptedKey().toString() : "null");
            report.put("iv", jweObject.getIV() != null ? jweObject.getIV().toString() : "null");
            report.put("ciphertext", jweObject.getCipherText().toString());
            report.put("auth_tag", jweObject.getAuthTag() != null ? 
                    jweObject.getAuthTag().toString() : "null");

            return report;
        } catch (Exception e) {
            throw new RuntimeException("Could not inspect token", e);
        }
    }
}
