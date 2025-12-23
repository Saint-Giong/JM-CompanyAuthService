package rmit.saintgiong.authservice.common.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.type.Role;
import rmit.saintgiong.authapi.internal.type.TokenType;
import rmit.saintgiong.authapi.internal.dto.common.TokenClaimsDto;
import rmit.saintgiong.authapi.internal.dto.common.TokenPairDto;
import rmit.saintgiong.authservice.common.exception.TokenExpiredException;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

// Service for generating and validating JWE (JSON Web Encryption) tokens.
// Integrates with Redis for token storage and validation.
@Service
@Slf4j
public class JweTokenService {
    @Value("${jwe.issuer}")
    private String issuer;

    @Value("${jwe.register-token-ttl-seconds:300}")  // Default: 5 minutes
    private long registerTokenTtlSeconds;

    @Value("${jwe.access-token-ttl-seconds:900}")  // Default: 15 minutes
    private long accessTokenTtlSeconds;

    @Value("${jwe.refresh-token-ttl-seconds:604800}")  // Default: 7 days
    private long refreshTokenTtlSeconds;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private final RsaKeyLoader keyLoader;
    private final TokenStorageService tokenStorageService;

    public JweTokenService(RsaKeyLoader keyLoader, TokenStorageService tokenStorageService) {
        this.keyLoader = keyLoader;
        this.tokenStorageService = tokenStorageService;
    }

    @PostConstruct
    public void init() throws Exception {
        this.publicKey = keyLoader.loadPublicKey();
        this.privateKey = keyLoader.loadPrivateKey();

        log.info("JWE Token Service initialized with issuer: {}", issuer);
        log.info("Access token TTL: {} seconds, Refresh token TTL: {} seconds",
                accessTokenTtlSeconds, refreshTokenTtlSeconds);
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
    public TokenPairDto generateTokenPair(UUID userId, String email, Role role, Boolean isActivated) {
        try {

            String accessTokenId = UUID.randomUUID().toString();
            String refreshTokenId = UUID.randomUUID().toString();

            String accessToken = generateToken(userId, email, role, TokenType.ACCESS, accessTokenTtlSeconds, accessTokenId);
            String refreshToken = "";

            // Only generate refresh token if user is activated
            if (isActivated) {
                refreshToken = generateToken(userId, email, role, TokenType.REFRESH, refreshTokenTtlSeconds, refreshTokenId);

                // Only store refresh token in Redis (whitelist approach)
                // Access token is verified via JWE decryption + blocklist check
                tokenStorageService.storeRefreshToken(refreshTokenId, userId, refreshToken);
            }


            //Only generate long-lived refresh token for activated users
            //Inactivated users will only have short-lived access tokens
            return TokenPairDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .accessTokenExpiresIn(accessTokenTtlSeconds)
                    .refreshTokenExpiresIn(refreshTokenTtlSeconds)
                    .build();
        } catch (JOSEException e) {
            log.error("Failed to generate token pair for user: {}", userId, e);
            throw new RuntimeException("Token generation failed", e);
        }
    }

    /**
     * Refreshes an access token using a valid refresh token.
     * The old refresh token is revoked and new tokens are generated.
     *
     * @param refreshToken The refresh token
     * @return New TokenPairDto with fresh access token and rotated refresh token
     */
    public TokenPairDto refreshAccessToken(String refreshToken) {
        TokenClaimsDto claims = buildTokenClaimsDto(refreshToken);

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
        TokenClaimsDto claims = buildTokenClaimsDto(accessToken);

        // Verify this is an access token
        if (claims.getType() != TokenType.ACCESS) {
            throw new InvalidTokenException("Invalid token type: expected ACCESS token");
        }

        // Check if the token is in the blocklist (revoked)
        String tokenId = claims.getJti();
        if (tokenStorageService.isAccessTokenBlocked(tokenId)) {
            throw new InvalidTokenException("Access token has been revoked");
        }

        return claims;
    }

    /**
     * Generate the temporary token for a user registration process when they use Google as External SSO
     *
     * @param email    The user email
     * @param googleId The googleId returning from GoogleIdToken.Payload
     * @return String Returns the temp token string
     */
    public String generateRegistrationTokenForGoogleAuth(String email, String googleId) {
        try {
            String tokenId = UUID.randomUUID().toString();

            long now = Instant.now().getEpochSecond();
            long exp = now + registerTokenTtlSeconds;

            JWEHeader header = new JWEHeader
                    .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .type(JOSEObjectType.JOSE)
                    .issuer(issuer)
                    .customParam("iat", now)
                    .customParam("exp", exp)
                    .build();

            Map<String, Object> payloadMap = new LinkedHashMap<>();
            payloadMap.put("googleId", googleId);
            payloadMap.put("email", email);
            payloadMap.put("role", Role.COMPANY);
            payloadMap.put("type", TokenType.TEMP);
            payloadMap.put("jti", tokenId);

            Payload payload = new Payload(payloadMap);
            JWEObject jweObject = new JWEObject(header, payload);
            jweObject.encrypt(new RSAEncrypter(publicKey));

            return jweObject.serialize();
        } catch (JOSEException e) {
            log.error("Failed to generate register token for email {}", email, e);
            throw new RuntimeException("Register token generation failed", e);
        }
    }

    public String getGoogleIdFromJweToken(String jweString) {
        try {
            JWEObject jweObject = validateAndGetDecryptedJweObject(jweString, TokenType.TEMP);
            Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

            String googleIdString = tokenPayload.get("googleId") != null ? tokenPayload.get("googleId").toString() : null;
            if (googleIdString == null) {
                throw new InvalidTokenException("Google ID not found in token.");
            }

            return googleIdString;

        } catch (TokenExpiredException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            throw new InvalidTokenException("Invalid or malformed token");
        }
    }

    public String getEmailFromJweString(String jweString) {
        try {
            JWEObject jweObject = validateAndGetDecryptedJweObject(jweString, TokenType.TEMP);
            Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

            String emailString = tokenPayload.get("email") != null ? tokenPayload.get("email").toString() : null;
            if (emailString == null) {
                throw new InvalidTokenException("Google ID not found in token.");
            }

            return emailString;

        } catch (TokenExpiredException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            throw new InvalidTokenException("Invalid or malformed token");
        }
    }

    // Generates a single JWE token with the specified parameters.
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

    // Decrypts and validates a JWE token.
    private TokenClaimsDto buildTokenClaimsDto(String jweString) {
        try {
            JWEObject jweObject = validateAndGetDecryptedJweObject(jweString, null);
            Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

            Number iat = (Number) jweObject.getHeader().getCustomParam("iat");
            Number exp = (Number) jweObject.getHeader().getCustomParam("exp");
            String iss = jweObject.getHeader().getIssuer();

            return TokenClaimsDto.builder()
                    .sub(UUID.fromString((String) tokenPayload.get("sub")))
                    .email((String) tokenPayload.get("email"))
                    .role(Role.valueOf((String) tokenPayload.get("role")))
                    .type(TokenType.valueOf((String) tokenPayload.get("type")))
                    .jti((String) tokenPayload.get("jti"))
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

    private JWEObject validateAndGetDecryptedJweObject(String jweString, TokenType type) throws JOSEException, ParseException {
        JWEObject jweObject = JWEObject.parse(jweString);
        jweObject.decrypt(new RSADecrypter(privateKey));
        Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

        Number exp = (Number) jweObject.getHeader().getCustomParam("exp");
        if (exp != null) {
            long now = Instant.now().getEpochSecond();
            if (now > exp.longValue()) {
                throw new TokenExpiredException("Token has expired");
            }
        }

        String tokenIssuer = jweObject.getHeader().getIssuer();
        if (tokenIssuer == null || !tokenIssuer.equals(issuer)) {
            throw new InvalidTokenException("Invalid token issuer");
        }

        List<Role> roleList = Arrays.asList(Role.values());
        String role = tokenPayload.get("role") != null ? tokenPayload.get("role").toString() : null;
        if (role == null || roleList.stream().noneMatch(r -> r.name().equals(role))) {
            throw new InvalidTokenException(String.format("Invalid token role: %s, expected COMPANY", role));
        }

        if (type != null && type.equals(TokenType.TEMP)) {
            Object typeObj = tokenPayload.get("type");
            String typeStr = typeObj != null ? typeObj.toString() : null;
            if (typeStr == null || !typeStr.equalsIgnoreCase(TokenType.TEMP.name())) {
                throw new InvalidTokenException("Invalid token type: expected TEMP");
            }
        }

        return jweObject;
    }
}
