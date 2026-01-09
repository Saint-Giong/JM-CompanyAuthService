package rmit.saintgiong.authservice.common.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import rmit.saintgiong.shared.type.Role;
import rmit.saintgiong.shared.type.TokenType;
import rmit.saintgiong.shared.token.TokenClaimsDto;
import rmit.saintgiong.shared.token.TokenPairDto;
import rmit.saintgiong.authservice.common.config.JweConfig;
import rmit.saintgiong.authservice.common.exception.token.TokenExpiredException;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.authservice.common.exception.token.TokenReuseException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Arrays;


@Service
@Slf4j
public class JweTokenService {

    private final JweConfig jweConfig;
    private final RsaKeyLoader keyLoader;
    private final TokenStorageService tokenStorageService;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    @Value("${otp.ttl-seconds:120}")  // Default: 2 minutes
    private long activationTtlSeconds;

    public JweTokenService(RsaKeyLoader keyLoader, TokenStorageService tokenStorageService, JweConfig jweConfig) {
        this.keyLoader = keyLoader;
        this.tokenStorageService = tokenStorageService;
        this.jweConfig = jweConfig;
    }

    @PostConstruct
    public void init() throws Exception {
        this.publicKey = keyLoader.loadPublicKey();
        this.privateKey = keyLoader.loadPrivateKey();

        log.info("JWE Token Service initialized with issuer: {}", jweConfig.getIssuer());
        log.info("Access token TTL: {} seconds, Refresh token TTL: {} seconds",
                jweConfig.getAccessTokenTtlSeconds(), jweConfig.getRefreshTokenTtlSeconds());
    }

    /**
     * Generates a token pair (access and refresh) for a user upon successful authentication.
     * Access tokens are NOT stored in Redis (verified via signature + blocklist check)
     * Refresh tokens ARE stored in Redis (whitelist approach).
     *
     * @param userId      The user/company ID
     * @param email       The user email
     * @param role        The user role
     * @param isActivated Whether the user is activated or not.
     * @return TokenPairDto containing both tokens and their expiration info
     */
    public TokenPairDto generateTokenPairDto(UUID userId, String email, Role role, Boolean isActivated) {
        try {
            String accessTokenId = UUID.randomUUID().toString();
            String refreshTokenId = UUID.randomUUID().toString();

            String accessToken = generateNewToken(
                    userId,
                    email,
                    role,
                    TokenType.ACCESS,
                    jweConfig.getIssuer(),
                    jweConfig.getAccessTokenTtlSeconds(),
                    accessTokenId
            );
            String refreshToken = null;

            // Only generate the refresh token on activated accounts
            if (isActivated) {
                refreshToken = generateNewToken(
                        userId,
                        email,
                        role,
                        TokenType.REFRESH,
                        jweConfig.getIssuer(),
                        jweConfig.getRefreshTokenTtlSeconds(),
                        refreshTokenId
                );

                // Only store refresh token in Redis (whitelist approach)
                // Access token is verified via JWE decryption + blocklist check
                tokenStorageService.storeNewRefreshToken(refreshTokenId, userId, refreshToken);
            }

            return TokenPairDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .accessTokenExpiresIn(jweConfig.getAccessTokenTtlSeconds())
                    .refreshTokenExpiresIn(jweConfig.getRefreshTokenTtlSeconds())
                    .build();
        } catch (JOSEException e) {
            log.error("Failed to generate token pair for user: {}", userId, e);
            throw new RuntimeException("Token generation failed", e);
        }
    }

    /**
     * Refreshes an access token using a valid refresh token.
     * The old refresh token is revoked and new tokens are generated.
     * Implements token reuse detection - if a previously used token is detected,
     * all user sessions are invalidated as a security measure.
     *
     * @param refreshToken The refresh token
     * @return New TokenPairDto with fresh access token and rotated refresh token
     */
    public TokenPairDto refreshAccessToken(String refreshToken) {
        TokenClaimsDto claims = getTokenClaimsDtoDecryptedFromTokenString(refreshToken);
        if (claims.getType() != TokenType.REFRESH) {
            throw new InvalidTokenException("Invalid token type. Expected TokenType: REFRESH");
        }

        String currentRefreshTokenId = claims.getJti();
        // Check if it has been revoked or not
        if (tokenStorageService.isRefreshTokenRevoked(currentRefreshTokenId)) {
            log.warn("Usage of revoked refresh token detected for user {}. Revoking all sessions.", claims.getSub());
            tokenStorageService.revokeAllUserRefreshTokens(claims.getSub());
            throw new TokenReuseException("Refresh token has already been revoked. All sessions will be invalidated.");
        }

        // Verify token exists in Redis (not revoked)
        if (!tokenStorageService.isRefreshTokenExisted(currentRefreshTokenId)) {
            throw new InvalidTokenException("Refresh token has been revoked or expired.");
        }

        try {
            String newAccessTokenId = UUID.randomUUID().toString();
            String newRefreshTokenId = UUID.randomUUID().toString();

            String newAccessToken = generateNewToken(
                    claims.getSub(),
                    claims.getEmail(),
                    claims.getRole(),
                    TokenType.ACCESS,
                    jweConfig.getIssuer(),
                    jweConfig.getAccessTokenTtlSeconds(),

                    newAccessTokenId
            );

            // Rotate refresh token
            String rotatedRefreshToken = generateNewToken(
                    claims.getSub(),
                    claims.getEmail(),
                    claims.getRole(),
                    TokenType.REFRESH,
                    jweConfig.getIssuer(),
                    jweConfig.getRefreshTokenTtlSeconds(),
                    newRefreshTokenId
            );

            // Revoke old refresh token and store new refresh token
            tokenStorageService.revokeRefreshToken(currentRefreshTokenId);
            tokenStorageService.storeNewRefreshToken(newRefreshTokenId, claims.getSub(), rotatedRefreshToken);

            return TokenPairDto.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(rotatedRefreshToken)
                    .accessTokenExpiresIn(jweConfig.getAccessTokenTtlSeconds())
                    .refreshTokenExpiresIn(jweConfig.getRefreshTokenTtlSeconds())
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
        TokenClaimsDto tokenClaimsDto = getTokenClaimsDtoDecryptedFromTokenString(accessToken);
        if (tokenClaimsDto.getType() != TokenType.ACCESS) {
            throw new InvalidTokenException("Invalid token type. Expected TokenType: ACCESS");
        }

        String accessTokenId = tokenClaimsDto.getJti();
        if (tokenStorageService.isAccessTokenBlocked(accessTokenId)) {
            throw new InvalidTokenException("Access token has been revoked.");
        }

        return tokenClaimsDto;
    }

    // Generates a single JWE token with the specified parameters.
    private String generateNewToken(
            UUID userId,
            String email,
            Role role,
            TokenType tokenType,
            String issuer,
            long ttlSeconds,
            String tokenId
    ) throws JOSEException {
        long now = Instant.now().getEpochSecond();
        long exp = now + ttlSeconds;

        // Build JWE Header
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .type(JOSEObjectType.JOSE)
                .issuer(issuer)
                .customParam("iat", now)
                .customParam("exp", exp)
                .build();

        Map<String, Object> payloadMap = new LinkedHashMap<>();
        payloadMap.put("sub", userId.toString());
        payloadMap.put("email", email);
        payloadMap.put("role", role.name());
        payloadMap.put("type", tokenType.name());
        payloadMap.put("jti", tokenId);

        Payload payload = new Payload(payloadMap);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new RSAEncrypter(publicKey));

        return jweObject.serialize();
    }

    /**
     * Revokes both access and refresh tokens during logout.
     * Adds an access token to the blocklist and removes the refresh token from the whitelist.
     *
     * @param accessToken  The access token to revoke
     * @param refreshToken The refresh token to revoke (can be null)
     */
    public void revokeTokens(String accessToken, String refreshToken) {
        if (accessToken != null && !accessToken.isEmpty()) {
            try {
                TokenClaimsDto accessClaims = getTokenClaimsDtoDecryptedFromTokenString(accessToken);
                long now = Instant.now().getEpochSecond();
                long remainingTtl = accessClaims.getExp() - now;
                tokenStorageService.blockAccessToken(accessClaims.getJti(), remainingTtl);

                log.debug("Access token blocked for user {}", accessClaims.getSub());
            } catch (Exception e) {
                log.debug("Could not block access token: {}", e.getMessage());
            }
        }

        // Revoke refresh token by removing from whitelist
        if (refreshToken != null && !refreshToken.isEmpty()) {
            try {
                TokenClaimsDto refreshClaims = getTokenClaimsDtoDecryptedFromTokenString(refreshToken);
                tokenStorageService.revokeRefreshToken(refreshClaims.getJti());

                log.debug("Refresh token revoked for user {}", refreshClaims.getSub());
            } catch (Exception e) {
                log.debug("Could not revoke refresh token: {}", e.getMessage());
            }
        }
    }

    // Decrypts and validates a JWE token.
    public TokenClaimsDto getTokenClaimsDtoDecryptedFromTokenString(String jweString) {
        try {
            JWEObject jweObject = validateAndConvertTokenStringToJweObject(jweString, null);
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

    private JWEObject validateAndConvertTokenStringToJweObject(String jweString, TokenType type)
            throws JOSEException, ParseException {
        JWEObject jweObject = JWEObject.parse(jweString);
        jweObject.decrypt(new RSADecrypter(privateKey));
        Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

        Number exp = (Number) jweObject.getHeader().getCustomParam("exp");
        if (exp != null) {
            long now = Instant.now().getEpochSecond();
            if (now > exp.longValue()) {
                throw new TokenExpiredException("Token has expired.");
            }
        }

        String tokenIssuer = jweObject.getHeader().getIssuer();
        if (tokenIssuer == null || !tokenIssuer.equals(jweConfig.getIssuer())) {
            throw new InvalidTokenException(String.format("Invalid token issuer. Issue: %s is UNAUTHORIZED. ", tokenIssuer));
        }

        List<Role> roleList = Arrays.asList(Role.values());
        String role = tokenPayload.get("role") != null ? tokenPayload.get("role").toString() : null;
        if (role == null || roleList.stream().noneMatch(r -> r.name().equals(role))) {
            throw new InvalidTokenException(String.format("Invalid token role. Got: %s is UNAUTHORIZED.", role));
        }

        if (type != null && type.equals(TokenType.TEMP)) {
            Object typeObj = tokenPayload.get("type");
            String typeStr = typeObj != null ? typeObj.toString() : null;
            if (typeStr == null || !typeStr.equalsIgnoreCase(TokenType.TEMP.name())) {
                throw new InvalidTokenException(String.format("Invalid token type. Expected: TEMP, Got: %s", typeStr));
            }
        }

        return jweObject;
    }

    /**
     * Generate the temporary token for a user registration process when they use Google as External SSO
     *
     * @param email    The user email
     * @param googleId The googleId returning from GoogleIdToken.Payload
     * @return String Returns the temp token string
     */
    public String generateTempTokenForGoogleAuth(String email, String googleId) {
        try {
            long now = Instant.now().getEpochSecond();
            long exp = now + jweConfig.getTempTokenTtlSeconds();

            JWEHeader header = new JWEHeader
                    .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .type(JOSEObjectType.JOSE)
                    .issuer(jweConfig.getIssuer())
                    .customParam("iat", now)
                    .customParam("exp", exp)
                    .build();

            Map<String, Object> payloadMap = new LinkedHashMap<>();
            payloadMap.put("googleId", googleId);
            payloadMap.put("email", email);
            payloadMap.put("role", Role.COMPANY);
            payloadMap.put("type", TokenType.TEMP);

            Payload payload = new Payload(payloadMap);
            JWEObject jweObject = new JWEObject(header, payload);
            jweObject.encrypt(new RSAEncrypter(publicKey));

            return jweObject.serialize();
        } catch (JOSEException e) {
            log.error("Failed to generate temp token for user: {}", email);
            throw new RuntimeException("Register token generation failed", e);
        }
    }

    public String getGoogleIdFromJweToken(String jweString) {
        try {
            JWEObject jweObject = validateAndConvertTokenStringToJweObject(jweString, TokenType.TEMP);
            Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

            String googleIdString =
                    tokenPayload.get("googleId") != null
                            ? tokenPayload.get("googleId").toString()
                            : null;
            if (googleIdString == null) {
                throw new InvalidTokenException("Google ID not found in token.");
            }

            return googleIdString;
        } catch (TokenExpiredException e) {
            throw e;
        } catch (Exception e) {
            log.error("Temp token validation failed", e);
            throw new InvalidTokenException("Invalid or malformed token");
        }
    }

    // Get Email from a callback access token from Google
    public String getEmailFromJweString(String jweString) {
        try {
            JWEObject jweObject = validateAndConvertTokenStringToJweObject(jweString, TokenType.TEMP);
            Map<String, Object> tokenPayload = jweObject.getPayload().toJSONObject();

            String emailString =
                    tokenPayload.get("email") != null
                            ? tokenPayload.get("email").toString()
                            : null;
            if (emailString == null) {
                throw new InvalidTokenException("Google Email not found in token.");
            }

            return emailString;
        } catch (TokenExpiredException e) {
            throw e;
        } catch (Exception e) {
            log.error("Temp token validation failed", e);
            throw new InvalidTokenException("Invalid or malformed token");
        }
    }


    public String generateActivationToken(UUID userId, String email, Role role) {
        try {
            String activationTokenId = UUID.randomUUID().toString();

            String activationToken = generateNewToken(
                    userId,
                    email,
                    role,
                    TokenType.ACCESS, // TODO: Add token type
                    jweConfig.getIssuer(),
                    activationTtlSeconds,
                    activationTokenId
            );

            return activationToken;
        } catch (JOSEException e) {
            log.error("Failed to generate activation token for user: {}", userId, e);
            throw new RuntimeException("Token generation failed", e);
        }
    }
}
