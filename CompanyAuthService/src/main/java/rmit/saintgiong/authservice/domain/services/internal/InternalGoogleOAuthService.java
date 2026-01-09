package rmit.saintgiong.authservice.domain.services.internal;


import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleAuthResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleOAuthResponseDto;
import rmit.saintgiong.authapi.internal.services.InternalCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.services.InternalGoogleOAuthInterface;
import rmit.saintgiong.authservice.common.config.JweConfig;
import rmit.saintgiong.authservice.common.exception.resources.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.shared.type.CookieType;
import rmit.saintgiong.shared.type.Role;
import rmit.saintgiong.shared.token.TokenPairDto;
import rmit.saintgiong.authservice.common.exception.resources.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.token.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.utils.JweTokenService;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class InternalGoogleOAuthService implements InternalGoogleOAuthInterface {

    @Value("${OAUTH2_CLIENT_ID}")
    private String clientId;

    @Value("${OAUTH2_CLIENT_SECRET}")
    private String clientSecret;

    @Value("${google.oauth2-login-redirect-uri}")
    private String redirectLoginUri;

    @Value("${google.oauth2-link-redirect-uri}")
    private String redirectLinkUri;

    private final InternalCompanyAuthInterface internalCompanyAuthInterface;

    private final CompanyAuthRepository companyAuthRepository;
    private final JweTokenService jweTokenService;
    private final JweConfig jweConfig;

    private static final GsonFactory GSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final NetHttpTransport NET_HTTP_TRANSPORT = new NetHttpTransport();

    @Override
    public GoogleAuthResponseDto handleGoogleAuthentication (HttpServletResponse response, String code) throws IOException {
        GoogleOAuthResponseDto oauthResponseDto = authenticateGoogleUser(code);
        TokenPairDto tokenPairDto = oauthResponseDto.getTokenPairDto();

        // login is ok
        if (tokenPairDto != null) {
            internalCompanyAuthInterface.setCookieToBrowser(
                    response,
                    CookieType.ACCESS_TOKEN,
                    tokenPairDto.getAccessToken(),
                    (int) tokenPairDto.getAccessTokenExpiresIn()
            );

            if (tokenPairDto.getRefreshToken() != null && !tokenPairDto.getRefreshToken().isEmpty()) {
                internalCompanyAuthInterface.setCookieToBrowser(
                        response,
                        CookieType.REFRESH_TOKEN,
                        tokenPairDto.getRefreshToken(),
                        (int) tokenPairDto.getRefreshTokenExpiresIn()
                );
            }

            return GoogleAuthResponseDto.builder()
                    .companyId(oauthResponseDto.getCompanyId())
                    .email(oauthResponseDto.getEmail())
                    .build();
        }

        // return prefill for register phase
        if (oauthResponseDto.getTempToken() != null) {
            internalCompanyAuthInterface.setCookieToBrowser(
                    response,
                    CookieType.TEMP_TOKEN,
                    oauthResponseDto.getTempToken(),
                    (int) oauthResponseDto.getTempTokenExpiresIn()
            );

            return GoogleAuthResponseDto.builder()
                    .email(oauthResponseDto.getEmail())
                    .name(oauthResponseDto.getName())
                    .build();

        }

        return null;
    }

    @Override
    public void handleLinkGoogleToAccount (String companyId, String code, boolean isLink, boolean isRelink) throws IOException {
        if (code == null || code.trim().isEmpty()) {
            throw new InvalidTokenException("Authorization code is missing");
        }

        CompanyAuthEntity currentUser = companyAuthRepository.findById(UUID.fromString(companyId)).orElseThrow(
                () -> new ResourceNotFoundException("Company", "ID", companyId)
        );

        if (isLink && currentUser.getSsoToken() != null) {
            throw new IllegalArgumentException("Account already linked to Google. Use '/google/relink-google' to re-link new Google Account");
        }

        if (isRelink && currentUser.getSsoToken() == null) {
            throw new IllegalArgumentException("Account is not linked to Google. Use '/google/link-google' to link new Google Account");
        }

        GoogleIdToken.Payload payload = verifyAndGetGoogleIdTokenPayload(code, true);
        String googleId = payload.getSubject();
        String googleEmail = payload.getEmail();

        Optional<CompanyAuthEntity> existingLinkedAccount = companyAuthRepository.findBySsoToken(googleId);
        if (existingLinkedAccount.isPresent() && !existingLinkedAccount.get().getCompanyId().toString().equals(companyId)) {
            throw new CompanyAccountAlreadyExisted("This Google account is already linked to another company account");
        }

        if (!currentUser.getEmail().equals(googleEmail)) {
            if (companyAuthRepository.existsByEmail(googleEmail)) {
                throw new CompanyAccountAlreadyExisted("Cannot Link: Google mail is already used by another account");
            }

            currentUser.setEmail(googleEmail);
        }

        currentUser.setSsoToken(googleId);
        companyAuthRepository.save(currentUser);
    }

    @Override
    public GoogleOAuthResponseDto authenticateGoogleUser(String authorizationCode) throws IOException {
        if (authorizationCode == null || authorizationCode.trim().isEmpty()) {
            throw new InvalidTokenException("Authorization code is missing");
        }

        String decodedAuthorizationCode = URLDecoder.decode(authorizationCode, StandardCharsets.UTF_8);
        GoogleIdToken.Payload googlePayload = verifyAndGetGoogleIdTokenPayload(decodedAuthorizationCode, false);

        if (!Boolean.TRUE.equals(googlePayload.getEmailVerified())) {
            throw new IllegalArgumentException(String.format("Email: %s is not verified by Google", googlePayload.getEmail()));
        }

        String googleId = googlePayload.getSubject();
        String googleEmail = googlePayload.getEmail();
        String googleName = (String) googlePayload.get("name");

        Optional<CompanyAuthEntity> savedCompany = companyAuthRepository.findByEmail(googleEmail);

        if (savedCompany.isEmpty()) {
            // Has no email account --> Register
            String tempToken = jweTokenService.generateTempTokenForGoogleAuth(googleEmail, googleId);

            return GoogleOAuthResponseDto.builder()
                    .tempToken(tempToken)
                    .tempTokenExpiresIn(jweConfig.getTempTokenTtlSeconds())
                    .email(googleEmail)
                    .name(googleName)
                    .build();
        }

        // Has email but no sso --> Duplicated
        if (savedCompany.get().getSsoToken() == null) {
            throw new CompanyAccountAlreadyExisted(String.format("Email: %s is already existed.", googleEmail));
        }

        if (!savedCompany.get().getSsoToken().equals(googleId)) {
            throw new InvalidCredentialsException(String.format(String.format("Google ID does not match the stored Google ID for the email address: %s. This account is linked to a different Google account.", googleEmail)));
        }
        // Has email and sso --> Login
        TokenPairDto tokenPairDto = jweTokenService.generateTokenPairDto(
                savedCompany.get().getCompanyId(),
                savedCompany.get().getEmail(),
                Role.COMPANY,
                savedCompany.get().isActivated()
        );

        return GoogleOAuthResponseDto.builder()
                .tokenPairDto(tokenPairDto)
                .companyId(savedCompany.get().getCompanyId().toString())
                .email(savedCompany.get().getEmail())
                .build();
    }

    @Override
    public GoogleIdToken.Payload verifyAndGetGoogleIdTokenPayload(String authorizationCode, boolean isLinking) throws IOException {
        GoogleTokenResponse responseToken = new GoogleAuthorizationCodeTokenRequest(
                NET_HTTP_TRANSPORT,
                GSON_FACTORY,
                "https://oauth2.googleapis.com/token",
                clientId,
                clientSecret,
                authorizationCode,
                isLinking ? redirectLinkUri : redirectLoginUri
        ).execute();

        GoogleIdToken idToken = responseToken.parseIdToken();

        if (!idToken.verifyAudience(Collections.singletonList(clientId))) {
            throw new IllegalArgumentException("Invalid audience 'clientID' in ID token");
        }

        if (!idToken.verifyIssuer("https://accounts.google.com")) {
            throw new IllegalArgumentException("Invalid issuer in ID Token");
        }

        return idToken.getPayload();
    }

    @Override
    public String buildGoogleAuthUrl(boolean isLinking) {
        String encodedRedirectUri = isLinking
                ? URLEncoder.encode(redirectLinkUri, StandardCharsets.UTF_8)
                : URLEncoder.encode(redirectLoginUri, StandardCharsets.UTF_8);

        String state = isLinking ? "link" : "login";

        return UriComponentsBuilder.newInstance()
                .scheme("https").host("accounts.google.com").path("/o/oauth2/v2/auth")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", encodedRedirectUri)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid email profile")
                .queryParam("access_type", "offline")
                .queryParam("prompt", "consent")
                .queryParam("state", state)
                .build()
                .toUriString();
    }
}
