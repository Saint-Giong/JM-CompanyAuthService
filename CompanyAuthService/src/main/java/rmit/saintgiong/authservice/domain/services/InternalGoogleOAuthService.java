package rmit.saintgiong.authservice.domain.services;


import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleOAuthResponseDto;
import rmit.saintgiong.authapi.internal.service.InternalGoogleOAuthInterface;
import rmit.saintgiong.authservice.common.config.JweConfig;
import rmit.saintgiong.shared.type.Role;
import rmit.saintgiong.shared.token.TokenPairDto;
import rmit.saintgiong.authservice.common.exception.resources.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.token.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.utils.JweTokenService;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class InternalGoogleOAuthService implements InternalGoogleOAuthInterface {

    @Value("${OAUTH2_CLIENT_ID}")
    private String clientId;

    @Value("${OAUTH2_CLIENT_SECRET}")
    private String clientSecret;

    @Value("${google.oauth2-redirect-uri:http://localhost:8180/dashboard}")
    private String redirectLoginUri;

    private final CompanyAuthRepository companyAuthRepository;
    private final JweTokenService jweTokenService;
    private final JweConfig jweConfig;

    private static final GsonFactory GSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final NetHttpTransport NET_HTTP_TRANSPORT = new NetHttpTransport();

    @Override
    public GoogleOAuthResponseDto authenticateGoogleUser(String authorizationCode) throws IOException {
        String decodedAuthorizationCode = URLDecoder.decode(authorizationCode, StandardCharsets.UTF_8);
        GoogleIdToken.Payload googlePayload = verifyAndGetGoogleIdTokenPayload(decodedAuthorizationCode);

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
    public GoogleIdToken.Payload verifyAndGetGoogleIdTokenPayload(String authorizationCode) throws IOException  {
        GoogleTokenResponse responseToken = new GoogleAuthorizationCodeTokenRequest(
                NET_HTTP_TRANSPORT,
                GSON_FACTORY,
                "https://oauth2.googleapis.com/token",
                clientId,
                clientSecret,
                authorizationCode,
                redirectLoginUri
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
    public String buildGoogleAuthUrl() {
        return UriComponentsBuilder.newInstance()
                .scheme("https").host("accounts.google.com").path("/o/oauth2/v2/auth")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectLoginUri)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid email profile")
                .queryParam("access_type", "offline")
                .queryParam("prompt", "consent")
                .queryParam("state", "login")
                .build()
                .toUriString();
    }
}
