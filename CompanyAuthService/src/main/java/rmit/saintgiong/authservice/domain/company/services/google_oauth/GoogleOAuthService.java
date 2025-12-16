package rmit.saintgiong.authservice.domain.company.services.google_oauth;


import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleOAuthResponseDto;
import rmit.saintgiong.authapi.internal.google_oauth.InternalGoogleOAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.type.Role;
import rmit.saintgiong.authapi.internal.dto.common.TokenPairDto;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.repository.CompanyAuthRepository;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Slf4j
@Service
public class GoogleOAuthService implements InternalGoogleOAuthInterface {

    @Value("${OAUTH2_CLIENT_ID}")
    private String clientId;

    @Value("${OAUTH2_CLIENT_SECRET}")
    private String clientSecret;

    @Value("${google.oauth2_redirect_uri:http://localhost:8080/dashboard}")
    private String redirectLoginUri;

    @Value("${jwe.register-token-ttl-seconds:300}")  // Default: 5 minutes
    private long registerTokenTtlSeconds;

    private final CompanyAuthRepository companyAuthRepository;
    private final InternalCreateCompanyAuthInterface createCompanyAuthInterface;
    private final JweTokenService jweTokenService;

    private static final GsonFactory gsonFactory = new GsonFactory().getDefaultInstance();
    private static final NetHttpTransport netHttpTransport = new NetHttpTransport();

    @Autowired
    public GoogleOAuthService(CompanyAuthRepository companyAuthRepository, InternalCreateCompanyAuthInterface createCompanyAuthInterface, JweTokenService jweTokenService) {
        this.companyAuthRepository = companyAuthRepository;
        this.createCompanyAuthInterface = createCompanyAuthInterface;
        this.jweTokenService = jweTokenService;
    }

    @Override
    public GoogleOAuthResponseDto authenticateGoogleUser(String authorizationCode) throws IOException {
        GoogleIdToken.Payload googlePayload = verifyAndGetGoogleIdTokenPayload(authorizationCode);

        if (!googlePayload.getEmailVerified()) {
            throw new IllegalArgumentException(String.format("Email: %s is not verified by Google", googlePayload.getEmail()));
        }

        String googleId = googlePayload.getSubject();
        String googleEmail = googlePayload.getEmail();
        String googleName = (String) googlePayload.get("name");

        Optional<CompanyAuthEntity> savedCompany = companyAuthRepository.findByEmail(googleEmail);

        if (savedCompany.isEmpty()) {
            // Has no email account --> Register
            String registerToken = jweTokenService.generateRegistrationTokenForGoogleAuth(googleEmail, googleId);
            return new GoogleOAuthResponseDto(null, registerToken, registerTokenTtlSeconds, googleEmail, googleName);
        }

        CompanyAuthEntity existingCompany = savedCompany.get();
        // Has email but no sso --> Duplicated
        if (existingCompany.getSsoToken() == null) {
            throw new CompanyAccountAlreadyExisted(String.format("Email: %s is already existed.", googleEmail));
        }

        if (!existingCompany.getSsoToken().equals(googleId)) {
            throw new InvalidCredentialsException(String.format("Email: %s contains googleId different from the saved record.", googleEmail));
        }
        // Has email and sso --> Login
        TokenPairDto tokenPairDto = jweTokenService.generateTokenPair(
                existingCompany.getCompanyId(),
                existingCompany.getEmail(),
                Role.COMPANY,
                existingCompany.isActivated()
        );

        return new GoogleOAuthResponseDto(tokenPairDto, null, existingCompany.getEmail(), null);
    }

    @Override
    public GoogleIdToken.Payload verifyAndGetGoogleIdTokenPayload(String authorizationCode) throws IOException  {
        GoogleTokenResponse responseToken = new GoogleAuthorizationCodeTokenRequest(
                netHttpTransport,
                gsonFactory,
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
