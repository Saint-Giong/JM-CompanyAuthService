package rmit.saintgiong.authservice.domain.company.services.google_oauth;


import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import rmit.saintgiong.authapi.internal.google_oauth.InternalGoogleOAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.util.TokenStorageService;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.repository.CompanyAuthRepository;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
public class GoogleOAuthService implements InternalGoogleOAuthInterface {

    @Value("${OAUTH2_CLIENT_ID}")
    private String clientId;

    @Value("${OAUTH2_CLIENT_SECRET}")
    private String clientSecret;

    @Value("${OAUTH2_REDIRECT_URI:http://localhost:8080/dashboard}")
    private String redirectLoginUri;

    private CompanyAuthRepository companyAuthRepository;
    private InternalCreateCompanyAuthInterface createCompanyAuthInterface;

    private static final GsonFactory gsonFactory = new GsonFactory().getDefaultInstance();
    private static final NetHttpTransport netHttpTransport = new NetHttpTransport();

    @Autowired
    public GoogleOAuthService(CompanyAuthRepository companyAuthRepository, InternalCreateCompanyAuthInterface createCompanyAuthInterface) {
        this.companyAuthRepository = companyAuthRepository;
        this.createCompanyAuthInterface = createCompanyAuthInterface;
    }

//    @Override
//    public String authenticateGoogleUser(String authorizationCode) throws IOException {
//        GoogleIdToken.Payload googlePayload = verifyGoogleAuthentication(authorizationCode);
//
//        if (!googlePayload.getEmailVerified()) {
//            throw new IllegalArgumentException(String.format("Email: %s is not verified by Google", googlePayload.getEmail()));
//        }
//
//        String googleId = googlePayload.getSubject();
//        String googleEmail = googlePayload.getEmail();
//
//        Optional<CompanyAuthEntity> savedCompanyRecord = companyAuthRepository.findByCompanyId(googleId);
//        Optional<CompanyAuthEntity> savedCompanyWithEmail = companyAuthRepository.findByEmail(googleEmail);
//
//        CompanyAuthEntity resolvedCompany;
//
//        if (savedCompanyRecord.isEmpty()) {
//            if (savedCompanyWithEmail.isPresent()) {
//                throw new CompanyAccountAlreadyExisted(String.format("Email: %s is already existed.", googleEmail));
//            }
//
//            resolvedCompany = CompanyAuthEntity.builder()
//                    .companyId(UUID.fromString(googleId))
//                    .email(googleEmail)
//                    .hashedPassword(null)
//                    .ssoProvider("Google")
//                    .isActivated(false)
//                    .build();
//
//        } else {
//            resolvedCompany = savedCompanyRecord.get();
//        }
//
//
//        return "";
//    }

    @Override
    public GoogleIdToken.Payload verifyGoogleAuthentication(String authorizationCode) throws IOException {
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
        String base = "https://accounts.google.com/o/oauth2/v2/auth";

        return UriComponentsBuilder.fromPath(base)
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
