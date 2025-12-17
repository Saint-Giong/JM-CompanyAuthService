package rmit.saintgiong.authapi.internal.service.google_oauth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleOAuthResponseDto;

import java.io.IOException;

public interface InternalGoogleOAuthInterface {
    GoogleOAuthResponseDto authenticateGoogleUser(String authorizationCode) throws IOException;
    GoogleIdToken.Payload verifyAndGetGoogleIdTokenPayload(String authorizationCode) throws IOException;
    String buildGoogleAuthUrl();
}
