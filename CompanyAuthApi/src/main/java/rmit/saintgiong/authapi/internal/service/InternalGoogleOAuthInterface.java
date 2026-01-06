package rmit.saintgiong.authapi.internal.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleOAuthResponseDto;

import java.io.IOException;

public interface InternalGoogleOAuthInterface {
    GoogleOAuthResponseDto authenticateGoogleUser(String authorizationCode) throws IOException;
    GoogleIdToken.Payload verifyAndGetGoogleIdTokenPayload(String authorizationCode) throws IOException;
    String buildGoogleAuthUrl();
}
