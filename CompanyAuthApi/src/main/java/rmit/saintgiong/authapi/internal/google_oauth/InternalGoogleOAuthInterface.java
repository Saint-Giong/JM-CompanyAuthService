package rmit.saintgiong.authapi.internal.google_oauth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;

import java.io.IOException;

public interface InternalGoogleOAuthInterface {
//    public String authenticateGoogleUser(String authorizationCode) throws IOException;
    GoogleIdToken.Payload verifyGoogleAuthentication (String authorizationCode) throws IOException;
    String buildGoogleAuthUrl();
}
