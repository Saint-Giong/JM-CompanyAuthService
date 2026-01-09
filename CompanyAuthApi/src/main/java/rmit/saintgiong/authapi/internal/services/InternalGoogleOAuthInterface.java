package rmit.saintgiong.authapi.internal.services;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import jakarta.servlet.http.HttpServletResponse;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleAuthResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleOAuthResponseDto;

import java.io.IOException;

public interface InternalGoogleOAuthInterface {
    void handleLinkGoogleToAccount (String companyId, String code, boolean isLink, boolean isRelink) throws IOException;
    GoogleAuthResponseDto handleGoogleAuthentication (HttpServletResponse response, String code) throws IOException;
    GoogleOAuthResponseDto authenticateGoogleUser(String authorizationCode) throws IOException;
    GoogleIdToken.Payload verifyAndGetGoogleIdTokenPayload(String authorizationCode, boolean isLinking) throws IOException;
    String buildGoogleAuthUrl(boolean isLinking);
}
