package rmit.saintgiong.authapi.internal.dto.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// DTO containing the token pair (access + refresh) returned upon successful login.
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenPairDto {
    
    // Short-lived access token (JWE encrypted).
    // Contains user identity information (user ID, role).
    private String accessToken;
    
    // Longer-lived refresh token (JWE encrypted).
    // Used to get new access tokens without re-authentication.
    private String refreshToken;
    
    // Access token expiration time in seconds.
    private long accessTokenExpiresIn;
    
    // Refresh token expiration time in seconds.
    private long refreshTokenExpiresIn;
}
