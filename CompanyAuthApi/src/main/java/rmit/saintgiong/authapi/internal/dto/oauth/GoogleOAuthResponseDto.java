package rmit.saintgiong.authapi.internal.dto.oauth;

import lombok.*;
import rmit.saintgiong.shared.token.TokenPairDto;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GoogleOAuthResponseDto {
    private TokenPairDto tokenPairDto;
    private String tempToken;
    // Access token expiration time in seconds.
    private long tempTokenExpiresIn;

    private String email;
    private String name;

    public GoogleOAuthResponseDto(TokenPairDto tokenPairDto, String tempToken, String email, String name) {
        this.tokenPairDto = tokenPairDto;
        this.tempToken = tempToken;
        this.email = email;
        this.name = name;
    }
}
