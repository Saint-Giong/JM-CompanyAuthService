package rmit.saintgiong.authapi.internal.dto.oauth;

import lombok.*;
import rmit.saintgiong.authapi.internal.dto.common.TokenPairDto;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GoogleOAuthResponseDto {
    private TokenPairDto tokenPairDto;
    private String registerToken;

    // Access token expiration time in seconds.
    private long registerTokenExpiresIn;

    private String email;
    private String name;

    public GoogleOAuthResponseDto(TokenPairDto tokenPairDto, String registerToken, String email, String name) {
        this.tokenPairDto = tokenPairDto;
        this.registerToken = registerToken;
        this.email = email;
        this.name = name;
    }
}
