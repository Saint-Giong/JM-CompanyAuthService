package rmit.saintgiong.authapi.internal.dto.oauth;

import com.google.auto.value.AutoValue;
import lombok.*;
import rmit.saintgiong.shared.token.TokenPairDto;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleOAuthResponseDto {
    private TokenPairDto tokenPairDto;
    private String tempToken;
    private long tempTokenExpiresIn;
    private String companyId;
    private String email;
    private String name;

//    // Constructor for new user registration (temp token flow)
//    public GoogleOAuthResponseDto(TokenPairDto tokenPairDto, String tempToken, long tempTokenExpiresIn, String email, String name) {
//        this.tokenPairDto = tokenPairDto;
//        this.tempToken = tempToken;
//        this.tempTokenExpiresIn = tempTokenExpiresIn;
//        this.email = email;
//        this.name = name;
//    }
//
//    // Constructor for existing user login (token pair flow)
//    public GoogleOAuthResponseDto(TokenPairDto tokenPairDto, String tempToken, String companyId, String email, String name) {
//        this.tokenPairDto = tokenPairDto;
//        this.tempToken = tempToken;
//        this.companyId = companyId;
//        this.email = email;
//        this.name = name;
//    }
}
