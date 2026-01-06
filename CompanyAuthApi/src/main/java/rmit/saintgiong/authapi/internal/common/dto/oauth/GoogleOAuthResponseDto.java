package rmit.saintgiong.authapi.internal.common.dto.oauth;

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
}
