package rmit.saintgiong.authapi.internal.common.dto.auth;

import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import rmit.saintgiong.shared.token.TokenPairDto;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CompanyRegistrationResponseDto {
    private UUID companyId;
    private String email;
    private String message;
    private boolean success;
    private TokenPairDto tokenPair; // For SSO registrations - allows immediate login
}
