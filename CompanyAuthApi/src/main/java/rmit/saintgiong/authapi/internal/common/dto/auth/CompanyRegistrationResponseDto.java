package rmit.saintgiong.authapi.internal.common.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CompanyRegistrationResponseDto {
    private UUID companyId;
    private String email;
    private String message;
    private boolean success;
}
