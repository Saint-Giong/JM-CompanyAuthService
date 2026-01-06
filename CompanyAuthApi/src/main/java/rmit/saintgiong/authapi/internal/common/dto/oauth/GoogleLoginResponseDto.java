package rmit.saintgiong.authapi.internal.common.dto.oauth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for existing Google SSO user login.
 * Contains companyId and email for the frontend to use.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleLoginResponseDto {
    private String companyId;
    private String email;
}
