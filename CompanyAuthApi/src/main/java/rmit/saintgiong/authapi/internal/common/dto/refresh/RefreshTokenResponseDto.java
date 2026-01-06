package rmit.saintgiong.authapi.internal.common.dto.refresh;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for refresh token response.
 * Contains the result of token refresh operation.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshTokenResponseDto {
    private boolean success;
    private String message;
    private String companyId;
}
