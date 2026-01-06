package rmit.saintgiong.authapi.internal.common.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for logout response.
 * Contains the result of logout operation.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogoutResponseDto {
    private boolean success;
    private String message;
}
