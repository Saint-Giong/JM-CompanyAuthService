package rmit.saintgiong.authapi.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * DTO for company login response.
 * Contains authentication tokens and account activation status.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CompanyLoginResponseDto {
    private boolean success;
    private boolean isActivated;
    private String message;
}
