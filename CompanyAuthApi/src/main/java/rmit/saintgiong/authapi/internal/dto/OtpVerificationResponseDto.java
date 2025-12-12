package rmit.saintgiong.authapi.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for OTP verification response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OtpVerificationResponseDto {
    private boolean success;
    private String message;
}
