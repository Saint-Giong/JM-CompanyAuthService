package rmit.saintgiong.authapi.internal.common.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CompanyUpdatePasswordRequestDto {

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 number, 1 special character, and 1 uppercase letter"
    )
    @Schema(description = "Account password", example = "SecurePassword123!")
    private String currentPassword;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 number, 1 special character, and 1 uppercase letter"
    )
    @Schema(description = "Account password", example = "SecurePassword123!")
    private String newPassword;
}
