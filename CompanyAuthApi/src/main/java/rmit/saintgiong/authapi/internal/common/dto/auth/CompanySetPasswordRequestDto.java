package rmit.saintgiong.authapi.internal.common.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CompanySetPasswordRequestDto {

    @NotNull(message = "Company ID cannot be NULL")
    @Schema(description = "Company ID", example = "123e4567-e89b-12d3-a456-426614174000")
    private String companyId;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[A-Z]).+$",
            message = "Password must contain at least 1 number, 1 special character, and 1 uppercase letter"
    )
    @Schema(description = "New password for the account", example = "SecurePassword123!")
    private String password;
}

