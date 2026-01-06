package rmit.saintgiong.authapi.internal.common.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordOperationResponseDto {

    @Schema(description = "Operation success status", example = "true")
    private boolean success;

    @Schema(description = "Response message", example = "Password operation completed successfully")
    private String message;
}