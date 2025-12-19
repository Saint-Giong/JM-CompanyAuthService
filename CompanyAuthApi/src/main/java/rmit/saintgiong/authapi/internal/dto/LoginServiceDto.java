package rmit.saintgiong.authapi.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginServiceDto {
    private boolean success;
    private boolean isActivated;
    private String message;
    private String accessToken;
    private String refreshToken;
    private String companyId;
}
