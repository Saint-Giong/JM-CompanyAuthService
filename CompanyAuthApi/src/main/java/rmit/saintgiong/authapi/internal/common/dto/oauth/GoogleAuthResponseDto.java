package rmit.saintgiong.authapi.internal.common.dto.oauth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleAuthResponseDto {
    private String companyId;
    private String email;
    private String name;
}
