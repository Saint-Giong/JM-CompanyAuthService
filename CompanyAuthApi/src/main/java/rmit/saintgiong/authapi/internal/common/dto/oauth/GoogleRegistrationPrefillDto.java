package rmit.saintgiong.authapi.internal.common.dto.oauth;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleRegistrationPrefillDto {
    private String email;
    private String name;
}
