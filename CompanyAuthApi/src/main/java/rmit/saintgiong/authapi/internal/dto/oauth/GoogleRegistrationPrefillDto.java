package rmit.saintgiong.authapi.internal.dto.oauth;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GoogleRegistrationPrefillDto {
    private String email;
    private String name;
}
