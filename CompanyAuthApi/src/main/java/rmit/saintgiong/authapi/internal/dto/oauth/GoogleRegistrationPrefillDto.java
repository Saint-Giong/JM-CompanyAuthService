package rmit.saintgiong.authapi.internal.dto.oauth;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GoogleRegistrationPrefillDto {
    private String email;
    private String name;
}
