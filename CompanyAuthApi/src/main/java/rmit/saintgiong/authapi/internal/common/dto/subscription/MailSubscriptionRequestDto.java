package rmit.saintgiong.authapi.internal.common.dto.subscription;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MailSubscriptionRequestDto {

    @NotNull (message = "companyId can not be null")
    private UUID companyId;

    private long expiredInMs;
}
