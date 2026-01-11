package rmit.saintgiong.authapi.internal.common.dto.subscription;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MailSubscriptionRequestDtoList {

    private List<MailSubscriptionRequestDto> requestDtos;
}
