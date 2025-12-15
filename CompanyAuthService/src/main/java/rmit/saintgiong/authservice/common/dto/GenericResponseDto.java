package rmit.saintgiong.authservice.common.dto;

import lombok.*;

@Data
@Builder
@Getter @Setter @ToString
@AllArgsConstructor
public class GenericResponseDto<T> {
    private String code;
    private String message;
    private final T data;
}
