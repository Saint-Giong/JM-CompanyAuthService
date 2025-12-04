package rmit.saintgiong.authservice.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponseDto {
    private int status;
    private String message;
    private String error;
    private LocalDateTime timestamp;
    private Map<String, String> fieldErrors; // For validation errors
    private String path;
}
