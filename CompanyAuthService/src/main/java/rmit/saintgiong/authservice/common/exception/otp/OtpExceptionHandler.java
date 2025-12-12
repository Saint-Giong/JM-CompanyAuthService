package rmit.saintgiong.authservice.common.exception.otp;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import rmit.saintgiong.authservice.common.dto.ErrorResponseDto;

import java.time.LocalDateTime;

@RestControllerAdvice
public class OtpExceptionHandler {

    @ExceptionHandler({
            OtpVerificationLockedException.class,
            OtpResendCooldownException.class,
            OtpHourlyLimitExceededException.class
    })
    public ResponseEntity<ErrorResponseDto> handleOtpRateLimitExceptions(
            RuntimeException exception,
            WebRequest request
    ) {
        ErrorResponseDto errorResponseDto = ErrorResponseDto.builder()
                .apiPath(request.getDescription(false).replace("uri=", ""))
                .errorCode(HttpStatus.TOO_MANY_REQUESTS)
                .message(exception.getMessage())
                .timeStamp(LocalDateTime.now())
                .build();

        return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .body(errorResponseDto);
    }
}
