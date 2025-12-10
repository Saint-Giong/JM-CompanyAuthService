package rmit.saintgiong.authservice.common.exception;

public class OtpResendCooldownException extends RuntimeException {

    public OtpResendCooldownException(String message) {
        super(message);
    }
}
