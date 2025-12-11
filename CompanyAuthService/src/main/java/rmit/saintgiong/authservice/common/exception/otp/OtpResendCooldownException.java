package rmit.saintgiong.authservice.common.exception.otp;

public class OtpResendCooldownException extends RuntimeException {

    public OtpResendCooldownException(String message) {
        super(message);
    }
}
