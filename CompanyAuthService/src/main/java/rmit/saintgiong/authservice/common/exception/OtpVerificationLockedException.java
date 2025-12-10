package rmit.saintgiong.authservice.common.exception;

public class OtpVerificationLockedException extends RuntimeException {

    public OtpVerificationLockedException(String message) {
        super(message);
    }
}
