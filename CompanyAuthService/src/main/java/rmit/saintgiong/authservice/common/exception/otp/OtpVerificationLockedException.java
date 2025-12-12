package rmit.saintgiong.authservice.common.exception.otp;

public class OtpVerificationLockedException extends RuntimeException {

    public OtpVerificationLockedException(String message) {
        super(message);
    }
}
