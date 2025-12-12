package rmit.saintgiong.authservice.common.exception.otp;

public class OtpHourlyLimitExceededException extends RuntimeException {

    public OtpHourlyLimitExceededException(String message) {
        super(message);
    }
}
