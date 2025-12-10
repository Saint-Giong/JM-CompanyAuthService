package rmit.saintgiong.authservice.common.exception;

public class OtpHourlyLimitExceededException extends RuntimeException {

    public OtpHourlyLimitExceededException(String message) {
        super(message);
    }
}
