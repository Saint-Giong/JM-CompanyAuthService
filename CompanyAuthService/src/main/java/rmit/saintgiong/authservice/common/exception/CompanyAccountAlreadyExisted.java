package rmit.saintgiong.authservice.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class CompanyAccountAlreadyExisted extends RuntimeException {
    public CompanyAccountAlreadyExisted(String message) {
        super(message);
    }
}
