package rmit.saintgiong.authservice.common.util;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


@Slf4j
@Component
public class JweTokenUtil {

    @Value("${jwt.secret:your-secret-key-min-256-bits-for-jwe-encryption-security-purpose}")
    private String jwtSecret;

    @Value("${jwt.expiration:86400000}")
    private long jwtExpiration;

}
