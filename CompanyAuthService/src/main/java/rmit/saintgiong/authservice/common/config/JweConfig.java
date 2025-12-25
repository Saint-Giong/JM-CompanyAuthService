package rmit.saintgiong.authservice.common.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwe")
@Data
public class JweConfig {
    @Value("${jwe.issuer}")
    private String issuer;

    @Value("${jwe.register-token-ttl-seconds:300}")  // Default: 5 minutes
    private int registerTokenTtlSeconds;

    @Value("${jwe.access-token-ttl-seconds:900}")  // Default: 15 minutes
    private int accessTokenTtlSeconds;

    @Value("${jwe.refresh-token-ttl-seconds:604800}")  // Default: 7 days
    private int refreshTokenTtlSeconds;
}