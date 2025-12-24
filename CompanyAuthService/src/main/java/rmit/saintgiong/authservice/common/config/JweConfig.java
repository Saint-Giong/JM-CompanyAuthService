package rmit.saintgiong.authservice.common.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwe")
@Data // Lombok getter/setter
public class JweConfig {
    private String issuer;
    private int registerTokenTtlSeconds;
    private int accessTokenTtlSeconds;
    private int refreshTokenTtlSeconds;
}