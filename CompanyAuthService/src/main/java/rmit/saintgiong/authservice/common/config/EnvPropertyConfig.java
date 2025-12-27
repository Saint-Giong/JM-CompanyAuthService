package rmit.saintgiong.authservice.common.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(
        value = {
                "file: ./CompanyAuthService/.auth.env",
                "file: ./.auth.env"
        }, ignoreResourceNotFound = true)
public class EnvPropertyConfig {
}
