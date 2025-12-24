package rmit.saintgiong.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import rmit.saintgiong.authservice.common.config.JweConfig;

@EnableJpaAuditing
@SpringBootApplication
@EnableConfigurationProperties(JweConfig.class)
public class JmCompanyAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(JmCompanyAuthApplication.class, args);
    }

}
