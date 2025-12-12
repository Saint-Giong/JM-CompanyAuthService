package rmit.saintgiong.authservice.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/swagger-ui.html",
                    "/swagger-ui/**",
                    "/api-docs/**",
                    "/api-docs.yaml",
                    "/v3/api-docs/**"
                ).permitAll()
                .requestMatchers("/api/v1/sgjm/auth/register").permitAll()  // Allow public access to registration
                .anyRequest().permitAll()
            )
            .httpBasic(basic -> {})
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
