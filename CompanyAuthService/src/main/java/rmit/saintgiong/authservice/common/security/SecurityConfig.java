package rmit.saintgiong.authservice.common.security;

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(AbstractHttpConfigurer::disable)
                                .cors(
                                                cors -> cors
                                                                .configurationSource(
                                                                                corsConfigurationSource()))
                                .logout(AbstractHttpConfigurer::disable)
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers(
                                                                "/swagger-ui.html",
                                                                "/swagger-ui/**",
                                                                "/api-docs/**",
                                                                "/api-docs.yaml",
                                                                "/v3/api-docs/**")
                                                .permitAll()
                                                .requestMatchers(
                                                                "/register",
                                                                "/login",
                                                                "/dashboard/**")
                                                .permitAll()
                                                .requestMatchers(
                                                                "/google/redirect-url",
                                                                "/google/auth",
                                                                "/google/register")
                                                .permitAll()
                                                .requestMatchers(
                                                                "/verify-account",
                                                                "/resend-otp")
                                                .permitAll()
                                                .requestMatchers("/logout", "/refresh-token")
                                                .permitAll()
                                                .requestMatchers(
                                                                "/actuator/**")
                                                .permitAll()

                                                .anyRequest().authenticated());

                return http.build();
        }

        @Bean
        public UrlBasedCorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(Collections.singletonList("*"));
                configuration.setAllowedMethods(Collections.singletonList("*"));
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }
}
