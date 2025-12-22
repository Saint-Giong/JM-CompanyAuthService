package rmit.saintgiong.authservice.common.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

// OpenAPI/Swagger configuration for API documentation.
@Configuration
public class OpenApiConfig {

//    @Value("${server.port:8080}") should follow docker port mapping
    private String serverPort = "8180";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Company Auth Service API")
                        .version("1.0.0")
                        .description("Authentication and Authorization service for company accounts. " +
                                "Provides endpoints for company registration, login, token management, and account activation.")
                        .contact(new Contact()
                                .name("Saint Giong Team")
                                .email("support@saintgiong.rmit.edu.vn"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:" + serverPort)
                                .description("Local Development Server")))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWE")
                                .description("JWE Access Token for authenticated endpoints")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
