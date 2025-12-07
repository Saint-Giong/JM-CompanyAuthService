package rmit.saintgiong.authservice.domain.company.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.auth.Role;
import rmit.saintgiong.authservice.common.dto.TokenClaimsDto;
import rmit.saintgiong.authservice.common.dto.TokenPairDto;
import rmit.saintgiong.authservice.common.util.JweTokenService;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;

@RestController
@RequestMapping("/api/v1/sgjm/auth") //TODO: keep for testing purpose, will be removed when deployed with API Gateway
@AllArgsConstructor
public class CompanyAuthController {

    private final InternalCreateCompanyAuthInterface companyAuthService;
    private final JweTokenService jweTokenService;

    /**
     * Registers a new company account.
     * 
     * @param registrationDto the company registration details containing email, password,
     *                        and other required information
     * @return a {@link Callable} that returns a {@link ResponseEntity} containing
     *         the registration response with company ID, email, and success status
     */
    @PostMapping("/register")
    public Callable<ResponseEntity<CompanyAuthRegistrationResponseDto>> registerCompany(
            @Valid @RequestBody CompanyRegistrationDto registrationDto) {
        return () -> {
            CompanyAuthRegistrationResponseDto response = companyAuthService.registerCompany(registrationDto);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        };
    }
// Endpoint to test JWE token service
//    @PostMapping("/test/generate-token")
//    public ResponseEntity<TokenPairDto> generateTestToken(@RequestBody Map<String, String> request) {
//        UUID userId = UUID.fromString(request.getOrDefault("userId", UUID.randomUUID().toString()));
//        String email = request.getOrDefault("email", "test@example.com");
//        Role role = Role.valueOf(request.getOrDefault("role", "COMPANY"));
//
//        TokenPairDto tokenPair = jweTokenService.generateTokenPair(userId, email, role);
//        return ResponseEntity.ok(tokenPair);
//    }
//
//    @PostMapping("/test/validate-access-token")
//    public ResponseEntity<TokenClaimsDto> validateAccessToken(@RequestBody Map<String, String> request) {
//        String accessToken = request.get("accessToken");
//        TokenClaimsDto claims = jweTokenService.validateAccessToken(accessToken);
//        return ResponseEntity.ok(claims);
//    }
//
//    @PostMapping("/test/refresh-token")
//    public ResponseEntity<TokenPairDto> refreshToken(@RequestBody Map<String, String> request) {
//        String refreshToken = request.get("refreshToken");
//        TokenPairDto tokenPair = jweTokenService.refreshAccessToken(refreshToken);
//        return ResponseEntity.ok(tokenPair);
//    }
}
