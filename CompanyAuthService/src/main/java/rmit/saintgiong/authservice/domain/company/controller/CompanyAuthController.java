package rmit.saintgiong.authservice.domain.company.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authapi.internal.service.CreateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.util.RsaJweService;

import java.util.Map;
import java.util.concurrent.Callable;

@RestController
@RequestMapping("/api/v1/sgjm/auth") //TODO: keep for testing purpose, will be removed when deployed with API Gateway
@AllArgsConstructor
public class CompanyAuthController {

    private final CreateCompanyAuthInterface companyAuthService;

    private final RsaJweService rsaJweService;

    @PostMapping("/register")
    public Callable<ResponseEntity<CompanyAuthRegistrationResponseDto>> registerCompany(
            @Valid @RequestBody CompanyRegistrationDto registrationDto) {
        return () -> {
            CompanyAuthRegistrationResponseDto response = companyAuthService.registerCompany(registrationDto);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        };
    }

    @PostMapping("/generate")
    public String generateToken(@RequestBody Map<String, Object> secretData) {
        try {
            // Encrypt with a 1-hour expiration (3600 seconds)
            return rsaJweService.encrypt(secretData, 3600);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @PostMapping("/decrypt")
    public Map<String, Object> decryptToken(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            if (token == null) {
                throw new IllegalArgumentException("Token is required");
            }
            return rsaJweService.decrypt(token);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed or token expired", e);
        }
    }

    @PostMapping("/inspect")
    public Map<String, Object> inspectToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        try {
            return rsaJweService.inspect(token);
        } catch (Exception e) {
            throw new RuntimeException("Could not inspect token", e);
        }
    }


}
