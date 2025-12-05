package rmit.saintgiong.authservice.domain.company.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authapi.internal.service.CreateCompanyAuthInterface;

@RestController
@RequestMapping("/api/v1/sgjm/auth") //TODO: keep for testing purpose, will be removed when deployed with API Gateway
@AllArgsConstructor
public class CompanyAuthController {

    private final CreateCompanyAuthInterface companyAuthService;


    @PostMapping("/register")
    public ResponseEntity<CompanyAuthRegistrationResponseDto> registerCompany(
            @Valid @RequestBody CompanyRegistrationDto registrationDto) {
        CompanyAuthRegistrationResponseDto response = companyAuthService.registerCompany(registrationDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
