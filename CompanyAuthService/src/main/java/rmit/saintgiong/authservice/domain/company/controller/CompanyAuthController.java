package rmit.saintgiong.authservice.domain.company.controller;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authservice.domain.company.dto.CompanyAuthResponseDto;
import rmit.saintgiong.authservice.domain.company.dto.CompanyRegistrationDto;
import rmit.saintgiong.authservice.domain.company.services.service.CompanyAuthService;

@RestController
@RequestMapping("/api/v1/sgjm/auth")
@AllArgsConstructor
public class CompanyAuthController {

    private final CompanyAuthService companyAuthService;


    @PostMapping("/register")
    public ResponseEntity<CompanyAuthResponseDto> registerCompany(
            @Valid @RequestBody CompanyRegistrationDto registrationDto) {
        CompanyAuthResponseDto response = companyAuthService.registerCompany(registrationDto);
        
        if (response.isSuccess()) {
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}
