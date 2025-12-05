package rmit.saintgiong.authservice.domain.company.services.service;

import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authapi.internal.service.CreateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;

import java.util.Optional;

@Service
@AllArgsConstructor
public class CompanyAuthService implements CreateCompanyAuthInterface {

    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;

    public CompanyAuthRegistrationResponseDto registerCompany(CompanyRegistrationDto registrationDto) {
        // Check if email already exists
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(registrationDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        // Create and save CompanyAuth
        CompanyAuthEntity companyAuth = CompanyAuthEntity.builder()
                                            .email(registrationDto.getEmail())
                                            .hashedPassword(passwordEncoder.encode(registrationDto.getPassword()))
                                            .isActivated(false)
                                            .build();

        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuth);

        //TODO: Add kafka publisher to create profile
        

        return CompanyAuthRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Company registered successfully. Please check your email for activation link.")
                .build();
    }
}
