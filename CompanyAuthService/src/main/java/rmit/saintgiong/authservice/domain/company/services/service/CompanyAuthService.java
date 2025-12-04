package rmit.saintgiong.authservice.domain.company.services.service;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authservice.domain.company.dto.CompanyAuthResponseDto;
import rmit.saintgiong.authservice.domain.company.dto.CompanyRegistrationDto;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuth;

import java.util.Optional;

@Service
@AllArgsConstructor
public class CompanyAuthService {


    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;

    public CompanyAuthResponseDto registerCompany(CompanyRegistrationDto registrationDto) {
        // Check if email already exists
        Optional<CompanyAuth> existingAuth = companyAuthRepository.findByEmail(registrationDto.getEmail());
        if (existingAuth.isPresent()) {
            return CompanyAuthResponseDto.builder()
                    .success(false)
                    .message("Email already registered")
                    .build();
        }

        // Create and save CompanyAuth
        CompanyAuth companyAuth = CompanyAuth.builder()
                                            .email(registrationDto.getEmail())
                                            .hashedPassword(passwordEncoder.encode(registrationDto.getPassword()))
                                            .isActivated(false)
                                            .build();

        CompanyAuth savedAuth = companyAuthRepository.save(companyAuth);

        //TODO: Add kafka publisher to create profile
        

        return CompanyAuthResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Company registered successfully. Please check your email for activation link.")
                .build();
    }
}
