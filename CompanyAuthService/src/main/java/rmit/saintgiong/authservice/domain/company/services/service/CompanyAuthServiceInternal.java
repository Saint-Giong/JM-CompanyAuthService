package rmit.saintgiong.authservice.domain.company.services.service;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.company.model.CompanyAuth;

import java.util.Optional;

@Service
@AllArgsConstructor
@Slf4j
public class CompanyAuthServiceInternal implements InternalCreateCompanyAuthInterface {

    private final CompanyAuthMapper companyAuthMapper;
    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public CompanyAuthRegistrationResponseDto registerCompany(CompanyRegistrationDto registrationDto) {
        // Check if email already exists
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(registrationDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        // Convert DTO to model
        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationDto(registrationDto);
        
        // Encode password in the model
        companyAuth.setHashedPassword(passwordEncoder.encode(registrationDto.getPassword()));

        // Convert model to entity and save
        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));

        //TODO: Add kafka publisher to create profile
        

        return CompanyAuthRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Company registered successfully. Please check your email for activation link.")
                .build();
    }
}
