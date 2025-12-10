package rmit.saintgiong.authservice.domain.company.services;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalUpdateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;
import rmit.saintgiong.authservice.common.exception.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.util.EmailService;
import rmit.saintgiong.authservice.common.util.TokenStorageService;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.company.model.CompanyAuth;

import java.util.Optional;

@Service
@AllArgsConstructor
@Slf4j
public class CompanyAuthServiceInternal implements InternalCreateCompanyAuthInterface, InternalUpdateCompanyAuthInterface {

    private final CompanyAuthMapper companyAuthMapper;
    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TokenStorageService tokenStorageService;

    /**
     * Registers a new company with the authentication system.
     * 
     * @param registrationDto the company registration data transfer object containing
     *                        the email, password, and other registration details
     * @return a {@link CompanyAuthRegistrationResponseDto} containing the registered
     *         company's ID, email, success status, and a confirmation message
     */
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

        // Generate UUID-based activation token and store in Redis
        String activationToken = java.util.UUID.randomUUID().toString();
        tokenStorageService.storeActivationToken(activationToken, savedAuth.getCompanyId(), registrationDto.getEmail());

        emailService.sendVerificationEmail(registrationDto.getEmail(), registrationDto.getCompanyName(), activationToken);
        return CompanyAuthRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Company registered successfully. Please check your email for activation link.")
                .build();
    }

    @Override
    @Transactional
    public void activateCompanyAccount(String activationToken) {
        // Retrieve activation token data from Redis
        String[] tokenData = tokenStorageService.getActivationTokenData(activationToken);
        if (tokenData == null) {
            throw new InvalidTokenException("Activation token has been used or expired");
        }
        
        java.util.UUID companyId = java.util.UUID.fromString(tokenData[0]);
        String email = tokenData[1];
        
        // Find the company by ID
        CompanyAuthEntity companyAuth = companyAuthRepository.findById(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("Company not found"));
        
        // Activate the company account
        companyAuth.setActivated(true);
        companyAuthRepository.save(companyAuth);
        
        // Consume the activation token (remove from Redis)
        tokenStorageService.consumeActivationToken(activationToken);
        
        log.info("Company account activated successfully for: {}", email);
    }
}
