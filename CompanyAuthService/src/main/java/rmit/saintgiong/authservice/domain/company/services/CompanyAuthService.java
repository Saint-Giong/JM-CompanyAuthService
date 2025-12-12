package rmit.saintgiong.authservice.domain.company.services;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGetCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalUpdateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.auth.type.Role;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;
import rmit.saintgiong.authservice.common.dto.TokenPairDto;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;
import rmit.saintgiong.authservice.common.exception.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.util.EmailService;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.common.util.OtpService;
import rmit.saintgiong.authservice.common.util.TokenStorageService;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.company.model.CompanyAuth;

import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
@Slf4j
public class CompanyAuthService implements InternalCreateCompanyAuthInterface , InternalGetCompanyAuthInterface, InternalUpdateCompanyAuthInterface {

    private final CompanyAuthMapper companyAuthMapper;
    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TokenStorageService tokenStorageService;
    private final OtpService otpService;
    private final JweTokenService jweTokenService;

    /**
     * Registers a new company with the authentication system.
     * 
     * @param registrationDto the company registration data transfer object containing
     *                        the email, password, and other registration details
     * @return a {@link CompanyRegistrationResponseDto} containing the registered
     *         company's ID, email, success status, and a confirmation message
     */
    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto registrationDto) {
        // Check if email already exists
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(registrationDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        // Convert DTO to model
        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationDto(registrationDto);
        
        // Encode password in the model
        companyAuth.setHashedPassword(passwordEncoder.encode(registrationDto.getPassword()));

        // Convert model to entity and save (isActivated remains false)
        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));

        //TODO: Add kafka publisher to create profile

        // Generate OTP and store in Redis with 2-minute TTL
        String otp = otpService.generateOtp(savedAuth.getCompanyId());
        // Send OTP email
        emailService.sendOtpEmail(registrationDto.getEmail(), registrationDto.getCompanyName(), otp);
        
        return CompanyRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Company registered successfully. Please check your email for the OTP to activate your account.")
                .build();
    }

    /**
     * Authenticates a company with email and password.
     * If account is not activated, generates and sends a new OTP.
     *
     * @param loginDto The login credentials
     * @return CompanyLoginResponseDto with authentication result and tokens if activated
     */
    @Transactional
    @Override
    public LoginServiceDto authenticateWithEmailAndPassword(CompanyLoginRequestDto loginDto) {
        // Find company by email
        CompanyAuthEntity companyAuth = companyAuthRepository.findByEmail(loginDto.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));
        
        // Verify password
        if (!passwordEncoder.matches(loginDto.getPassword(), companyAuth.getHashedPassword())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        // Generate token pair for valid credential
        TokenPairDto tokenPair = jweTokenService.generateTokenPair(
                companyAuth.getCompanyId(),
                companyAuth.getEmail(),
                Role.COMPANY,
                companyAuth.isActivated()
        );

        log.info("Company logged in successfully: {}", companyAuth.getEmail());
        
        return LoginServiceDto.builder()
                .success(true)
                .isActivated(companyAuth.isActivated())
                .message("Login successful. " + (companyAuth.isActivated() ? "Account activated!" : "This account is inactivated. Please activate"))
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken())
                .build();
    }

    /**
     * Verifies the OTP and activates the company account.
     *
     * @param companyId The company ID (extracted from JWE token)
     * @param otp       The OTP provided by the user
     */
    @Override
    @Transactional
    public void verifyOtpAndActivateAccount(UUID companyId, String otp) {
        // Verify OTP
        if (!otpService.verifyOtp(companyId, otp)) {
            throw new InvalidTokenException("Invalid or expired OTP");
        }
        
        // Find the company by ID
        CompanyAuthEntity companyAuth = companyAuthRepository.findById(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("companyId","","Company not found"));
        
        // Activate the company account
        companyAuth.setActivated(true);
        companyAuthRepository.save(companyAuth);
        
        log.info("Company account activated successfully for company ID: {}", companyId);
    }

    /**
     * Resends OTP to the company email.
     *
     * @param companyId The company ID
     */
    @Override
    @Transactional
    public void resendOtp(UUID companyId) {
        // Find the company by ID
        CompanyAuthEntity companyAuth = companyAuthRepository.findById(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("companyId","","Company not found"));
        
        if (companyAuth.isActivated()) {
            throw new IllegalStateException("Account is already activated");
        }

        
        // Invalidate and Generate new OTP
        String otp = otpService.invalidateExistingAndGenerateNewOtp(companyId);
        
        // Send OTP email
        //TODO: replace company email with company name
        emailService.sendOtpEmail(companyAuth.getEmail(), companyAuth.getEmail(), otp);
        
        log.info("OTP resent to company: {}", companyAuth.getEmail());
    }

}
