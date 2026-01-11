package rmit.saintgiong.authservice.domain.services.internal;

import java.util.Optional;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import rmit.saintgiong.authapi.external.services.ExternalCompanyAuthRequestInterface;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.LoginServiceDto;
import rmit.saintgiong.authapi.internal.common.dto.otp.ActivationPairDto;
import rmit.saintgiong.authapi.internal.common.dto.subscription.CreateSubscriptionRequestDto;
import rmit.saintgiong.authapi.internal.services.InternalCompanyAuthInterface;
import rmit.saintgiong.authservice.common.exception.resources.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.resources.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.exception.token.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.authservice.common.utils.EmailService;
import rmit.saintgiong.authservice.common.utils.JweTokenService;
import rmit.saintgiong.authservice.common.utils.OtpService;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.model.CompanyAuth;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileResponseRecord;
import rmit.saintgiong.shared.dto.avro.subscription.CreateSubscriptionResponseRecord;
import rmit.saintgiong.shared.token.TokenClaimsDto;
import rmit.saintgiong.shared.token.TokenPairDto;
import rmit.saintgiong.shared.type.CookieType;
import rmit.saintgiong.shared.type.Role;

@Service
@AllArgsConstructor
@Slf4j
public class InternalCompanyAuthService implements InternalCompanyAuthInterface {

    private final ExternalCompanyAuthRequestInterface externalCompanyAuthRequestInterface;

    private final CompanyAuthMapper companyAuthMapper;
    private final CompanyAuthRepository companyAuthRepository;
    private final PasswordEncoder passwordEncoder;

    private final EmailService emailService;
    private final OtpService otpService;
    private final JweTokenService jweTokenService;

    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto requestDto) {
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(requestDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationDto(requestDto);
        companyAuth.setCompanyId(UUID.randomUUID());
        companyAuth.setHashedPassword(passwordEncoder.encode(requestDto.getPassword()));

        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));

        CreateProfileResponseRecord profileResponse = externalCompanyAuthRequestInterface.sendCreateProfileRequest(savedAuth.getCompanyId(), requestDto);
        if (profileResponse.getCompanyId() == null) {
            log.warn("Failed create profile for ID: {}", savedAuth.getCompanyId());
            return CompanyRegistrationResponseDto.builder()
                    .success(false)
                    .email("Failed to create profile for ID: " + savedAuth.getCompanyId())
                    .build();
        }
        log.info("Successfully create profile for ID: {}", profileResponse.getCompanyId());

        // Create Subscription Profile
        CreateSubscriptionRequestDto subscriptionRequestDto = CreateSubscriptionRequestDto.builder()
                .companyId(savedAuth.getCompanyId())
                .build();

        CreateSubscriptionResponseRecord subReponse = externalCompanyAuthRequestInterface.sendCreateSubscriptionRequest(subscriptionRequestDto);
        if (subReponse.getCompanyId() == null) {
            log.warn("Failed create subscription for ID: {}", savedAuth.getCompanyId());
            return CompanyRegistrationResponseDto.builder()
                    .success(false)
                    .email("Failed to create subscription for ID: " + savedAuth.getCompanyId())
                    .build();
        }
        log.info("Successfully create subscription for ID: {}", subReponse.getCompanyId());

        String activationToken = jweTokenService.generateActivationToken(
                savedAuth.getCompanyId(),
                savedAuth.getEmail(),
                Role.COMPANY
        );

        ActivationPairDto activationPairDto = otpService.generateOtp(savedAuth.getCompanyId(), activationToken);
        emailService.sendOtpEmail(requestDto.getEmail(), requestDto.getCompanyName(), activationPairDto.getOtp(), activationPairDto.getActivationToken());

        return CompanyRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Successfully create profile for ID: " + savedAuth.getCompanyId())
                .build();
    }

    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompanyWithGoogleId (
            CompanyRegistrationGoogleRequestDto googleRequestDto,
            String tempToken
    ) {
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(googleRequestDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        String googleId = jweTokenService.getGoogleIdFromJweToken(tempToken);
        String emailFromToken = jweTokenService.getEmailFromJweString(tempToken);
        if (googleId == null || emailFromToken == null) {
            throw new InvalidTokenException("Missing either googleId or email in TEMP_COOKIE.");
        }

        if (!emailFromToken.equals(googleRequestDto.getEmail())) {
            throw new InvalidTokenException("Email in TEMP_COOKIE does not match the registration email.");
        }

        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationGoogleDto(googleRequestDto);
        companyAuth.setCompanyId(UUID.randomUUID());
        companyAuth.setSsoToken(googleId);
        companyAuth.setActivated(true);

        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));
        CompanyRegistrationRequestDto requestDto = CompanyRegistrationRequestDto.builder()
                .companyName(googleRequestDto.getCompanyName())
                .country(googleRequestDto.getCountry())
                .phoneNumber(Optional.ofNullable(googleRequestDto.getPhoneNumber()).orElse(""))
                .city(Optional.ofNullable(googleRequestDto.getCity()).orElse(""))
                .address(Optional.ofNullable(googleRequestDto.getAddress()).orElse(""))
                .build();

        CreateProfileResponseRecord response = externalCompanyAuthRequestInterface.sendCreateProfileRequest(savedAuth.getCompanyId(), requestDto);

        if (response.getCompanyId() == null) {
            log.warn("Failed create profile for ID: {}", savedAuth.getCompanyId());
            return CompanyRegistrationResponseDto.builder()
                    .success(false)
                    .email("Failed to create profile for ID: " + savedAuth.getCompanyId())
                    .build();
        }

        log.info("Successfully create profile for ID: {}", response.getCompanyId());

        // Generate tokens for immediate authentication (no OTP required for SSO)
        TokenPairDto tokenPair = jweTokenService.generateTokenPairDto(
                savedAuth.getCompanyId(),
                savedAuth.getEmail(),
                Role.COMPANY,
                true
        );

        log.info("Company registered via Google SSO and auto-activated: {}", savedAuth.getEmail());

        return CompanyRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message("Company registered successfully via Google SSO.")
                .tokenPair(tokenPair)
                .build();
    }

    @Override
    @Transactional
    public LoginServiceDto authenticateWithEmailAndPassword(CompanyLoginRequestDto loginDto) {
        // Find company by email
        CompanyAuthEntity companyAuth = companyAuthRepository.findByEmail(loginDto.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        // Verify password
        if (!passwordEncoder.matches(loginDto.getPassword(), companyAuth.getHashedPassword())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        // Generate token pair for valid credential
        TokenPairDto tokenPair = jweTokenService.generateTokenPairDto(
                companyAuth.getCompanyId(),
                companyAuth.getEmail(),
                Role.COMPANY,
                companyAuth.isActivated());

        log.info("Company logged in successfully: {}", companyAuth.getEmail());

        return LoginServiceDto.builder()
                .success(true)
                .isActivated(companyAuth.isActivated())
                .message("Login successful. " + (companyAuth.isActivated() ? "Account activated!"
                        : "This account is inactivated. Please activate"))
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken())
                .companyId(companyAuth.getCompanyId().toString())
                .build();
    }

    @Override
    @Transactional
    public void verifyOtpAndActivateAccount(UUID companyId, String otp) {
        // Verify OTP
        if (!otpService.verifyOtp(companyId, otp)) {
            throw new InvalidTokenException("Invalid or expired OTP");
        }

        // Find the company by ID
        CompanyAuthEntity companyAuth = companyAuthRepository.findById(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("companyId", "", "Company not found"));

        // Activate the company account
        companyAuth.setActivated(true);
        companyAuthRepository.save(companyAuth);

        log.info("Company account activated successfully for company ID: {}", companyId);
    }

    @Override
    @Transactional
    public void verifyActivationTokenAndActivateAccount(String activationToken) {
        // Validate and decrypt the token to get companyId
        TokenClaimsDto claims = jweTokenService.getTokenClaimsDtoDecryptedFromTokenString(activationToken);
        UUID companyId = claims.getSub();

        // Verify that this token matches the one stored in Redis for this user
        if (!otpService.verifyActivationToken(companyId, activationToken)) {
            throw new InvalidTokenException("Invalid, expired, or used activation link");
        }

        // Find the company by ID
        CompanyAuthEntity companyAuth = companyAuthRepository.findById(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("companyId", "", "Company not found"));

        if (companyAuth.isActivated()) {
            // Idempotency: if already activated, just return (or could throw exception)
            log.info("Company account already activated: {}", companyId);
            return;
        }

        // Activate the company account
        companyAuth.setActivated(true);
        companyAuthRepository.save(companyAuth);

        log.info("Company account activated via link successfully for company ID: {}", companyId);
    }

    @Override
    @Transactional
    public void resendOtp(UUID companyId) {
        // Find the company by ID
        CompanyAuthEntity companyAuth = companyAuthRepository.findById(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("companyId", "", "Company not found"));

        if (companyAuth.isActivated()) {
            throw new IllegalStateException("Account is already activated");
        }

        String activationToken = jweTokenService.generateActivationToken(
                companyAuth.getCompanyId(),
                companyAuth.getEmail(),
                Role.COMPANY
        );

        ActivationPairDto activationPairDto = otpService.invalidateExistingAndGenerateNewOtp(companyAuth.getCompanyId(), activationToken);

        // TODO: get company name Kafka
        emailService.sendOtpEmail(companyAuth.getEmail(), companyAuth.getEmail(), activationPairDto.getOtp(), activationPairDto.getActivationToken());

        log.info("OTP resent to company: {}", companyAuth.getEmail());
    }

    @Override
    public UUID validateAccessTokenAndGetCompanyId(String accessToken) {
        TokenClaimsDto claims = jweTokenService.validateAccessToken(accessToken);
        return claims.getSub();
    }

    @Override
    public LoginServiceDto refreshTokenPair(String refreshToken) {
        // Get claims from the refresh token to extract companyId
        TokenClaimsDto claims = jweTokenService.getTokenClaimsDtoDecryptedFromTokenString(refreshToken);

        TokenPairDto tokenPair = jweTokenService.refreshAccessToken(refreshToken);

        return LoginServiceDto.builder()
                .success(true)
                .isActivated(true)
                .message("Token refreshed successfully.")
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken())
                .companyId(claims.getSub().toString())
                .build();
    }

    @Override
    public void logout(String accessToken, String refreshToken) {
        jweTokenService.revokeTokens(accessToken, refreshToken);
        log.info("User logged out successfully");
    }

    @Override
    public void setAuthAndRefreshCookieToBrowser(
            HttpServletResponse response,
            String accessToken,
            String refreshToken,
            int accessMaxAge,
            int refreshMaxAge) {
        setCookieToBrowser(response, CookieType.ACCESS_TOKEN, accessToken, accessMaxAge);
        setCookieToBrowser(response, CookieType.REFRESH_TOKEN, refreshToken, refreshMaxAge);
    }

    @Override
    public void setCookieToBrowser(
            HttpServletResponse response,
            String cookieType,
            String token,
            int maxAge) {
        if (token != null) {
            // Use Set-Cookie header directly to support SameSite=None for cross-origin
            // requests
            String cookieValue = String.format(
                    "%s=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=None",
                    cookieType, token, maxAge);
            response.addHeader("Set-Cookie", cookieValue);
        }
    }

    @Override
    public void clearBrowserCookie(
            HttpServletResponse response,
            String cookieType) {
        // Use Set-Cookie header directly to support SameSite=None for cross-origin
        // requests
        String cookieValue = String.format(
                "%s=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None",
                cookieType);
        response.addHeader("Set-Cookie", cookieValue);
    }

    @Override
    @Transactional
    public void setInitialPassword(String companyId, String password) {
        CompanyAuthEntity currentUser = companyAuthRepository.findById(UUID.fromString(companyId))
                .orElseThrow(() -> new ResourceNotFoundException("Company", "ID", companyId));

        if (currentUser.getSsoToken() == null) {
            throw new IllegalStateException("This endpoint is only for SSO accounts");
        }

        if (currentUser.getHashedPassword() != null) {
            throw new IllegalStateException("Password already set. Use change password endpoint instead.");
        }

        currentUser.setHashedPassword(passwordEncoder.encode(password));
        companyAuthRepository.save(currentUser);

        log.info("Initial password set successfully for SSO account: {}", companyId);
    }

    @Override
    @Transactional
    public void changePassword(String companyId, String currentPassword, String newPassword) {
        CompanyAuthEntity currentUser = companyAuthRepository.findById(UUID.fromString(companyId))
                .orElseThrow(() -> new ResourceNotFoundException("Company", "ID", companyId));

        if (currentUser.getHashedPassword() == null) {
            throw new IllegalArgumentException("No password set. Use set password endpoint first.");
        }

        if (!passwordEncoder.matches(currentPassword, currentUser.getHashedPassword())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        currentUser.setHashedPassword(passwordEncoder.encode(newPassword));
        companyAuthRepository.save(currentUser);

        log.info("Password changed successfully for company: {}", companyId);
    }
}
