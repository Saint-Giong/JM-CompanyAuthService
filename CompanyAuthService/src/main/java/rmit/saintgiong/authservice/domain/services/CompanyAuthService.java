package rmit.saintgiong.authservice.domain.services;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.kafka.requestreply.ReplyingKafkaTemplate;
import org.springframework.kafka.requestreply.RequestReplyFuture;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import rmit.saintgiong.authapi.internal.dto.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;
import rmit.saintgiong.authapi.internal.dto.avro.ProfileRegistrationResponseRecord;
import rmit.saintgiong.authapi.internal.dto.avro.ProfileRegistrationSentRecord;
import rmit.saintgiong.authapi.internal.dto.common.TokenPairDto;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.internal.dto.*;
import rmit.saintgiong.authapi.internal.dto.common.TokenClaimsDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGetCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalUpdateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.type.KafkaTopic;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;
import rmit.saintgiong.authapi.internal.type.Role;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;
import rmit.saintgiong.authservice.common.exception.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.util.EmailService;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.common.util.OtpService;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.model.CompanyAuth;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;

@Service
@AllArgsConstructor
@Slf4j
public class CompanyAuthService implements InternalCreateCompanyAuthInterface, InternalGetCompanyAuthInterface, InternalUpdateCompanyAuthInterface {

    private final CompanyAuthMapper companyAuthMapper;
    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final OtpService otpService;
    private final JweTokenService jweTokenService;

    private ReplyingKafkaTemplate<String, Object, Object> replyingKafkaTemplate;

    /**
     * Registers a new company with the authentication system.
     *
     * @param requestDto the company registration data transfer object containing
     *                   the email, password, and other registration details
     * @return a {@link CompanyRegistrationResponseDto} containing the registered
     *         company's ID, email, success status, and a confirmation message
     */
    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto requestDto) {
        // Check if email already exists
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(requestDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        // Convert DTO to model
        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationDto(requestDto);

        // Encode password in the model
        companyAuth.setHashedPassword(passwordEncoder.encode(requestDto.getPassword()));

        // Convert model to entity and save (isActivated remains false)
        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));

        // TODO: Add kafka publisher to create profile

        ProfileRegistrationSentRecord profileSentRecord = ProfileRegistrationSentRecord.newBuilder()
                .setCompanyId(savedAuth.getCompanyId())
                .setCompanyName(requestDto.getCompanyName())
                .setCountry(requestDto.getCountry())
                .setPhoneNumber(Optional.ofNullable(requestDto.getPhoneNumber()).orElse(""))
                .setCity(Optional.ofNullable(requestDto.getCity()).orElse(""))
                .setAddress(Optional.ofNullable(requestDto.getAddress()).orElse(""))
                .build();

        ProducerRecord<String, Object> request = new ProducerRecord<>(KafkaTopic.COMPANY_REGISTRATION_REQUEST_TOPIC,
                profileSentRecord);
        request.headers().add(
                KafkaHeaders.REPLY_TOPIC,
                KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC.getBytes());

        try {
            RequestReplyFuture<String, Object, Object> responseRecord = replyingKafkaTemplate.sendAndReceive(request);

            ConsumerRecord<String, Object> response = responseRecord.get(10, TimeUnit.SECONDS);

            Object responseValue = response.value();
            if (responseValue instanceof ProfileRegistrationResponseRecord profileResponse) {
                log.info(
                        "Received profile registration response for companyId={}: {}",
                        savedAuth.getCompanyId(),
                        profileResponse);
            } else {
                log.warn(
                        "Received unexpected or null profile registration response for companyId={} : {}",
                        savedAuth.getCompanyId(),
                        responseValue);
            }
        } catch (Exception e) {
            log.error("Error while sending profile registration message for companyId={}", savedAuth.getCompanyId(), e);
        }

        // Generate OTP and store in Redis with 2-minute TTL
        String otp = otpService.generateOtp(savedAuth.getCompanyId());
        // Send OTP email
        emailService.sendOtpEmail(requestDto.getEmail(), requestDto.getCompanyName(), otp);



        return CompanyRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message(
                        "Company registered successfully. Please check your email for the OTP to activate your account.")
                .build();
    }

    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompanyWithGoogleId(CompanyRegistrationGoogleRequestDto requestDto,
            String tempToken) {
        // Convert DTO to model
        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationGoogleDto(requestDto);

        String googleId = jweTokenService.getGoogleIdFromJweToken(tempToken);
        String emailFromToken = jweTokenService.getEmailFromJweString(tempToken);
        if (googleId == null || emailFromToken == null) {
            throw new InvalidTokenException("Missing either googleId or email in TEMP_COOKIE.");
        }

        if (!emailFromToken.equals(requestDto.getEmail())) {
            throw new InvalidTokenException("Email in TEMP_COOKIE does not match the registration email.");
        }

        companyAuth.setSsoToken(googleId);

        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));

        // Send Kafka message to create profile in Profile Service
        ProfileRegistrationSentRecord profileSentRecord = ProfileRegistrationSentRecord.newBuilder()
                .setCompanyId(savedAuth.getCompanyId())
                .setCompanyName(requestDto.getCompanyName())
                .setCountry(requestDto.getCountry())
                .setPhoneNumber(Optional.ofNullable(requestDto.getPhoneNumber()).orElse(""))
                .setCity(Optional.ofNullable(requestDto.getCity()).orElse(""))
                .setAddress(Optional.ofNullable(requestDto.getAddress()).orElse(""))
                .build();

        ProducerRecord<String, Object> request = new ProducerRecord<>(KafkaTopic.COMPANY_REGISTRATION_REQUEST_TOPIC,
                profileSentRecord);
        request.headers().add(
                KafkaHeaders.REPLY_TOPIC,
                KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC.getBytes());

        try {
            RequestReplyFuture<String, Object, Object> responseRecord = replyingKafkaTemplate.sendAndReceive(request);

            ConsumerRecord<String, Object> response = responseRecord.get(10, TimeUnit.SECONDS);

            Object responseValue = response.value();
            if (responseValue instanceof ProfileRegistrationResponseRecord profileResponse) {
                log.info(
                        "Received profile registration response for Google OAuth companyId={}: {}",
                        savedAuth.getCompanyId(),
                        profileResponse);
            } else {
                log.warn(
                        "Received unexpected or null profile registration response for Google OAuth companyId={} : {}",
                        savedAuth.getCompanyId(),
                        responseValue);
            }
        } catch (Exception e) {
            log.error("Error while sending profile registration message for Google OAuth companyId={}",
                    savedAuth.getCompanyId(), e);
        }

        String otp = otpService.generateOtp(savedAuth.getCompanyId());
        emailService.sendOtpEmail(requestDto.getEmail(), requestDto.getCompanyName(), otp);

        return CompanyRegistrationResponseDto.builder()
                .companyId(savedAuth.getCompanyId())
                .email(savedAuth.getEmail())
                .success(true)
                .message(
                        "Company registered successfully. Please check your email for the OTP to activate your account.")
                .build();
    }

    /**
     * Authenticates a company with email and password.
     * If an account is not activated, it generates and sends a new OTP.
     *
     * @param loginDto The login credentials
     * @return CompanyLoginResponseDto with an authentication result and tokens if
     *         activated
     */
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
        TokenPairDto tokenPair = jweTokenService.generateTokenPair(
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
                .orElseThrow(() -> new ResourceNotFoundException("companyId", "", "Company not found"));

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
                .orElseThrow(() -> new ResourceNotFoundException("companyId", "", "Company not found"));

        if (companyAuth.isActivated()) {
            throw new IllegalStateException("Account is already activated");
        }

        // Invalidate and Generate new OTP
        String otp = otpService.invalidateExistingAndGenerateNewOtp(companyId);

        // Send OTP email
        // TODO: replace company email with company name
        emailService.sendOtpEmail(companyAuth.getEmail(), companyAuth.getEmail(), otp);

        log.info("OTP resent to company: {}", companyAuth.getEmail());
    }



    /**
     * Validates access token and returns the company ID.
     *
     * @param accessToken the access token to validate
     * @return the company ID extracted from the token
     */
    @Override
    public UUID validateAccessTokenAndGetCompanyId(String accessToken) {
        TokenClaimsDto claims = jweTokenService.validateAccessToken(accessToken);
        return claims.getSub();
    }

    /**
     * Refreshes the token pair using a valid refresh token.
     *
     * @param refreshToken the refresh token
     * @return LoginServiceDto containing new access and refresh tokens
     */
    @Override
    public LoginServiceDto refreshTokenPair(String refreshToken) {
        TokenPairDto tokenPair = jweTokenService.refreshAccessToken(refreshToken);

        return LoginServiceDto.builder()
                .success(true)
                .isActivated(true)
                .message("Token refreshed successfully.")
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken())
                .build();
    }

    /**
     * Logs out the user by revoking their authentication tokens.
     * Access token is added to blocklist, refresh token is removed from whitelist.
     *
     * @param accessToken  The access token to revoke
     * @param refreshToken The refresh token to revoke
     */
    @Override
    public void logout(String accessToken, String refreshToken) {
        jweTokenService.revokeTokens(accessToken, refreshToken);
        log.info("User logged out successfully");
    }

}
