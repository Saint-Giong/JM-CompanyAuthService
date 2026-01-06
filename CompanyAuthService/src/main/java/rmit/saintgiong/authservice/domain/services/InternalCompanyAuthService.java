package rmit.saintgiong.authservice.domain.services;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
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
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.LoginServiceDto;
import rmit.saintgiong.authapi.internal.common.dto.avro.ProfileRegistrationResponseRecord;
import rmit.saintgiong.authapi.internal.common.dto.avro.ProfileRegistrationSentRecord;
import rmit.saintgiong.shared.type.CookieType;
import rmit.saintgiong.shared.token.TokenPairDto;
import rmit.saintgiong.shared.token.TokenClaimsDto;
import rmit.saintgiong.authapi.internal.service.InternalCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.common.type.KafkaTopic;
import rmit.saintgiong.shared.type.Role;
import rmit.saintgiong.authservice.common.exception.resources.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.exception.token.InvalidCredentialsException;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.authservice.common.exception.resources.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.utils.EmailService;
import rmit.saintgiong.authservice.common.utils.JweTokenService;
import rmit.saintgiong.authservice.common.utils.OtpService;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.model.CompanyAuth;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;

@Service
@AllArgsConstructor
@Slf4j
public class InternalCompanyAuthService implements InternalCompanyAuthInterface {

    private final CompanyAuthMapper companyAuthMapper;
    private final CompanyAuthRepository companyAuthRepository;

    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final OtpService otpService;
    private final JweTokenService jweTokenService;

    private ReplyingKafkaTemplate<String, Object, Object> replyingKafkaTemplate;

    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto requestDto) {
        // Check if email already exists
        Optional<CompanyAuthEntity> existingAuth = companyAuthRepository.findByEmail(requestDto.getEmail());
        if (existingAuth.isPresent()) {
            throw new CompanyAccountAlreadyExisted("Email already registered");
        }

        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationDto(requestDto);
        companyAuth.setHashedPassword(passwordEncoder.encode(requestDto.getPassword()));

        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));
        ProfileRegistrationSentRecord profileSentRecord = ProfileRegistrationSentRecord.newBuilder()
                .setCompanyId(savedAuth.getCompanyId())
                .setCompanyName(requestDto.getCompanyName())
                .setCountry(requestDto.getCountry())
                .setPhoneNumber(Optional.ofNullable(requestDto.getPhoneNumber()).orElse(""))
                .setCity(Optional.ofNullable(requestDto.getCity()).orElse(""))
                .setAddress(Optional.ofNullable(requestDto.getAddress()).orElse(""))
                .build();

        ProducerRecord<String, Object> request = new ProducerRecord<>(
                KafkaTopic.COMPANY_REGISTRATION_REQUEST_TOPIC,
                profileSentRecord
        );
        request.headers().add(
                KafkaHeaders.REPLY_TOPIC,
                KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC.getBytes()
        );

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

    @Override
    @Transactional
    public CompanyRegistrationResponseDto registerCompanyWithGoogleId(
            CompanyRegistrationGoogleRequestDto googleRequestDto,
            String tempToken
    ) {
        CompanyAuth companyAuth = companyAuthMapper.fromCompanyRegistrationGoogleDto(googleRequestDto);

        String googleId = jweTokenService.getGoogleIdFromJweToken(tempToken);
        String emailFromToken = jweTokenService.getEmailFromJweString(tempToken);
        if (googleId == null || emailFromToken == null) {
            throw new InvalidTokenException("Missing either googleId or email in TEMP_COOKIE.");
        }

        if (!emailFromToken.equals(googleRequestDto.getEmail())) {
            throw new InvalidTokenException("Email in TEMP_COOKIE does not match the registration email.");
        }

        companyAuth.setSsoToken(googleId);

        CompanyAuthEntity savedAuth = companyAuthRepository.save(companyAuthMapper.toEntity(companyAuth));
        ProfileRegistrationSentRecord profileSentRecord = ProfileRegistrationSentRecord.newBuilder()
                .setCompanyId(savedAuth.getCompanyId())
                .setCompanyName(googleRequestDto.getCompanyName())
                .setCountry(googleRequestDto.getCountry())
                .setPhoneNumber(Optional.ofNullable(googleRequestDto.getPhoneNumber()).orElse(""))
                .setCity(Optional.ofNullable(googleRequestDto.getCity()).orElse(""))
                .setAddress(Optional.ofNullable(googleRequestDto.getAddress()).orElse(""))
                .build();

        ProducerRecord<String, Object> request = new ProducerRecord<>(
                KafkaTopic.COMPANY_REGISTRATION_REQUEST_TOPIC,
                profileSentRecord
        );
        request.headers().add(
                KafkaHeaders.REPLY_TOPIC,
                KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC.getBytes()
        );

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
        emailService.sendOtpEmail(googleRequestDto.getEmail(), googleRequestDto.getCompanyName(), otp);

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
            int refreshMaxAge
    ) {
        setCookieToBrowser(response, CookieType.ACCESS_TOKEN, accessToken, accessMaxAge);
        setCookieToBrowser(response, CookieType.REFRESH_TOKEN, refreshToken, refreshMaxAge);
    }

    @Override
    public void setCookieToBrowser(
            HttpServletResponse response,
            String cookieType,
            String token,
            int maxAge
    ) {
        if (token != null) {
            Cookie cookie = new Cookie(cookieType, token);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(maxAge);
            response.addCookie(cookie);
        }
    }

    @Override
    public void clearBrowserCookie(
            HttpServletResponse response,
            String cookieType
    ) {
        Cookie cookie = new Cookie(cookieType, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
