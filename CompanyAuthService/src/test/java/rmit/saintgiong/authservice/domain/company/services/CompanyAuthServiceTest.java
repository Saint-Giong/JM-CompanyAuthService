package rmit.saintgiong.authservice.domain.company.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.util.EmailService;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.common.util.OtpService;
import rmit.saintgiong.authservice.common.util.TokenStorageService;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;
import rmit.saintgiong.authservice.domain.company.model.CompanyAuth;
import rmit.saintgiong.authservice.domain.company.repository.CompanyAuthRepository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CompanyAuthServiceInternal Unit Tests")
class CompanyAuthServiceTest {

    @Mock
    private CompanyAuthMapper companyAuthMapper;

    @Mock
    private CompanyAuthRepository companyAuthRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @Mock
    private TokenStorageService tokenStorageService;

    @Mock
    private OtpService otpService;

    @Mock
    private JweTokenService jweTokenService;

    @InjectMocks
    private CompanyAuthService companyAuthService;

    // Test data
    private CompanyRegistrationRequestDto validRegistrationDto;
    private CompanyAuth companyAuth;
    private CompanyAuthEntity companyAuthEntity;
    private CompanyAuthEntity savedCompanyAuthEntity;
    private UUID testCompanyId;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "SecurePass123!";
    private static final String ENCODED_PASSWORD = "$2a$10$encodedPasswordHash";

    @BeforeEach
    void setUp() {
        testCompanyId = UUID.randomUUID();

        validRegistrationDto = new CompanyRegistrationRequestDto(
                "Test Company",
                TEST_EMAIL,
                TEST_PASSWORD,
                "Vietnam",
                "+84912345678",
                "Ho Chi Minh",
                "123 Main Street"
        );

        companyAuth = CompanyAuth.builder()
                .email(TEST_EMAIL)
                .isActivated(false)
                .build();

        companyAuthEntity = CompanyAuthEntity.builder()
                .email(TEST_EMAIL)
                .hashedPassword(ENCODED_PASSWORD)
                .isActivated(false)
                .build();

        savedCompanyAuthEntity = CompanyAuthEntity.builder()
                .companyId(testCompanyId)
                .email(TEST_EMAIL)
                .hashedPassword(ENCODED_PASSWORD)
                .isActivated(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    //   SUCCESSFUL REGISTRATION TESTS  

    @Nested
    @DisplayName("Successful Registration Tests")
    class SuccessfulRegistrationTests {

        @Test
        @DisplayName("Should register company successfully and response with valid data")
        void registerCompany_ValidData_ReturnsSuccessResponse() {
            // Arrange
            when(companyAuthRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
            when(companyAuthMapper.fromCompanyRegistrationDto(validRegistrationDto)).thenReturn(companyAuth);
            when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(companyAuthMapper.toEntity(any(CompanyAuth.class))).thenReturn(companyAuthEntity);
            when(companyAuthRepository.save(any(CompanyAuthEntity.class))).thenReturn(savedCompanyAuthEntity);
            when(otpService.generateOtp(testCompanyId)).thenReturn("123456");
            doNothing().when(emailService).sendOtpEmail(anyString(), anyString(), anyString());

            // Act
            CompanyRegistrationResponseDto response = companyAuthService.registerCompany(validRegistrationDto);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getCompanyId()).isEqualTo(testCompanyId);
            assertThat(response.getEmail()).isEqualTo(TEST_EMAIL);
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).isEqualTo( "Company registered successfully. Please check your email for the OTP to activate your account.");
            
            // Verify OTP generation and email sending
            verify(otpService, times(1)).generateOtp(testCompanyId);
            verify(emailService, times(1)).sendOtpEmail(eq(TEST_EMAIL), eq("Test Company"), eq("123456"));
        }
    }


    //   PASSWORD ENCODING TESTS  

    @Nested
    @DisplayName("Password Encoding Tests")
    class PasswordEncodingTests {

        @Test
        @DisplayName("Should encode password before saving")
        void registerCompany_ValidData_EncodesPassword() {
            // Arrange
            when(companyAuthRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());
            when(companyAuthMapper.fromCompanyRegistrationDto(validRegistrationDto)).thenReturn(companyAuth);
            when(passwordEncoder.encode(TEST_PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(companyAuthMapper.toEntity(any(CompanyAuth.class))).thenReturn(companyAuthEntity);
            when(companyAuthRepository.save(any(CompanyAuthEntity.class))).thenReturn(savedCompanyAuthEntity);
            when(otpService.generateOtp(testCompanyId)).thenReturn("123456");
            doNothing().when(emailService).sendOtpEmail(anyString(), anyString(), anyString());

            // Act
            companyAuthService.registerCompany(validRegistrationDto);

            // Assert
            verify(passwordEncoder, times(1)).encode(TEST_PASSWORD);
        }

    }

    //   DUPLICATE EMAIL TESTS  

    @Nested
    @DisplayName("Duplicate Email Tests")
    class DuplicateEmailTests {

        @Test
        @DisplayName("Should throw CompanyAccountAlreadyExisted when email exists")
        void registerCompany_DuplicateEmail_ThrowsCompanyAccountAlreadyExisted() {
            // Arrange
            CompanyAuthEntity existingEntity = CompanyAuthEntity.builder()
                    .companyId(UUID.randomUUID())
                    .email(TEST_EMAIL)
                    .build();
            when(companyAuthRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(existingEntity));

            // Act & Assert
            assertThatThrownBy(() -> companyAuthService.registerCompany(validRegistrationDto))
                    .isInstanceOf(CompanyAccountAlreadyExisted.class)
                    .hasMessage("Email already registered");
        }
    }


}
