package rmit.saintgiong.authservice.domain.company.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.google_oauth.InternalGoogleOAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGetCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalUpdateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.exception.CompanyAccountAlreadyExisted;
import rmit.saintgiong.authservice.common.util.EmailService;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.common.util.OtpService;
import rmit.saintgiong.authservice.common.util.TokenStorageService;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Company Auth Registration Tests")
class CompanyAuthRegistrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private InternalCreateCompanyAuthInterface companyAuthService;

    @MockitoBean
    private InternalGetCompanyAuthInterface internalGetCompanyAuthInterface;

    @MockitoBean
    private InternalUpdateCompanyAuthInterface internalUpdateCompanyAuthInterface;

    @MockitoBean
    private JweTokenService jweTokenService;

    @MockitoBean
    private InternalGoogleOAuthInterface googleOAuthInterface;

    @MockitoBean
    private CompanyAuthMapper companyAuthMapper;

    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private OtpService otpService;

    @MockitoBean
    private TokenStorageService tokenStorageService;

    private CompanyRegistrationRequestDto validRegistrationDto;
    private UUID testCompanyId;

    @BeforeEach
    void setUp() {
        testCompanyId = UUID.randomUUID();
        validRegistrationDto = new CompanyRegistrationRequestDto(
                "Test Company",
                "test@example.com",
                "SecurePass123!",
                "Vietnam",
                "+84912345678",
                "Ho Chi Minh",
                "123 Main Street"
        );
    }

    //VALID CASE TESTS

    @Nested
    @DisplayName("Valid Registration Tests")
    class ValidRegistrationTests {

        @Test
        @DisplayName("Should register company successfully with valid data")
        void testRegisterCompany_ValidData_Success() throws Exception {
            // Arrange
            CompanyRegistrationResponseDto mockResponse = CompanyRegistrationResponseDto.builder()
                    .companyId(testCompanyId)
                    .email("test@example.com")
                    .success(true)
                    .message("Company registered successfully. Please check your email for activation link.")
                    .build();

            when(companyAuthService.registerCompany(any(CompanyRegistrationRequestDto.class)))
                    .thenReturn(mockResponse);

            // Act & Assert
            MvcResult result = mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(result))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.companyId").value(testCompanyId.toString()))
                    .andExpect(jsonPath("$.email").value("test@example.com"))
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("Company registered successfully. Please check your email for activation link."));

            verify(companyAuthService, times(1)).registerCompany(any(CompanyRegistrationRequestDto.class));
        }

    }

    //COMPANY NAME VALIDATION TESTS

    @Nested
    @DisplayName("Company Name Validation Tests")
    class CompanyNameValidationTests {

        @Test
        @DisplayName("Should fail when company name is empty")
        void testRegisterCompany_EmptyCompanyName_Fail() throws Exception {
            validRegistrationDto.setCompanyName("");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.companyName").value("Company name is required"));

            verify(companyAuthService, never()).registerCompany(any());
        }

    }

    //EMAIL VALIDATION TESTS

    @Nested
    @DisplayName("Email Validation Tests")
    class EmailValidationTests {


        @Test
        @DisplayName("Should fail when email is empty")
        void testRegisterCompany_EmptyEmail_Fail() throws Exception {
            validRegistrationDto.setEmail("");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.email").exists());

            verify(companyAuthService, never()).registerCompany(any());
        }

        @ParameterizedTest
        @DisplayName("Should fail when email format is invalid")
        @ValueSource(strings = {
                "invalid-email",
                "test@",
                "@example.com",
                "test@@example.com",
                "test@example",
                "test.example.com",
                "test @example.com",
                "test@ example.com"
        })
        void testRegisterCompany_InvalidEmailFormat_Fail(String invalidEmail) throws Exception {
            validRegistrationDto.setEmail(invalidEmail);

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.email").exists());

            verify(companyAuthService, never()).registerCompany(any());
        }

    }

    //PASSWORD VALIDATION TESTS

    @Nested
    @DisplayName("Password Validation Tests")
    class PasswordValidationTests {

        @Test
        @DisplayName("Should fail when password is empty")
        void testRegisterCompany_EmptyPassword_Fail() throws Exception {
            validRegistrationDto.setPassword("");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.password").exists());

            verify(companyAuthService, never()).registerCompany(any());
        }

        @Test
        @DisplayName("Should fail when password is too short (less than 8 characters)")
        void testRegisterCompany_ShortPassword_Fail() throws Exception {
            validRegistrationDto.setPassword("Pass1!");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.password").exists());

            verify(companyAuthService, never()).registerCompany(any());
        }

        @Test
        @DisplayName("Should fail when password has no uppercase letter")
        void testRegisterCompany_NoUppercasePassword_Fail() throws Exception {
            validRegistrationDto.setPassword("password123!");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.password").value("Password must contain at least 1 number, 1 special character, and 1 uppercase letter"));

            verify(companyAuthService, never()).registerCompany(any());
        }

        @Test
        @DisplayName("Should fail when password has no number")
        void testRegisterCompany_NoNumberPassword_Fail() throws Exception {
            validRegistrationDto.setPassword("Password!");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.password").value("Password must contain at least 1 number, 1 special character, and 1 uppercase letter"));

            verify(companyAuthService, never()).registerCompany(any());
        }

        @Test
        @DisplayName("Should fail when password has no special character")
        void testRegisterCompany_NoSpecialCharPassword_Fail() throws Exception {
            validRegistrationDto.setPassword("Password123");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.password").value("Password must contain at least 1 number, 1 special character, and 1 uppercase letter"));

            verify(companyAuthService, never()).registerCompany(any());
        }


    }

    //COUNTRY VALIDATION TESTS

    @Nested
    @DisplayName("Country Validation Tests")
    class CountryValidationTests {

        @Test
        @DisplayName("Should fail when country is blank")
        void testRegisterCompany_EmptyCountry_Fail() throws Exception {
            validRegistrationDto.setCountry("");

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.country").value("Country is required"));

            verify(companyAuthService, never()).registerCompany(any());
        }

    }

    //PHONE NUMBER VALIDATION TESTS

    @Nested
    @DisplayName("Phone Number Validation Tests")
    class PhoneNumberValidationTests {

        @ParameterizedTest
        @DisplayName("Should fail when phone number format is invalid")
        @ValueSource(strings = {
                "09123456",      // Missing +
                "84912345678",     // Missing +
                "+",               // Only +
                "+abc12345678",    // Contains letters
                "++84912345678",   // Double +
                "+84 912345678"    // Contains space
        })
        void testRegisterCompany_InvalidPhoneFormat_Fail(String invalidPhone) throws Exception {
            validRegistrationDto.setPhoneNumber(invalidPhone);

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields.phoneNumber").value("Phone number must start with '+' followed by 1-3 digit country code and 1-12 digits"));

            verify(companyAuthService, never()).registerCompany(any());
        }

    }

    //DUPLICATE EMAIL TESTS

    @Nested
    @DisplayName("Duplicate Email Tests")
    class DuplicateEmailTests {

        @Test
        @DisplayName("Should fail when email already exists")
        void testRegisterCompany_DuplicateEmail_Fail() throws Exception {
            when(companyAuthService.registerCompany(any(CompanyRegistrationRequestDto.class)))
                    .thenThrow(new CompanyAccountAlreadyExisted("Email already registered"));

            MvcResult result = mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRegistrationDto)))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(result))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("Email already registered"));

            verify(companyAuthService, times(1)).registerCompany(any(CompanyRegistrationRequestDto.class));
        }
    }

    //MULTIPLE VALIDATION ERRORS TESTS

    @Nested
    @DisplayName("Multiple Validation Errors Tests")
    class MultipleValidationErrorsTests {

        @Test
        @DisplayName("Should return multiple validation errors when multiple fields are invalid")
        void testRegisterCompany_MultipleInvalidFields_Fail() throws Exception {
            CompanyRegistrationRequestDto invalidDto = new CompanyRegistrationRequestDto(
                    "",          // invalid - blank
                    "invalid",   // invalid - not email format
                    "weak",      // invalid - too short and missing requirements
                    "",          // invalid - blank
                    "invalid",   // invalid - wrong format
                    "",
                    ""
            );

            mockMvc.perform(post("/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidDto)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errorFields").isMap())
                    .andExpect(jsonPath("$.errorFields.companyName").exists())
                    .andExpect(jsonPath("$.errorFields.email").exists())
                    .andExpect(jsonPath("$.errorFields.password").exists())
                    .andExpect(jsonPath("$.errorFields.country").exists())
                    .andExpect(jsonPath("$.errorFields.phoneNumber").exists());

            verify(companyAuthService, never()).registerCompany(any());
        }
    }

}