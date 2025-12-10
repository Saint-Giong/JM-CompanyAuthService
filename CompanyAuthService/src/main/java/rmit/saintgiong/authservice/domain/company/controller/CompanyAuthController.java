package rmit.saintgiong.authservice.domain.company.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.dto.*;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGetCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalUpdateCompanyAuthInterface;
import rmit.saintgiong.authservice.common.dto.ErrorResponseDto;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;
import rmit.saintgiong.authservice.common.dto.TokenClaimsDto;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;

import java.util.UUID;
import java.util.concurrent.Callable;

@RestController
@RequestMapping("/api/v1/sgjm/auth") //TODO: keep for testing purpose, will be removed when deployed with API Gateway
@AllArgsConstructor
@Tag(name = "Company Authentication", description = "APIs for company registration, authentication, and account management")
public class CompanyAuthController {

    private final InternalGetCompanyAuthInterface internalGetCompanyAuthInterface;
    private final InternalUpdateCompanyAuthInterface internalUpdateCompanyAuthInterface;
    private final InternalCreateCompanyAuthInterface internalCreateCompanyAuthInterface;
    private final JweTokenService jweTokenService;

    private static final String AUTH_COOKIE_NAME = "auth_token";
    private final CompanyAuthMapper companyAuthMapper;

    /**
     * Registers a new company account.
     *
     * @param registrationDto the company registration details containing email, password,
     *                        and other required information
     * @return a {@link Callable} that returns a {@link ResponseEntity} containing
     *         the registration response with company ID, email, and success status
     */
    @Operation(
            summary = "Register a new company",
            description = "Creates a new company account and sends an activation email. " +
                    "The company must verify their email before they can log in."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Company registered successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = CompanyRegistrationResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid registration data",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Email already registered",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/register")
    public Callable<ResponseEntity<CompanyRegistrationResponseDto>> registerCompany(
            @Valid @RequestBody CompanyRegistrationRequestDto registrationDto) {
        return () -> {
            CompanyRegistrationResponseDto response = internalCreateCompanyAuthInterface.registerCompany(registrationDto);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        };
    }

    /**
     * Authenticates a company and returns tokens if activated.
     * If account is not activated, sends OTP and sets a temporary cookie.
     */
    @Operation(
            summary = "Company login",
            description = "Authenticates a company with email and password. " +
                    "If the account is not activated, a new OTP is sent and a temporary token is set in a cookie."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Login successful or OTP sent for activation",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = CompanyLoginResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/login")
    public Callable<ResponseEntity<CompanyLoginResponseDto>> login(
            @Valid @RequestBody CompanyLoginRequestDto loginDto,
            HttpServletResponse response) {
        return () -> {
            LoginServiceDto loginResponse = internalGetCompanyAuthInterface.login(loginDto);

            // For activated accounts, set access token in HttpOnly cookie
            Cookie authCookie = new Cookie(AUTH_COOKIE_NAME, loginResponse.getAccessToken());
            authCookie.setHttpOnly(true);
            authCookie.setSecure(true);
            authCookie.setPath("/");
            authCookie.setMaxAge(900);
            response.addCookie(authCookie);

            CompanyLoginResponseDto companyLoginResponseDto = companyAuthMapper.fromLoginServiceDto(loginResponse);

            return ResponseEntity.status(HttpStatus.OK).body(companyLoginResponseDto);
        };
    }

    /**
     * Verifies OTP and activates the company account.
     * The company ID is extracted from the JWE token in the cookie.
     */
    @Operation(
            summary = "Verify OTP and activate account",
            description = "Verifies the OTP sent to the user's email and activates the account. " +
                    "Requires a valid auth token in cookie (set during login for inactive accounts)."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Account activated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = OtpVerificationResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired OTP",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/verify-account")
    public Callable<ResponseEntity<OtpVerificationResponseDto>> verifyAccount(
            @Valid @RequestBody OtpVerificationRequestDto otpDto,
            @CookieValue(name = AUTH_COOKIE_NAME, required = false) String authToken,
            HttpServletResponse response) {
        return () -> {
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token
            TokenClaimsDto claims = jweTokenService.validateAccessToken(authToken);
            UUID companyId = claims.getSub();

            // Verify OTP and activate account
            internalUpdateCompanyAuthInterface.verifyOtpAndActivateAccount(companyId, otpDto.getOtp());

            return ResponseEntity.ok(OtpVerificationResponseDto.builder()
                    .success(true)
                    .message("Account activated successfully. Please login to continue.")
                    .build());
        };
    }

    /**
     * Resends OTP to the user's email.
     * The company ID is extracted from the JWE token in the cookie.
     */
    @Operation(
            summary = "Resend OTP",
            description = "Resends a new OTP to the user's email. " +
                    "Requires a valid auth token in cookie (set during login for inactive accounts)."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "OTP resent successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = OtpVerificationResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid authentication token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/resend-otp")
    public Callable<ResponseEntity<OtpVerificationResponseDto>> resendOtp(
            @CookieValue(name = AUTH_COOKIE_NAME, required = false) String authToken) {
        return () -> {
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token
            TokenClaimsDto claims = jweTokenService.validateAccessToken(authToken);
            UUID companyId = claims.getSub();

            // Resend OTP
            internalUpdateCompanyAuthInterface.resendOtp(companyId);

            return ResponseEntity.ok(OtpVerificationResponseDto.builder()
                    .success(true)
                    .message("A new OTP has been sent to your email.")
                    .build());
        };
    }
}
