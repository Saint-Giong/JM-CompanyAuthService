package rmit.saintgiong.authservice.domain.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.util.UUID;
import java.util.concurrent.Callable;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.external.services.ExternalCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.common.dto.auth.*;
import rmit.saintgiong.authapi.internal.common.dto.otp.OtpVerificationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.otp.OtpVerificationResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.refresh.RefreshTokenResponseDto;
import rmit.saintgiong.authapi.internal.services.InternalCompanyAuthInterface;
import rmit.saintgiong.authservice.common.config.JweConfig;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.authservice.domain.mapper.CompanyAuthMapper;
import rmit.saintgiong.shared.response.ErrorResponseDto;
import rmit.saintgiong.shared.response.GenericResponseDto;
import rmit.saintgiong.shared.type.CookieType;


@Slf4j
@RestController
@AllArgsConstructor
@Tag(name = "Company Authentication", description = "APIs for company registration, authentication, and account management")
public class CompanyAuthController {
    private final JweConfig jweConfig;
    private final InternalCompanyAuthInterface internalCompanyAuthInterface;
    private final ExternalCompanyAuthInterface externalCompanyAuthInterface;
    private final CompanyAuthMapper companyAuthMapper;

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
    public Callable<ResponseEntity<CompanyRegistrationResponseDto>> registerCompanyWithEmailAndPassword(
            @Valid @RequestBody CompanyRegistrationRequestDto registrationDto
    ) {
        return () -> {
            CompanyRegistrationResponseDto response = internalCompanyAuthInterface.registerCompany(registrationDto);
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(response);
        };
    }

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
    public Callable<ResponseEntity<CompanyLoginResponseDto>> loginWithEmailAndPassword(
            @Valid @RequestBody CompanyLoginRequestDto loginDto,
            HttpServletResponse response) {
        return () -> {
            LoginServiceDto loginResponse = internalCompanyAuthInterface.authenticateWithEmailAndPassword(loginDto);
            internalCompanyAuthInterface.setAuthAndRefreshCookieToBrowser(
                    response,
                    loginResponse.getAccessToken(),
                    loginResponse.getRefreshToken(),
                    jweConfig.getAccessTokenTtlSeconds(),
                    jweConfig.getRefreshTokenTtlSeconds()
            );
            CompanyLoginResponseDto companyLoginResponseDto = companyAuthMapper.fromLoginServiceDto(loginResponse);

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(companyLoginResponseDto);
        };
    }


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
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String authToken
    ) {
        return () -> {

            //TODO: use filter and security to check for cookie and get id from authenticated session instead
            //TODO: manually checking in controller method
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token via the service layer
            UUID companyId = internalCompanyAuthInterface.validateAccessTokenAndGetCompanyId(authToken);

            // Verify OTP and activate an account
            internalCompanyAuthInterface.verifyOtpAndActivateAccount(companyId, otpDto.getOtp());

            return ResponseEntity.ok(
                    OtpVerificationResponseDto.builder()
                            .success(true)
                            .message("Account activated successfully. Please login to continue.")
                            .build()
            );
        };
    }


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
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String authToken
    ) {
        return () -> {

            //TODO: use filter and security to check for cookie and get id from authenticated session instead
            //TODO: manually checking in controller method
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }
            log.info("Resending OTP for company with token.");
            // Validate and extract company ID from the token via the service layer
            UUID companyId = internalCompanyAuthInterface.validateAccessTokenAndGetCompanyId(authToken);

            // Resend OTP
            internalCompanyAuthInterface.resendOtp(companyId);

            return ResponseEntity.ok(
                    OtpVerificationResponseDto.builder()
                            .success(true)
                            .message("A new OTP has been sent to your email.")
                            .build()
            );
        };
    }

    @Operation(
            summary = "Refresh access token",
            description = "Refreshes the access token using a valid refresh token from the cookie. " +
                    "The old refresh token is invalidated and a new token pair is issued (token rotation). " +
                    "If token reuse is detected, all user sessions are invalidated for security."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token refreshed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = RefreshTokenResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid, expired, or reused refresh token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/refresh-token")
    public Callable<ResponseEntity<RefreshTokenResponseDto>> refreshToken(
            @CookieValue(name = CookieType.REFRESH_TOKEN, required = false) String refreshToken,
            HttpServletResponse response
    ) {
        return () -> {
            if (refreshToken == null || refreshToken.isEmpty()) {
                throw new InvalidTokenException("Refresh token not found. Please login first.");
            }

            // Refresh the token pair (includes reuse detection)
            LoginServiceDto tokenResponse = internalCompanyAuthInterface.refreshTokenPair(refreshToken);
            internalCompanyAuthInterface.setAuthAndRefreshCookieToBrowser(
                    response,
                    tokenResponse.getAccessToken(),
                    tokenResponse.getRefreshToken(),
                    jweConfig.getAccessTokenTtlSeconds(),
                    jweConfig.getRefreshTokenTtlSeconds()
            );

            return ResponseEntity.ok(
                    RefreshTokenResponseDto.builder()
                            .success(true)
                            .message("Token refreshed successfully.")
                            .companyId(tokenResponse.getCompanyId())
                            .build()
            );
        };
    }

    @Operation(
            summary = "Logout",
            description = "Logs out the user by revoking their authentication tokens and clearing cookies. " +
                    "The access token is added to a blocklist and the refresh token is removed from the whitelist."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Logout successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LogoutResponseDto.class)
                    )
            )
    })
    @PostMapping("/logout")
    public Callable<ResponseEntity<LogoutResponseDto>> logout(
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String accessToken,
            @CookieValue(name = CookieType.REFRESH_TOKEN, required = false) String refreshToken,
            HttpServletResponse response) {
        return () -> {
            // Revoke tokens via service layer (blocklist access token, remove refresh token)
            internalCompanyAuthInterface.logout(accessToken, refreshToken);
            internalCompanyAuthInterface.setAuthAndRefreshCookieToBrowser(response, accessToken, refreshToken, 0, 0);

            return ResponseEntity.ok(
                    LogoutResponseDto.builder()
                            .success(true)
                            .message("Logged out successfully.")
                            .build()
            );
        };
    }

    @Operation(
            summary = "Set initial password for SSO account",
            description = "Sets the initial password for an SSO account. " +
                    "This endpoint is only for accounts that logged in via Google OAuth and don't have a password yet."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Password set successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PasswordOperationResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request or password already set",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Company not found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/set-password")
    public Callable<ResponseEntity<GenericResponseDto<?>>> setInitialPassword(
            @Valid @RequestBody CompanySetPasswordRequestDto requestDto,
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String authToken
    ) {
        return () -> {
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token via the service layer
            UUID companyId = internalCompanyAuthInterface.validateAccessTokenAndGetCompanyId(authToken);

            internalCompanyAuthInterface.setInitialPassword(companyId.toString(), requestDto.getPassword());

            PasswordOperationResponseDto response = PasswordOperationResponseDto.builder()
                    .success(true)
                    .message("Password set successfully. You can now login with email and password.")
                    .build();

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Password set successfully", response));
        };
    }

    @Operation(
            summary = "Change password",
            description = "Changes the password for an account. " +
                    "Requires the current password for verification. Works for both SSO and non-SSO accounts."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Password changed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PasswordOperationResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request or no password set",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Current password is incorrect",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Company not found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponseDto.class)
                    )
            )
    })
    @PostMapping("/change-password")
    public Callable<ResponseEntity<GenericResponseDto<?>>> changePassword(
            @Valid @RequestBody CompanyUpdatePasswordRequestDto requestDto,
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String authToken
    ) {
        return () -> {
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token via the service layer
            UUID companyId = internalCompanyAuthInterface.validateAccessTokenAndGetCompanyId(authToken);

            internalCompanyAuthInterface.changePassword(
                    companyId.toString(),
                    requestDto.getCurrentPassword(),
                    requestDto.getNewPassword()
            );

            PasswordOperationResponseDto response = PasswordOperationResponseDto.builder()
                    .success(true)
                    .message("Password changed successfully.")
                    .build();

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Password changed successfully", response));
        };
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "this is a dashboard";
    }
}
