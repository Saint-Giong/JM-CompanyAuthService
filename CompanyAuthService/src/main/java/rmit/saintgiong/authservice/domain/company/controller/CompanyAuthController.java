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
import rmit.saintgiong.authapi.internal.dto.common.GenericResponseDto;
import rmit.saintgiong.authapi.internal.dto.common.TokenPairDto;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleOAuthResponseDto;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleRegistrationPrefillDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGetCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalUpdateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.google_oauth.InternalGoogleOAuthInterface;
import rmit.saintgiong.authapi.internal.dto.common.ErrorResponseDto;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;
import rmit.saintgiong.authapi.internal.dto.common.TokenClaimsDto;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;
import rmit.saintgiong.authservice.common.util.JweTokenService;
import rmit.saintgiong.authservice.domain.company.mapper.CompanyAuthMapper;

import java.util.UUID;
import java.util.concurrent.Callable;

@RestController
@AllArgsConstructor
@Tag(name = "Company Authentication", description = "APIs for company registration, authentication, and account management")
public class CompanyAuthController {

    private final InternalGetCompanyAuthInterface internalGetCompanyAuthInterface;
    private final InternalUpdateCompanyAuthInterface internalUpdateCompanyAuthInterface;
    private final InternalCreateCompanyAuthInterface internalCreateCompanyAuthInterface;
    private final InternalGoogleOAuthInterface internalGoogleOAuthInterface;

    private final JweTokenService jweTokenService;

    private static final String TEMP_COOKIE_NAME = "temp_token";
    private static final String AUTH_COOKIE_NAME = "auth_token";
    private static final String REFRESH_COOKIE_NAME = "refresh_token";

    private final CompanyAuthMapper companyAuthMapper;

    /**
     * Registers a new company account
     *
     * @param registrationDto the company registration details containing email, password,
     *                        and other required information
     * @return a {@link Callable} that returns a {@link ResponseEntity} containing
     * the registration response with company ID, email, and success status
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
    public Callable<ResponseEntity<CompanyRegistrationResponseDto>> registerCompanyWithEmailAndPassword(
            @Valid @RequestBody CompanyRegistrationRequestDto registrationDto
    ) {
        return () -> {
            CompanyRegistrationResponseDto response = internalCreateCompanyAuthInterface.registerCompany(registrationDto);
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(response);
        };
    }

    /**
     * Authenticates a company and returns tokens if activated.
     * If an account is not activated, sends OTP and sets a temporary cookie.
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
    public Callable<ResponseEntity<CompanyLoginResponseDto>> loginWithEmailAndPassword(
            @Valid @RequestBody CompanyLoginRequestDto loginDto,
            HttpServletResponse response) {
        return () -> {
            LoginServiceDto loginResponse = internalGetCompanyAuthInterface.authenticateWithEmailAndPassword(loginDto);

            // set a short-lived access token in HttpOnly cookie
            Cookie authCookie = new Cookie(AUTH_COOKIE_NAME, loginResponse.getAccessToken());
            authCookie.setHttpOnly(true);
            authCookie.setSecure(true); //TODO: change to true when deployed with HTTPS
            authCookie.setPath("/");
            authCookie.setMaxAge(900);
            response.addCookie(authCookie);

            // set a refresh token in HttpOnly cookie
            Cookie refreshCookie = new Cookie(REFRESH_COOKIE_NAME, loginResponse.getRefreshToken());
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true); //TODO: change to true when deployed with HTTPS
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(604800);
            response.addCookie(refreshCookie);

            CompanyLoginResponseDto companyLoginResponseDto = companyAuthMapper.fromLoginServiceDto(loginResponse);

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(companyLoginResponseDto);
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
            HttpServletResponse response
    ) {
        return () -> {

            //TODO: use filter and security to check for cookie and get id from authenticated session instead
            //TODO: manually checking in controller method
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token
            TokenClaimsDto claims = jweTokenService.validateAccessToken(authToken);
            UUID companyId = claims.getSub();

            // Verify OTP and activate an account
            internalUpdateCompanyAuthInterface.verifyOtpAndActivateAccount(companyId, otpDto.getOtp());

            return ResponseEntity.ok(
                    OtpVerificationResponseDto.builder()
                            .success(true)
                            .message("Account activated successfully. Please login to continue.")
                            .build()
            );
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
    public Callable<ResponseEntity<OtpVerificationResponseDto>> resendOtp(@CookieValue(name = AUTH_COOKIE_NAME, required = false) String authToken) {
        return () -> {

            //TODO: use filter and security to check for cookie and get id from authenticated session instead
            //TODO: manually checking in controller method
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token
            TokenClaimsDto claims = jweTokenService.validateAccessToken(authToken);
            UUID companyId = claims.getSub();

            // Resend OTP
            internalUpdateCompanyAuthInterface.resendOtp(companyId);

            return ResponseEntity.ok(
                    OtpVerificationResponseDto.builder()
                            .success(true)
                            .message("A new OTP has been sent to your email.")
                            .build()
            );
        };
    }

    @GetMapping("/google/redirect-url")
    public ResponseEntity<GenericResponseDto<?>> getGoogleRedirectUrl() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new GenericResponseDto<>(true, "", internalGoogleOAuthInterface.buildGoogleAuthUrl()));
    }

    @GetMapping("/google/auth")
    public Callable<ResponseEntity<GenericResponseDto<?>>> handleGoogleCallback(
            HttpServletResponse response,
            @RequestParam("code") String code
    ) {
        return () -> {
            if (code == null || code.trim().isEmpty()) {
                throw new InvalidTokenException("Authorization code is missing");
            }

            GoogleOAuthResponseDto oauthResponseDto = internalGoogleOAuthInterface.authenticateGoogleUser(code);

            TokenPairDto tokenPairDto = oauthResponseDto.getTokenPairDto();
            // login is ok
            if (tokenPairDto != null) {
                Cookie authCookie = new Cookie(AUTH_COOKIE_NAME, tokenPairDto.getAccessToken());
                authCookie.setHttpOnly(true);
                authCookie.setSecure(true); //TODO: change to true when deployed with HTTPS
                authCookie.setPath("/");
                authCookie.setMaxAge((int) tokenPairDto.getAccessTokenExpiresIn());
                response.addCookie(authCookie);

                // set a refresh token in HttpOnly cookie
                if (tokenPairDto.getRefreshToken() != null && !tokenPairDto.getRefreshToken().isEmpty()) {
                    Cookie refreshCookie = new Cookie(REFRESH_COOKIE_NAME, tokenPairDto.getRefreshToken());
                    refreshCookie.setHttpOnly(true);
                    refreshCookie.setSecure(true); //TODO: change to true when deployed with HTTPS
                    refreshCookie.setPath("/");
                    refreshCookie.setMaxAge((int) tokenPairDto.getRefreshTokenExpiresIn());
                    response.addCookie(refreshCookie);
                }

                return ResponseEntity
                        .status(HttpStatus.OK)
                        .body(new GenericResponseDto<>(true, "", null));
            }

            if (oauthResponseDto.getRegisterToken() != null) {
                Cookie temp = new Cookie(TEMP_COOKIE_NAME, oauthResponseDto.getRegisterToken());
                temp.setHttpOnly(true);
                temp.setSecure(true);  //TODO: change to true when deployed with HTTPS
                temp.setPath("/");
                temp.setMaxAge((int) oauthResponseDto.getRegisterTokenExpiresIn());
                response.addCookie(temp);

                GoogleRegistrationPrefillDto prefillDto = new GoogleRegistrationPrefillDto(oauthResponseDto.getEmail(), oauthResponseDto.getName());

                return ResponseEntity
                        .status(HttpStatus.OK)
                        .body(new GenericResponseDto<>(true, "", prefillDto));
            }

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new GenericResponseDto<>(false, "Unable to process Google Authentication", null));
        };
    }

    @PostMapping("/google/register")
    public Callable<ResponseEntity<GenericResponseDto<?>>> registerCompanyWithGoogleAuthentication(
            @Valid @RequestBody CompanyRegistrationGoogleRequestDto requestDto,
            @CookieValue(name = TEMP_COOKIE_NAME) String tempToken,
            HttpServletResponse response
    ) {
        return () -> {
            CompanyRegistrationResponseDto registerResponseDto = internalCreateCompanyAuthInterface.registerCompanyWithGoogleId(requestDto, tempToken);

            Cookie tempTokenCookie = new Cookie(TEMP_COOKIE_NAME, "");
            tempTokenCookie.setPath("/");
            tempTokenCookie.setHttpOnly(true);
            tempTokenCookie.setSecure(true); // TODO: change to true when deployed with HTTPS
            tempTokenCookie.setMaxAge(0);
            response.addCookie(tempTokenCookie);

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Register company successfully!", registerResponseDto));
        };
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello world";
    }

    @GetMapping("/error")
    public String error() {
        return "error";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "this is a dashboard";
    }
}
