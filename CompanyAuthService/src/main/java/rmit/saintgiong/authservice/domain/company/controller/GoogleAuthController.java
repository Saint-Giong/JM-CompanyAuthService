package rmit.saintgiong.authservice.domain.company.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.common.GenericResponseDto;
import rmit.saintgiong.authapi.internal.dto.common.TokenPairDto;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleOAuthResponseDto;
import rmit.saintgiong.authapi.internal.dto.oauth.GoogleRegistrationPrefillDto;
import rmit.saintgiong.authapi.internal.service.InternalCreateCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.google_oauth.InternalGoogleOAuthInterface;
import rmit.saintgiong.authservice.common.exception.InvalidTokenException;

import java.util.concurrent.Callable;

@RestController
@AllArgsConstructor
@Tag(name = "Google OAuth Authentication", description = "APIs for Google Registration, Login and Verify OAuth code")
public class GoogleAuthController {

    private final InternalCreateCompanyAuthInterface internalCreateCompanyAuthInterface;
    private final InternalGoogleOAuthInterface internalGoogleOAuthInterface;

    private static final String TEMP_COOKIE_NAME = "temp_token";
    private static final String AUTH_COOKIE_NAME = "auth_token";
    private static final String REFRESH_COOKIE_NAME = "refresh_token";

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
                authCookie.setSecure(true);
                authCookie.setPath("/");
                authCookie.setMaxAge((int) tokenPairDto.getAccessTokenExpiresIn());
                response.addCookie(authCookie);

                // set a refresh token in HttpOnly cookie
                if (tokenPairDto.getRefreshToken() != null && !tokenPairDto.getRefreshToken().isEmpty()) {
                    Cookie refreshCookie = new Cookie(REFRESH_COOKIE_NAME, tokenPairDto.getRefreshToken());
                    refreshCookie.setHttpOnly(true);
                    refreshCookie.setSecure(true);
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
                temp.setSecure(true);
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
            tempTokenCookie.setSecure(true);
            tempTokenCookie.setMaxAge(0);
            response.addCookie(tempTokenCookie);

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Register company successfully!", registerResponseDto));
        };
    }
}
