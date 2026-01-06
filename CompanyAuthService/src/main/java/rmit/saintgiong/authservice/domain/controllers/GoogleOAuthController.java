package rmit.saintgiong.authservice.domain.controllers;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationResponseDto;
import rmit.saintgiong.shared.response.GenericResponseDto;
import rmit.saintgiong.shared.token.TokenPairDto;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleOAuthResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleLoginResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleRegistrationPrefillDto;
import rmit.saintgiong.authapi.internal.service.InternalCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGoogleOAuthInterface;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.shared.type.CookieType;

import java.util.concurrent.Callable;

@RestController
@AllArgsConstructor
@Tag(name = "Google OAuth Authentication", description = "APIs for Google Registration, Login and Verify OAuth code")
public class GoogleOAuthController {

    private final InternalCompanyAuthInterface internalCompanyAuthInterface;
    private final InternalGoogleOAuthInterface internalGoogleOAuthInterface;

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
                internalCompanyAuthInterface.setCookieToBrowser(
                        response,
                        CookieType.ACCESS_TOKEN,
                        tokenPairDto.getAccessToken(),
                        (int) tokenPairDto.getAccessTokenExpiresIn()
                );

                if (tokenPairDto.getRefreshToken() != null && !tokenPairDto.getRefreshToken().isEmpty()) {
                    internalCompanyAuthInterface.setCookieToBrowser(
                            response,
                            CookieType.REFRESH_TOKEN,
                            tokenPairDto.getRefreshToken(),
                            (int) tokenPairDto.getRefreshTokenExpiresIn()
                    );
                }

                // Return companyId and email for existing user login
                GoogleLoginResponseDto loginResponse = GoogleLoginResponseDto.builder()
                        .companyId(oauthResponseDto.getCompanyId())
                        .email(oauthResponseDto.getEmail())
                        .build();

                return ResponseEntity
                        .status(HttpStatus.OK)
                        .body(new GenericResponseDto<>(true, "", loginResponse));
            }

            if (oauthResponseDto.getTempToken() != null) {
                internalCompanyAuthInterface.setCookieToBrowser(
                        response,
                        CookieType.TEMP_TOKEN,
                        oauthResponseDto.getTempToken(),
                        (int) oauthResponseDto.getTempTokenExpiresIn()
                );
                GoogleRegistrationPrefillDto prefilledDto = GoogleRegistrationPrefillDto.builder()
                        .email(oauthResponseDto.getEmail())
                        .name(oauthResponseDto.getName())
                        .build();

                return ResponseEntity
                        .status(HttpStatus.OK)
                        .body(new GenericResponseDto<>(true, "", prefilledDto));
            }

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(new GenericResponseDto<>(false, "Unable to process Google Authentication", null));
        };
    }

    @PostMapping("/google/register")
    public Callable<ResponseEntity<GenericResponseDto<?>>> registerCompanyWithGoogleAuthentication(
            @Valid @RequestBody CompanyRegistrationGoogleRequestDto requestDto,
            @CookieValue(name = CookieType.TEMP_TOKEN) String tempToken,
            HttpServletResponse response
    ) {
        return () -> {
            CompanyRegistrationResponseDto registerResponseDto = internalCompanyAuthInterface.registerCompanyWithGoogleId(requestDto, tempToken);
            internalCompanyAuthInterface.clearBrowserCookie(response, CookieType.TEMP_TOKEN);

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Register company via Google successfully!", registerResponseDto));
        };
    }
}
