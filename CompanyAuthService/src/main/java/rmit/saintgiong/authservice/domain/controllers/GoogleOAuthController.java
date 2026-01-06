package rmit.saintgiong.authservice.domain.controllers;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import java.util.UUID;
import java.util.concurrent.Callable;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyLinkGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleAuthResponseDto;
import rmit.saintgiong.authapi.internal.service.InternalCompanyAuthInterface;
import rmit.saintgiong.authapi.internal.service.InternalGoogleOAuthInterface;
import rmit.saintgiong.authservice.common.exception.token.InvalidTokenException;
import rmit.saintgiong.shared.response.GenericResponseDto;
import rmit.saintgiong.shared.type.CookieType;


@RestController
@AllArgsConstructor
@Tag(name = "Google OAuth Authentication", description = "APIs for Google Registration, Login and Verify OAuth code")
public class GoogleOAuthController {

    private final InternalCompanyAuthInterface internalCompanyAuthInterface;
    private final InternalGoogleOAuthInterface internalGoogleOAuthInterface;

    @GetMapping("/google/redirect-url")
    public ResponseEntity<GenericResponseDto<?>> getGoogleRedirectUrl(
            boolean isLinking
    ) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new GenericResponseDto<>(true, "", internalGoogleOAuthInterface.buildGoogleAuthUrl(isLinking)));
    }

    @GetMapping("/google/auth")
    public Callable<ResponseEntity<GenericResponseDto<GoogleAuthResponseDto>>> handleGoogleAuthentication(
            HttpServletResponse response,
            @RequestParam("code") String code
    ) {
        return () -> {
            GoogleAuthResponseDto responseDto = internalGoogleOAuthInterface.handleGoogleAuthentication(response, code);

            if (responseDto == null) {
                return ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .body(new GenericResponseDto<>(false, "Unable to process Google Authentication", null));
            }

            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "", responseDto));
        };
    }

    @PostMapping("/google/link-google")
    public Callable<ResponseEntity<GenericResponseDto<?>>> linkGoogleToAccount(
            @RequestParam("code") String code,
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String authToken

    ) {
        return () -> {
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token via the service layer
            UUID companyId = internalCompanyAuthInterface.validateAccessTokenAndGetCompanyId(authToken);

            internalGoogleOAuthInterface.handleLinkGoogleToAccount(companyId.toString(), code, true, false);
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Google account linked successfully", null));
        };
    }

    @PostMapping("/google/relink-google")
    public Callable<ResponseEntity<GenericResponseDto<?>>> relinkNewGoogleToAccount(
            @RequestParam("code") String code,
            @CookieValue(name = CookieType.ACCESS_TOKEN, required = false) String authToken
    ) {
        return () -> {
            if (authToken == null || authToken.isEmpty()) {
                throw new InvalidTokenException("Authentication token not found. Please login first.");
            }

            // Validate and extract company ID from the token via the service layer
            UUID companyId = internalCompanyAuthInterface.validateAccessTokenAndGetCompanyId(authToken);

            internalGoogleOAuthInterface.handleLinkGoogleToAccount(companyId.toString(),  code, false, true);
            return ResponseEntity
                    .status(HttpStatus.OK)
                    .body(new GenericResponseDto<>(true, "Google account re-linked successfully", null));
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
