package rmit.saintgiong.authapi.internal.services;

import java.util.UUID;

import jakarta.servlet.http.HttpServletResponse;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.LoginServiceDto;

public interface InternalCompanyAuthInterface {

    CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto requestDto);

    CompanyRegistrationResponseDto registerCompanyWithGoogleId(CompanyRegistrationGoogleRequestDto requestDto, String tempToken);

    LoginServiceDto authenticateWithEmailAndPassword(CompanyLoginRequestDto loginDto);

    UUID validateAccessTokenAndGetCompanyId(String accessToken);

    LoginServiceDto refreshTokenPair(String refreshToken);

    void verifyOtpAndActivateAccount(UUID companyId, String otp);

    void verifyActivationTokenAndActivateAccount(String activationToken);

    void resendOtp(UUID companyId);

    void setInitialPassword(String companyId, String password);

    void changePassword(String companyId, String currentPassword, String newPassword);

    void logout(String accessToken, String refreshToken);

    void setAuthAndRefreshCookieToBrowser(
            HttpServletResponse response,
            String accessToken,
            String refreshToken,
            int accessMaxAge,
            int refreshMaxAge
    );

    void setCookieToBrowser(
            HttpServletResponse response,
            String cookieType,
            String token,
            int maxAge
    );

     void clearBrowserCookie(HttpServletResponse response, String cookieType);
}
