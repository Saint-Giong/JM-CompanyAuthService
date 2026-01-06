package rmit.saintgiong.authapi.internal.service;

import jakarta.servlet.http.HttpServletResponse;
import rmit.saintgiong.authapi.internal.common.dto.auth.*;

import java.util.UUID;

public interface InternalCompanyAuthInterface {
    CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto requestDto);

    CompanyRegistrationResponseDto registerCompanyWithGoogleId(CompanyRegistrationGoogleRequestDto requestDto, String tempToken);

    LoginServiceDto authenticateWithEmailAndPassword(CompanyLoginRequestDto loginDto);

    UUID validateAccessTokenAndGetCompanyId(String accessToken);

    LoginServiceDto refreshTokenPair(String refreshToken);

    void verifyOtpAndActivateAccount(UUID companyId, String otp);

    void resendOtp(UUID companyId);

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
