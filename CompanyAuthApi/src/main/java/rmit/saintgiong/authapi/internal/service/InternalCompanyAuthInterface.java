package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.*;

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
}
