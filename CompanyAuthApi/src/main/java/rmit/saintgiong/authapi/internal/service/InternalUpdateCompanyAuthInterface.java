package rmit.saintgiong.authapi.internal.service;

import java.util.UUID;

public interface InternalUpdateCompanyAuthInterface {
     void verifyOtpAndActivateAccount(UUID companyId, String otp);
     void resendOtp(UUID companyId);
}
