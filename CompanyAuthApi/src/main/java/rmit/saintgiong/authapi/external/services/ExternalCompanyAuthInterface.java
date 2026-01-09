package rmit.saintgiong.authapi.external.services;

import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileResponseRecord;

import java.util.UUID;

public interface ExternalCompanyAuthInterface {

    CreateProfileResponseRecord sendRegisterRequestForCompanyProfile (UUID companyId, CompanyRegistrationRequestDto requestDto);
}
