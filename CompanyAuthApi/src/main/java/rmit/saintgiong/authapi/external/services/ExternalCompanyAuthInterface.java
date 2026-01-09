package rmit.saintgiong.authapi.external.services;

import rmit.saintgiong.authapi.external.common.dto.avro.ProfileRegistrationResponseRecord;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;

import java.util.UUID;

public interface ExternalCompanyAuthInterface {

    ProfileRegistrationResponseRecord sendRegisterRequestForCompanyProfile (UUID companyId, CompanyRegistrationRequestDto requestDto);
}
