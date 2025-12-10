package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;

public interface InternalCreateCompanyAuthInterface {
    public CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto registrationDto);
}
