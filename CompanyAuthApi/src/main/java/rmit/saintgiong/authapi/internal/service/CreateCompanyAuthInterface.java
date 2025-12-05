package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.CompanyAuthResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;

public interface CreateCompanyAuthInterface {
    public CompanyAuthResponseDto registerCompany(CompanyRegistrationDto registrationDto);
}
