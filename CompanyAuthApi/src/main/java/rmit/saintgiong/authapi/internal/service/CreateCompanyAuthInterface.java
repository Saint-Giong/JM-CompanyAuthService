package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.CompanyAuthRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;

public interface CreateCompanyAuthInterface {
    public CompanyAuthRegistrationResponseDto registerCompany(CompanyRegistrationDto registrationDto);
}
