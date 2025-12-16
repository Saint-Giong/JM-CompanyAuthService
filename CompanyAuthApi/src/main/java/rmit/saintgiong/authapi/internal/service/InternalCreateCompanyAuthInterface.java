package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;

public interface InternalCreateCompanyAuthInterface {
    CompanyRegistrationResponseDto registerCompany(CompanyRegistrationRequestDto requestDto);
    CompanyRegistrationResponseDto registerCompanyWithGoogleId(CompanyRegistrationGoogleRequestDto requestDto, String tempToken);
}
