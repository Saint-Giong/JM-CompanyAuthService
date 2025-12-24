package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;

public interface InternalGetCompanyAuthInterface {
    LoginServiceDto authenticateWithEmailAndPassword(CompanyLoginRequestDto loginDto);
}
