package rmit.saintgiong.authapi.internal.service;

import rmit.saintgiong.authapi.internal.dto.CompanyLoginRequestDto;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;

import java.util.UUID;

public interface InternalGetCompanyAuthInterface {
    LoginServiceDto authenticateWithEmailAndPassword(CompanyLoginRequestDto loginDto);

    /**
     * Validates access token and returns the company ID.
     *
     * @param accessToken the access token to validate
     * @return the company ID extracted from the token
     */
    UUID validateAccessTokenAndGetCompanyId(String accessToken);

    /**
     * Refreshes the token pair using a valid refresh token.
     *
     * @param refreshToken the refresh token
     * @return LoginServiceDto containing new access and refresh tokens
     */
    LoginServiceDto refreshTokenPair(String refreshToken);
}
