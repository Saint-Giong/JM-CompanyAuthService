package rmit.saintgiong.authservice.domain.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyLoginResponseDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationGoogleRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.auth.LoginServiceDto;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.model.CompanyAuth;

@Mapper(componentModel = "spring")
public interface CompanyAuthMapper {


    @Mapping(target = "companyId", ignore = true)
    CompanyAuth fromCompanyRegistrationDto(CompanyRegistrationRequestDto dto);

    @Mapping(target = "hashedPassword", ignore = true)
    CompanyAuth fromCompanyRegistrationGoogleDto(CompanyRegistrationGoogleRequestDto dto);

    CompanyAuthEntity toEntity(CompanyAuth model);

    CompanyAuth fromEntity(CompanyAuthEntity entity);

    @Mapping(target = "isActivated", source = "activated")
    CompanyLoginResponseDto fromLoginServiceDto(LoginServiceDto dto);
}