package rmit.saintgiong.authservice.domain.company.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import rmit.saintgiong.authapi.internal.dto.CompanyLoginResponseDto;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.dto.LoginServiceDto;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.model.CompanyAuth;
@Mapper(componentModel = "spring")
public interface CompanyAuthMapper {


    @Mapping(target = "companyId", ignore = true)
    CompanyAuth fromCompanyRegistrationDto(CompanyRegistrationRequestDto dto);


    CompanyAuthEntity toEntity(CompanyAuth model);

    CompanyAuth fromEntity(CompanyAuthEntity entity);

    @Mapping(target = "isActivated", source = "activated")
    CompanyLoginResponseDto fromLoginServiceDto(LoginServiceDto dto);
}