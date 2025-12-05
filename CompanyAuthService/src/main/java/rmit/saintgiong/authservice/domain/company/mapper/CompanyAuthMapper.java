package rmit.saintgiong.authservice.domain.company.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import rmit.saintgiong.authapi.internal.dto.CompanyRegistrationDto;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.company.model.CompanyAuth;
@Mapper(componentModel = "spring")
public interface CompanyAuthMapper {


    @Mapping(target = "companyId", ignore = true)
    CompanyAuth fromCompanyRegistrationDto(CompanyRegistrationDto dto);


    CompanyAuthEntity toEntity(CompanyAuth model);

    CompanyAuth fromEntity(CompanyAuthEntity entity);
}