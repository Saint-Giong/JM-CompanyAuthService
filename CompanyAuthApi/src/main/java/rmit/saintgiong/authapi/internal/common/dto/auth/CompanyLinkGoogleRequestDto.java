package rmit.saintgiong.authapi.internal.common.dto.auth;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CompanyLinkGoogleRequestDto {

    @NotNull(message = "Company ID cannot be NULL")
    private String companyId;
}
