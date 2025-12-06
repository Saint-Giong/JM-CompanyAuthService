package rmit.saintgiong.authservice.domain.company.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CompanyAuth {

    private UUID companyId;

    private String email;

    private String hashedPassword;

    private String ssoProvider;

    private boolean isActivated;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}



