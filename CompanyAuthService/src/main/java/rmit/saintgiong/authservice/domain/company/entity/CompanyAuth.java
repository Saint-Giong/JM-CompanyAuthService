package rmit.saintgiong.authservice.domain.company.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;


@EntityListeners(AuditingEntityListener.class)
@Entity(name = "company_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Setter @Getter @ToString
@Builder
public class CompanyAuth {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID companyId;

    @Column(nullable = false, unique = true)
    @Email
    private String email;

    @Column(name = "hashed_password")
    private String hashedPassword;

    @Column(name = "sso_provider")
    private String ssoProvider;

    @Column(name = "is_activated")
    private boolean isActivated;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
