package rmit.saintgiong.authservice.domain.user.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Entity(name = "auth")
public class Auth {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID companyId;

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
    @Column(name = "updated_at", insertable = false)
    private LocalDateTime updatedAt;
}
