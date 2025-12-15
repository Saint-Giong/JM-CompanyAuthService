package rmit.saintgiong.authservice.domain.company.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuthEntity;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CompanyAuthRepository extends JpaRepository<CompanyAuthEntity, UUID> {
    Optional<CompanyAuthEntity> findByEmail(String email);
    Optional<CompanyAuthEntity> findByCompanyId(String id);
}
