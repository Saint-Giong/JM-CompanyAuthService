package rmit.saintgiong.authservice.domain.company.services.service;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuth;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CompanyAuthRepository extends JpaRepository<CompanyAuth, UUID> {
    Optional<CompanyAuth> findByEmail(String email);
}
