package rmit.saintgiong.authservice.domain.company.services.service;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rmit.saintgiong.authservice.domain.company.entity.CompanyAuth;

import java.util.UUID;

@Repository
interface CompanyAuthRepository extends JpaRepository<CompanyAuth, UUID> {
}
