package rmit.saintgiong.authservice.domain.user.services.service;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rmit.saintgiong.authservice.domain.user.entity.Auth;

import java.util.UUID;

@Repository
interface CompanyAuthRepository extends JpaRepository<Auth, UUID> {
}
