package rmit.saintgiong.authservice.common.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
@Slf4j
@RequiredArgsConstructor
public class DataSeedingConfig implements CommandLineRunner {

    private final CompanyAuthRepository companyAuthRepository;
    private final PasswordEncoder encoder;

    @Override
    public void run (String @NonNull ... args) {
        if (companyAuthRepository.count() != 0) {
            return;
        }

        List<CompanyAuthEntity> seeds = new ArrayList<>();
        String uuidBased = "00000000-0000-0000-0000-00000000000";

        for (int i = 0; i < 5; i++) {
            seeds.add(
                    CompanyAuthEntity.builder()
                            .companyId(UUID.fromString(uuidBased + i))
                            .email("nguyensontungtdn1901@gmail.com")
                            .hashedPassword(encoder.encode("123"))
                            .ssoToken(null)
                            .isActivated(true)
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build()
            );
        }

        companyAuthRepository.saveAll(seeds);
    }
}