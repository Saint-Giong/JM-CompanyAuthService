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
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run (String @NonNull ... args) {
        if (companyAuthRepository.count() != 0) {
            return;
        }

        List<CompanyAuthEntity> seeds = List.of(
                CompanyAuthEntity.builder()
                        .companyId(UUID.fromString("22222222-2222-2222-2222-222222222222"))
                        .email("google@gmail.com") // Company admin email
                        .hashedPassword(passwordEncoder.encode("Google123!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build(),

                CompanyAuthEntity.builder()
                        .companyId(UUID.fromString("33333333-3333-3333-3333-333333333333"))
                        .email("netcompany@gmail.com")
                        .hashedPassword(passwordEncoder.encode("Netcompany123!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build(),

                CompanyAuthEntity.builder()
                        .companyId(UUID.fromString("44444444-4444-4444-4444-444444444444"))
                        .email("shopee@gmail.com")
                        .hashedPassword(passwordEncoder.encode("Shopee123!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build(),

                CompanyAuthEntity.builder()
                        .companyId(UUID.fromString("55555555-5555-5555-5555-555555555555"))
                        .email("highlandscoffee@gmail.com")
                        .hashedPassword(passwordEncoder.encode("Highlands123!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build()
        );

        companyAuthRepository.saveAll(seeds);
        log.info("Seeded {} distinct company accounts.", seeds.size());

//        List<CompanyAuthEntity> seeds = new ArrayList<>();
//        String uuidBased = "00000000-0000-0000-0000-00000000000";
//
//        for (int i = 0; i < 5; i++) {
//            seeds.add(
//                    CompanyAuthEntity.builder()
//                            .companyId(UUID.fromString(uuidBased + i))
//                            .email("nguyensontungtdn1901@gmail.com")
//                            .hashedPassword(encoder.encode("123"))
//                            .ssoToken(null)
//                            .isActivated(true)
//                            .createdAt(LocalDateTime.now())
//                            .updatedAt(LocalDateTime.now())
//                            .build()
//            );
//        }
//
//        companyAuthRepository.saveAll(seeds);
    }
}