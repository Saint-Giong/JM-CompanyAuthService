package rmit.saintgiong.authservice.common.config;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;



@Component
@Slf4j
@RequiredArgsConstructor
public class DataSeedingConfig implements CommandLineRunner {

    private final CompanyAuthRepository companyAuthRepository;
    private final PasswordEncoder passwordEncoder;

    // Company UUIDs - shared across all services
    public static final UUID NAB_COMPANY_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    public static final UUID GOOGLE_COMPANY_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    public static final UUID NETCOMPANY_COMPANY_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    public static final UUID SHOPEE_COMPANY_ID = UUID.fromString("44444444-4444-4444-4444-444444444444");

    // Subscription UUIDs - for linking with Payment service
    public static final UUID NAB_SUBSCRIPTION_ID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    public static final UUID GOOGLE_SUBSCRIPTION_ID = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    public static final UUID NETCOMPANY_SUBSCRIPTION_ID = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");
    public static final UUID SHOPEE_SUBSCRIPTION_ID = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");

    // Transaction UUIDs - for linking Subscription with Payment
    public static final UUID NAB_TRANSACTION_ID = UUID.fromString("11111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    public static final UUID GOOGLE_TRANSACTION_ID = UUID.fromString("22222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    public static final UUID NETCOMPANY_TRANSACTION_ID = UUID.fromString("33333333-cccc-cccc-cccc-cccccccccccc");
    public static final UUID SHOPEE_TRANSACTION_ID = UUID.fromString("44444444-dddd-dddd-dddd-dddddddddddd");

    @Override
    public void run(String @NonNull ... args) {
        if (companyAuthRepository.count() != 0) {
            return;
        }

        List<CompanyAuthEntity> seeds = List.of(
                // ============================================================
                // FREEMIUM 1: NAB - Subscription EXPIRED (expiry: now - 31 days)
                // Has 2 job posts with different job titles
                // Has notifications: payment success + subscription expired
                // ============================================================
                CompanyAuthEntity.builder()
                        .companyId(NAB_COMPANY_ID)
                        .email("nab@gmail.com")
                        .hashedPassword(passwordEncoder.encode("SecuredPass123!!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build(),

                // ============================================================
                // FREEMIUM 2: Google - Subscription CANCELLED (expiry: null)
                // Transaction was 50 days ago (logic: if EXPIRED > 3 days, set CANCELLED + null expiry)
                // Has 2 job posts with different job titles
                // Has notifications: payment success + subscription expired
                // ============================================================
                CompanyAuthEntity.builder()
                        .companyId(GOOGLE_COMPANY_ID)
                        .email("google@gmail.com")
                        .hashedPassword(passwordEncoder.encode("SecuredPass123!!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build(),

                // ============================================================
                // PREMIUM 1: Netcompany - Software Engineering Domain
                // Subscription ACTIVE (expiry: now + 30 days)
                // Has 2+ job posts for Software Engineers
                // Search Profile: React, Spring Boot, Docker talents
                //   - Full-time + Intern Software Engineer
                //   - Vietnam, salary > 800 USD
                // ============================================================
                CompanyAuthEntity.builder()
                        .companyId(NETCOMPANY_COMPANY_ID)
                        .email("netcompany@gmail.com")
                        .hashedPassword(passwordEncoder.encode("SecuredPass123!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build(),

                // ============================================================
                // PREMIUM 2: Shopee - Data Engineering Domain
                // Subscription ACTIVE (expiry: now + 30 days)
                // Has 2+ job posts for Data Engineers
                // Search Profile: Python, AWS, Snowflake talents
                //   - Contractual Data Engineer
                //   - Singapore, salary > 1200 USD
                // ============================================================
                CompanyAuthEntity.builder()
                        .companyId(SHOPEE_COMPANY_ID)
                        .email("shopee@gmail.com")
                        .hashedPassword(passwordEncoder.encode("SecuredPass123!"))
                        .ssoToken(null)
                        .isActivated(true)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .build()
        );

        companyAuthRepository.saveAll(seeds);
        log.info("Seeded {} distinct company accounts (2 Freemiums + 2 Premiums).", seeds.size());
    }
}