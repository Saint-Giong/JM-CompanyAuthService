package rmit.saintgiong.authservice.domain.services.external;

import java.util.List;
import java.util.UUID;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import rmit.saintgiong.authapi.external.services.ExternalCompanyAuthConsumeInterface;
import rmit.saintgiong.authapi.internal.common.dto.subscription.MailSubscriptionRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.subscription.MailSubscriptionRequestDtoList;
import rmit.saintgiong.authservice.common.exception.resources.ResourceNotFoundException;
import rmit.saintgiong.authservice.common.utils.EmailService;
import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;
import rmit.saintgiong.shared.dto.avro.subscription.MailSubscriptionRequestRecordList;
import rmit.saintgiong.shared.type.KafkaTopic;

@Service
@Slf4j
@RequiredArgsConstructor
public class ExternalCompanyAuthConsumeService implements ExternalCompanyAuthConsumeInterface {

    private final CompanyAuthRepository companyAuthRepository;

    private final EmailService emailService;

    @KafkaListener(topics = KafkaTopic.JM_MAIL_SUBSCRIPTION_NOTIFICATION_TOPIC)
    public void handleSentSubscriptionMailRequest(MailSubscriptionRequestRecordList requestRecordList) {
        List<MailSubscriptionRequestDto> requestDtos = requestRecordList.getSubscriptionList().stream()
                .map(requestRecord ->
                        MailSubscriptionRequestDto.builder()
                                .companyId(requestRecord.getCompanyId())
                                .expiredInMs(requestRecord.getExpiredInMs())
                                .build()
                )
                .toList();

        MailSubscriptionRequestDtoList requestDtoList = MailSubscriptionRequestDtoList.builder()
                .requestDtos(requestDtos)
                .build();

        List<UUID> companyIdList = requestDtoList.getRequestDtos().stream().map(MailSubscriptionRequestDto::getCompanyId).toList();
        List<CompanyAuthEntity> emailList = companyAuthRepository.findAllById(companyIdList);

        for (MailSubscriptionRequestDto requestDto : requestDtoList.getRequestDtos()) {
            CompanyAuthEntity entity = emailList.stream()
                    .filter(
                            curr ->
                                    curr.getCompanyId().equals(requestDto.getCompanyId())
                    )
                    .findFirst()
                    .orElseThrow(
                            () -> new ResourceNotFoundException("Company", "companyId", requestDto.getCompanyId().toString())
                    );

            emailService.sendSubscriptionStatusMail(entity.getEmail(), entity.getEmail(), requestDto.getExpiredInMs());
        }
    }

}
