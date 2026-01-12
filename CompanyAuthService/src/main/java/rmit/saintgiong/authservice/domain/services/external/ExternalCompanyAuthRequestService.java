package rmit.saintgiong.authservice.domain.services.external;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.external.services.ExternalCompanyAuthRequestInterface;
import rmit.saintgiong.authapi.external.services.kafka.EventProducerInterface;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.subscription.CreateSubscriptionRequestDto;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileResponseRecord;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileRequestRecord;
import rmit.saintgiong.shared.dto.avro.subscription.CreateSubscriptionRequestRecord;
import rmit.saintgiong.shared.dto.avro.subscription.CreateSubscriptionResponseRecord;
import rmit.saintgiong.shared.type.KafkaTopic;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

@Service
@Slf4j
@RequiredArgsConstructor
public class ExternalCompanyAuthRequestService implements ExternalCompanyAuthRequestInterface {

    private final EventProducerInterface eventProducer;

    @Override
    public CreateProfileResponseRecord sendCreateProfileRequest (UUID companyId, CompanyRegistrationRequestDto requestDto) {
        try {
            CreateProfileRequestRecord profileSentRecord = CreateProfileRequestRecord.newBuilder()
                    .setCompanyId(companyId)
                    .setCompanyName(requestDto.getCompanyName())
                    .setCountry(requestDto.getCountry())
                    .setPhoneNumber(Optional.ofNullable(requestDto.getPhoneNumber()).orElse(""))
                    .setCity(Optional.ofNullable(requestDto.getCity()).orElse(""))
                    .setAddress(Optional.ofNullable(requestDto.getAddress()).orElse(""))
                    .build();

            CreateProfileResponseRecord response = eventProducer.sendAndReceive(
                    KafkaTopic.JM_CREATE_PROFILE_REQUEST_TOPIC,
                    KafkaTopic.JM_CREATE_PROFILE_RESPONSE_TOPIC,
                    profileSentRecord,
                    CreateProfileResponseRecord.class
            );

            return response;

        } catch (ExecutionException | InterruptedException e) {
            return CreateProfileResponseRecord.newBuilder()
                    .setCompanyId(null)
                    .build();
        }
    }

    @Override
    public CreateSubscriptionResponseRecord sendCreateSubscriptionRequest(CreateSubscriptionRequestDto requestDto) {
        try {
            CreateSubscriptionRequestRecord requestRecord = CreateSubscriptionRequestRecord.newBuilder()
                    .setCompanyId(requestDto.getCompanyId())
                    .build();

            CreateSubscriptionResponseRecord response = eventProducer.sendAndReceive(
                    KafkaTopic.JM_CREATE_SUBSCRIPTION_REQUEST_TOPIC,
                    KafkaTopic.JM_CREATE_SUBSCRIPTION_RESPONSE_TOPIC,
                    requestRecord,
                    CreateSubscriptionResponseRecord.class
            );

            return response;

        } catch (ExecutionException | InterruptedException e) {
            return CreateSubscriptionResponseRecord.newBuilder()
                    .setCompanyId(null)
                    .build();
        }
    }
}
