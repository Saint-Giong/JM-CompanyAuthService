package rmit.saintgiong.authservice.domain.services.external;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.external.services.ExternalCompanyAuthInterface;
import rmit.saintgiong.authapi.external.services.kafka.EventProducerInterface;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.type.KafkaTopic;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileResponseRecord;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileRequestRecord;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

@Service
@Slf4j
@RequiredArgsConstructor
public class ExternalCompanyAuthService implements ExternalCompanyAuthInterface {

    private final EventProducerInterface eventProducer;

    @Override
    public CreateProfileResponseRecord sendRegisterRequestForCompanyProfile(UUID companyId, CompanyRegistrationRequestDto requestDto) {
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
                    KafkaTopic.COMPANY_REGISTRATION_REQUEST_TOPIC,
                    KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC,
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
}
