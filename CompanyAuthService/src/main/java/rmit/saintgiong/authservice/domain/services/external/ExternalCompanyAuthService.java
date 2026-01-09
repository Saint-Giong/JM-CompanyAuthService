package rmit.saintgiong.authservice.domain.services.external;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import rmit.saintgiong.authapi.external.services.ExternalCompanyAuthInterface;
import rmit.saintgiong.authapi.external.services.kafka.EventProducerInterface;
import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.external.common.dto.avro.ProfileRegistrationResponseRecord;
import rmit.saintgiong.authapi.external.common.dto.avro.ProfileRegistrationSentRecord;
import rmit.saintgiong.authapi.internal.common.type.KafkaTopic;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

@Service
@Slf4j
@RequiredArgsConstructor
public class ExternalCompanyAuthService implements ExternalCompanyAuthInterface {

    private final EventProducerInterface eventProducer;

    @Override
    public ProfileRegistrationResponseRecord sendRegisterRequestForCompanyProfile(UUID companyId, CompanyRegistrationRequestDto requestDto) {
        try {
            ProfileRegistrationSentRecord profileSentRecord = ProfileRegistrationSentRecord.newBuilder()
                    .setCompanyId(companyId)
                    .setCompanyName(requestDto.getCompanyName())
                    .setCountry(requestDto.getCountry())
                    .setPhoneNumber(Optional.ofNullable(requestDto.getPhoneNumber()).orElse(""))
                    .setCity(Optional.ofNullable(requestDto.getCity()).orElse(""))
                    .setAddress(Optional.ofNullable(requestDto.getAddress()).orElse(""))
                    .build();

            ProfileRegistrationResponseRecord response = eventProducer.sendAndReceive(
                    KafkaTopic.COMPANY_REGISTRATION_REQUEST_TOPIC,
                    KafkaTopic.COMPANY_REGISTRATION_REPLY_TOPIC,
                    profileSentRecord,
                    ProfileRegistrationResponseRecord.class
            );

            return response;

        } catch (ExecutionException | InterruptedException e) {
            return ProfileRegistrationResponseRecord.newBuilder()
                    .setCompanyId(null)
                    .build();
        }
    }
}
