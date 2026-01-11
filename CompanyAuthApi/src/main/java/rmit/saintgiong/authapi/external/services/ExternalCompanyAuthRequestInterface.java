package rmit.saintgiong.authapi.external.services;

import rmit.saintgiong.authapi.internal.common.dto.auth.CompanyRegistrationRequestDto;
import rmit.saintgiong.authapi.internal.common.dto.subscription.CreateSubscriptionRequestDto;
import rmit.saintgiong.shared.dto.avro.profile.CreateProfileResponseRecord;
import rmit.saintgiong.shared.dto.avro.subscription.CreateSubscriptionResponseRecord;

import java.util.UUID;

public interface ExternalCompanyAuthRequestInterface {

    CreateProfileResponseRecord sendCreateProfileRequest(UUID companyId, CompanyRegistrationRequestDto requestDto);

    CreateSubscriptionResponseRecord sendCreateSubscriptionRequest (CreateSubscriptionRequestDto requestDto);
}
