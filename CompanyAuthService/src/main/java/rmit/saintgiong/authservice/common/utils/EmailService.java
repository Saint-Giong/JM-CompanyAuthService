package rmit.saintgiong.authservice.common.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;

import jakarta.annotation.PostConstruct;

// Service for sending emails using AWS SES (Simple Email Service).
@Service
@Slf4j
public class EmailService {

    @Value("${AWS_ACCESS_KEY_ID}")
    private String accessKey;

    @Value("${AWS_SECRET_ACCESS_KEY}")
    private String secretKey;

    @Value("${AWS_REGION}")
    private String region;

    @Value("${AWS_SES_SENDER}")
    private String senderEmail;

    @Value("${FRONTEND_BASE_URL}")
    private String frontendBaseUrl;

    private SesV2Client sesClient;

    @PostConstruct
    public void init() {
        this.sesClient = SesV2Client.builder()
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey)))
                .build();
    }

    /**
     * Sends an OTP verification email to a user for account activation.
     *
     * @param recipientEmail The recipient's email address
     * @param userName       The user's display name
     * @param otp            The 6-digit OTP code
     */
    public void sendOtpEmail(String recipientEmail, String userName, String otp, String activationToken) {
        // Prepare Data with OTP
        String activationLink = String.format("%s/activate-account?activationToken=%s", frontendBaseUrl, activationToken);

        String templateData = String.format("{\"name\":\"%s\", \"otp\":\"%s\" , \"activation_link\":\"%s\"}", userName, otp, activationLink);

        // Build Request
        SendEmailRequest request = SendEmailRequest.builder()
                .fromEmailAddress(senderEmail)
                .destination(d -> d.toAddresses(recipientEmail))
                .content(c -> c.template(t -> t
                        .templateName("AccountVerificationTemplate") // Must match AWS Console Name
                        .templateData(templateData)
                ))
                .build();

        // Send
        try {
            sesClient.sendEmail(request);
            log.info("OTP email sent to {}", recipientEmail);
        } catch (SesV2Exception e) {
            log.error("AWS SES Error: {}", e.awsErrorDetails().errorMessage());
            throw e;
        }
    }
}