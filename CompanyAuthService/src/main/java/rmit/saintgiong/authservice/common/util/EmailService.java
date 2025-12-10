package rmit.saintgiong.authservice.common.util;

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
public class EmailService {

    @Value("${aws.accessKeyId}")
    private String accessKey;

    @Value("${aws.secretAccessKey}")
    private String secretKey;

    @Value("${aws.region}")
    private String region;

    @Value("${aws.ses.sender}")
    private String senderEmail;

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
     * Sends a verification email to a newly registered user.
     *
     * @param recipientEmail The recipient's email address
     * @param userName       The user's display name
     * @param activationLink The activation link for account verification
     */
    public void sendVerificationEmail(String recipientEmail, String userName, String activationLink) {

        // Prepare Data
        String templateData = String.format("{\"name\":\"%s\", \"link\":\"%s\"}", userName, activationLink);

        //Build Request
        SendEmailRequest request = SendEmailRequest.builder()
                .fromEmailAddress(senderEmail)
                .destination(d -> d.toAddresses(recipientEmail))
                .content(c -> c.template(t -> t
                        .templateName("RegistrationTemplate") // Must match AWS Console Name
                        .templateData(templateData)
                ))
                .build();

        //Send
        try {
            sesClient.sendEmail(request);
            System.out.println("Email sent to " + recipientEmail);
        } catch (SesV2Exception e) {
            System.err.println("AWS SES Error: " + e.awsErrorDetails().errorMessage());
            throw e;
        }
    }
}