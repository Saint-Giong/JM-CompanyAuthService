package rmit.saintgiong.authservice.common.utils;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;
import software.amazon.awssdk.services.sesv2.model.SesV2Exception;


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

    public void sendSubscriptionStatusMail(String recipientEmail, String userName, long expiredInMs) {
        int numOfDays = Math.max(0, (int) (expiredInMs / 1000 / 60 / 60 / 24));

        String notificationHtml = buildSubscriptionMessageHtml(numOfDays);
        String notificationText = buildSubscriptionMessageText(numOfDays);

        String htmlBody = String.format(
                "<html>" +
                        "<head><style>" +
                        "body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }" +
                        ".container { max-width: 600px; margin: 0 auto; padding: 20px; }" +
                        ".header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }" +
                        ".content { background-color: #f9f9f9; padding: 30px; }" +
                        ".footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }" +
                        ".highlight { color: #4CAF50; font-weight: bold; font-size: 18px; }" +
                        "</style></head>" +
                        "<body>" +
                        "<div class='container'>" +
                        "<div class='header'><h1>Subscription Update</h1></div>" +
                        "<div class='content'>" +
                        "<p>Hello <strong>%s</strong>,</p>" +
                        "<p>%s</p>" +
                        "<p>Please renew your subscription to continue enjoying our services without interruption.</p>" +
                        "<p>If you have any questions, feel free to contact our support team.</p>" +
                        "<p>Best regards,<br>Job Manager Team</p>" +
                        "</div>" +
                        "<div class='footer'>" +
                        "<p>This is an automated message. Please do not reply to this email.</p>" +
                        "</div>" +
                        "</div>" +
                        "</body>" +
                        "</html>",
                userName, notificationHtml
        );

        String textBody = buildTextBody(userName, notificationText);

        SendEmailRequest request = SendEmailRequest.builder()
                .fromEmailAddress(senderEmail)
                .destination(d -> d.toAddresses(recipientEmail))
                .content(c -> c.simple(s -> s
                        .subject(sub -> sub.data("Subscription Expiration Notice"))
                        .body(b -> b
                                .html(h -> h.data(htmlBody))
                                .text(t -> t.data(textBody))
                        )
                ))
                .build();

        try {
            sesClient.sendEmail(request);
            log.info("Subscription status email sent to {} (expires in {} days)", recipientEmail, numOfDays);
        } catch (SesV2Exception e) {
            log.error("AWS SES Error sending subscription email to {}: {}", recipientEmail, e.awsErrorDetails().errorMessage());
            throw e;
        }
    }

    private static @NonNull String buildSubscriptionMessageHtml(int numOfDays) {
        if (numOfDays == 0) {
            return "Your subscription is currently <span class='highlight'>EXPIRED</span>.";
        }
        return String.format(
                "Your subscription will expire in <span class='highlight'>%d days</span>.",
                numOfDays
        );
    }

    private static @NonNull String buildSubscriptionMessageText(int numOfDays) {
        if (numOfDays == 0) {
            return "Your subscription is currently EXPIRED.";
        }
        return "Your subscription will expire in " + numOfDays + " days.";
    }

    private static @NonNull String buildTextBody(String userName, String notificationText) {
        return String.format(
                """
                        Hello %s,
                        
                        %s
                        
                        Please renew your subscription to continue enjoying our services without interruption.
                        
                        If you have any questions, feel free to contact our support team.
                        
                        Best regards,
                        Job Manager Team""",
                userName, notificationText
        );
    }
}