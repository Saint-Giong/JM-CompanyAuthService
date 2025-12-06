package rmit.saintgiong.authservice.common.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.Console;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
@Service
public class RsaJweService {

    @Value("${jwe.public-key}")
    private String publicKeyPem;

    @Value("${jwe.private-key}")
    private String privateKeyPem;

    @Value("${jwe.issuer}")
    private String issuer;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private final RsaKeyLoader keyLoader = new RsaKeyLoader();

    @PostConstruct
    public void init() throws Exception {
        this.publicKey = keyLoader.loadPublicKey(publicKeyPem);
        this.privateKey = keyLoader.loadPrivateKey(privateKeyPem);
    }

    /**
     * Generates a JWE with metadata in the HEADER (Part 1).
     * * @param payloadMap The sensitive data (Plaintext)
     * @param ttlSeconds Time-to-live in seconds
     * @return The 5-part JWE String
     */
    public String encrypt(Map<String, Object> payloadMap, long ttlSeconds) throws JOSEException {

        long now = Instant.now().getEpochSecond();
        long exp = now + ttlSeconds;

        // 1. Configure JWE Header
        // alg: RSA-OAEP-256 (Asymmetric)
        // enc: A256GCM (Standard AES GCM)
        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A256GCM
        );

        // 2. Add specific metadata to HEADER as requested
        // typ: JOSE
        // iss: JM_BACKEND
        headerBuilder.type(JOSEObjectType.JOSE);
        headerBuilder.issuer(issuer);
        JWEHeader header = headerBuilder.build();

        // 3. Create Payload
        Payload payload = new Payload(payloadMap);

        // 4. Create JWE Object
        JWEObject jweObject = new JWEObject(header, payload);

        // 5. Encrypt
        // - Generates the random Content Encryption Key (CEK)
        // - Generates the random IV (96-bit)
        // - Encrypts the CEK (Part 2) using RSA public key
        // - Encrypts the Payload (Part 4) using (CEK)
        // - Generates the Auth Tag (Part 5)
        jweObject.encrypt(new RSAEncrypter(publicKey));

        // 6. Serialize to 5-part string
        return jweObject.serialize();
    }

    /**
     * Decrypts and validates the JWE.
     */
    public Map<String, Object> decrypt(String jweString) throws Exception {
        JWEObject jweObject = JWEObject.parse(jweString);

        // 1. Decrypt (using Private Key)
        jweObject.decrypt(new RSADecrypter(privateKey));

        // 2. Validate Expiration (since we put it in the header, we must check it manually)
        Number exp = (Number) jweObject.getHeader().getCustomParam("exp");
        if (exp != null) {
            long now = Instant.now().getEpochSecond();
            if (now > exp.longValue()) {
                throw new RuntimeException("Token expired");
            }
        }

        // 3. Return Payload
        return jweObject.getPayload().toJSONObject();
    }

    /**
     * Parses the JWE and returns ALL components (Header, Payload, and Raw Encryption Parts).
     */
    public Map<String, Object> inspect(String jweString) throws Exception {
        // 1. Parse the JWE String
        JWEObject jweObject = JWEObject.parse(jweString);

        // 2. Decrypt it (required to see the payload)
        jweObject.decrypt(new RSADecrypter(privateKey));

        // 3. Construct a detailed report
        Map<String, Object> report = new LinkedHashMap<>();

        // --- PART 1: HEADER ---
        // This verifies your 'iss', 'exp', 'iat' are actually in the Header
        report.put("1_header", jweObject.getHeader().toJSONObject());

        // --- PART 2: ENCRYPTED KEY ---
        // The random key used to encrypt the payload, encrypted by your RSA Public Key
        report.put("2_encrypted_key", jweObject.getEncryptedKey() != null ? jweObject.getEncryptedKey().toString() : "null");

        // --- PART 3: IV (Initialization Vector) ---
        // The random salt (96 bits)
        report.put("3_iv", jweObject.getIV() != null ? jweObject.getIV().toString() : "null");

        // --- PART 4: CIPHERTEXT ---
        // The actual encrypted blob of your data
        report.put("4_ciphertext", jweObject.getCipherText().toString());

        // --- PART 5: AUTHENTICATION TAG ---
        // Ensures integrity (nobody tampered with the data)
        report.put("5_auth_tag", jweObject.getAuthTag() != null ? jweObject.getAuthTag().toString() : "null");

        // --- DECRYPTED PAYLOAD ---
        // The readable content
        report.put("decrypted_payload", jweObject.getPayload().toJSONObject());

        return report;
    }
}