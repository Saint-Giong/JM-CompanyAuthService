package rmit.saintgiong.authservice.common.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// Utility component for loading RSA public and private keys from PEM format.
@Component
public class RsaKeyLoader {

    @Value("${key.public-key-b64:}")
    private String publicKeyB64Prop;

    @Value("${key.private-key-b64:}")
    private String privateKeyB64Prop;

    /**
     * Loads an RSA public key from the {@code PUBLIC_KEY_B64} environment variable.
     * The environment variable should contain a Base64-encoded public key.
     *
     * @return The RSA public key
     * @throws Exception If key parsing fails
     */
    public RSAPublicKey loadPublicKey() throws Exception {
        byte[] encoded = Base64.getDecoder().decode(publicKeyB64Prop);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Loads an RSA private key from a PEM-encoded string.
     *
     * @return The RSA private key
     * @throws Exception If key parsing fails
     */
    public RSAPrivateKey loadPrivateKey() throws Exception {
        byte[] encoded = Base64.getDecoder().decode(privateKeyB64Prop);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}