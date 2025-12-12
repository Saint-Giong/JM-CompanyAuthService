package rmit.saintgiong.authservice.common.util;

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

    /**
     * Loads an RSA public key from the {@code PUBLIC_KEY_B64} environment variable.
     * The environment variable should contain a Base64-encoded public key.
     *
     * @return The RSA public key
     * @throws Exception If key parsing fails
     */
    public RSAPublicKey loadPublicKey() throws Exception {
        String publicKeyPEM = System.getenv("PUBLIC_KEY_B64");
        if (publicKeyPEM == null || publicKeyPEM.isBlank()) {
            throw new IllegalStateException("PUBLIC_KEY_B64 not set");
        }
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Loads an RSA private key from PEM-encoded string.
     *
     * @return The RSA private key
     * @throws Exception If key parsing fails
     */
    public RSAPrivateKey loadPrivateKey() throws Exception {
        String privateKeyPEM = System.getenv("PRIVATE_KEY_B64");
        if (privateKeyPEM == null || privateKeyPEM.isBlank()) {
            throw new IllegalStateException("PRIVATE_KEY_B64 not set");
        }

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}