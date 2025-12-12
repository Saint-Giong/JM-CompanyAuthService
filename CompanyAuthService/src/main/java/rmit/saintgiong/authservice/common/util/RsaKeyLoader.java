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
     * Loads an RSA public key from PEM-encoded string.
     *
     * @param pem The PEM-encoded public key string
     * @return The RSA public key
     * @throws Exception If key parsing fails
     */
    public RSAPublicKey loadPublicKey(String pem) throws Exception {
        String publicKeyPEM = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // Remove newlines

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Loads an RSA private key from PEM-encoded string.
     *
     * @param pem The PEM-encoded private key string
     * @return The RSA private key
     * @throws Exception If key parsing fails
     */
    public RSAPrivateKey loadPrivateKey(String pem) throws Exception {
        String privateKeyPEM = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}