package rmit.saintgiong.authservice.common.exception.token;

/**
 * Exception thrown when a refresh token reuse is detected.
 * This is a security event - when a previously used/revoked refresh token
 * is attempted to be used again, it may indicate token theft.
 */
public class TokenReuseException extends RuntimeException {
    
    public TokenReuseException(String message) {
        super(message);
    }
    
    public TokenReuseException(String message, Throwable cause) {
        super(message, cause);
    }
}
