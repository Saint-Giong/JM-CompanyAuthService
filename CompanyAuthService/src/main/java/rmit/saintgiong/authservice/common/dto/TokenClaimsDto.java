package rmit.saintgiong.authservice.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import rmit.saintgiong.authservice.common.auth.Role;
import rmit.saintgiong.authservice.common.auth.TokenType;

import java.util.UUID;

// DTO representing the claims/payload contained in a JWE token.
// This data is encrypted in the token and cannot be read by unauthorized parties.
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenClaimsDto {
    
    // Subject - the company ID.
    private UUID sub;
    
    // User email.
    private String email;
    
    // User role.
    private Role role;
    
    // Token type (ACCESS or REFRESH).
    private TokenType type;
    
    // Issued at timestamp (epoch seconds).
    private long iat;
    
    // Expiration timestamp (epoch seconds).
    private long exp;
    
    // Token issuer.
    private String iss;

    // JWT ID - unique identifier for the token.
    private String jti;

}
