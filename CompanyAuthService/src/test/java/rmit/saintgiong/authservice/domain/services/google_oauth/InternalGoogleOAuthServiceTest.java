//// java
//package rmit.saintgiong.authservice.domain.services.google_oauth;
//
//import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.junit.jupiter.MockitoExtension;
//import rmit.saintgiong.authservice.common.config.JweConfig;
//import rmit.saintgiong.shared.token.TokenPairDto;
//import rmit.saintgiong.authapi.internal.common.dto.oauth.GoogleOAuthResponseDto;
//import rmit.saintgiong.shared.type.Role;
//import rmit.saintgiong.authservice.common.exception.resources.CompanyAccountAlreadyExisted;
//import rmit.saintgiong.authservice.common.exception.token.InvalidCredentialsException;
//import rmit.saintgiong.authservice.common.utils.JweTokenService;
//import rmit.saintgiong.authservice.domain.entity.CompanyAuthEntity;
//import rmit.saintgiong.authservice.domain.repository.CompanyAuthRepository;
//import rmit.saintgiong.authservice.domain.services.InternalGoogleOAuthService;
//
//import java.util.*;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.ArgumentMatchers.*;
//import static org.mockito.Mockito.*;
//
//@ExtendWith(MockitoExtension.class)
//class InternalGoogleOAuthServiceTest {
//
//    @Mock
//    private CompanyAuthRepository companyAuthRepository;
//    @Mock
//    private JweTokenService jweTokenService;
//    @Mock
//    private JweConfig jweConfig;
//
//    private InternalGoogleOAuthService internalGoogleOAuthService;
//
//    @BeforeEach
//    void setUp() {
//        internalGoogleOAuthService = Mockito.spy(new InternalGoogleOAuthService(
//                companyAuthRepository,
//                jweTokenService,
//                jweConfig
//        ));
//    }
//
//    @Test
//    void authenticateGoogleUser_returnsRegisterPayload_whenCompanyNotFound() throws Exception {
//        String code = "new-user-code";
//        GoogleIdToken.Payload payload = payload("google-id", "new@company.com", true, "New User");
//        doReturn(payload).when(internalGoogleOAuthService).verifyAndGetGoogleIdTokenPayload(code);
//        when(companyAuthRepository.findByEmail("new@company.com")).thenReturn(Optional.empty());
//        when(jweTokenService.generateTempTokenForGoogleAuth("new@company.com", "google-id")).thenReturn("temp-token");
//
//        // FIX: Add missing mock for jweConfig.getTempTokenTtlSeconds()
//        when(jweConfig.getTempTokenTtlSeconds()).thenReturn(300);
//
//        GoogleOAuthResponseDto result = internalGoogleOAuthService.authenticateGoogleUser(code);
//
//        assertNull(result.getTokenPairDto());
//        assertEquals("temp-token", result.getTempToken());
//        assertEquals(300, result.getTempTokenExpiresIn());
//        assertEquals("new@company.com", result.getEmail());
//        assertEquals("New User", result.getName());
//    }
//
//    @Test
//    void authenticateGoogleUser_throwsConflict_whenEmailExistsWithoutSso() throws Exception {
//        String code = "conflict-code";
//        GoogleIdToken.Payload payload = payload("google-id", "conflict@company.com", true, "Conflict User");
//        doReturn(payload).when(internalGoogleOAuthService).verifyAndGetGoogleIdTokenPayload(code);
//
//        CompanyAuthEntity entity = mock(CompanyAuthEntity.class);
//        when(entity.getSsoToken()).thenReturn(null);
//        when(companyAuthRepository.findByEmail("conflict@company.com")).thenReturn(Optional.of(entity));
//
//        assertThrows(CompanyAccountAlreadyExisted.class, () -> internalGoogleOAuthService.authenticateGoogleUser(code));
//        verify(jweTokenService, never()).generateTempTokenForGoogleAuth(anyString(), anyString());
//    }
//
//    @Test
//    void authenticateGoogleUser_throwsInvalidCredentials_whenSsoTokenMismatch() throws Exception {
//        // NEW TEST: Cover the case where SSO token exists but doesn't match
//        String code = "mismatch-code";
//        GoogleIdToken.Payload payload = payload("different-google-id", "mismatch@company.com", true, "Mismatch User");
//        doReturn(payload).when(internalGoogleOAuthService).verifyAndGetGoogleIdTokenPayload(code);
//
//        CompanyAuthEntity entity = mock(CompanyAuthEntity.class);
//        when(entity.getSsoToken()).thenReturn("original-google-id"); // Different from payload's "different-google-id"
//        when(companyAuthRepository.findByEmail("mismatch@company.com")).thenReturn(Optional.of(entity));
//
//        assertThrows(InvalidCredentialsException.class, () -> internalGoogleOAuthService.authenticateGoogleUser(code));
//        verify(jweTokenService, never()).generateTokenPairDto(any(), anyString(), any(), anyBoolean());
//    }
//
//    @Test
//    void authenticateGoogleUser_returnsTokenPair_whenCompanyHasSso() throws Exception {
//        String code = "login-code";
//        GoogleIdToken.Payload payload = payload("google-id", "login@company.com", true, "Login User");
//        doReturn(payload).when(internalGoogleOAuthService).verifyAndGetGoogleIdTokenPayload(code);
//
//        UUID companyId = UUID.randomUUID();
//        CompanyAuthEntity entity = mock(CompanyAuthEntity.class);
//        when(entity.getSsoToken()).thenReturn("google-id");
//        when(entity.getCompanyId()).thenReturn(companyId);
//        when(entity.getEmail()).thenReturn("login@company.com");
//        when(entity.isActivated()).thenReturn(true);
//        when(companyAuthRepository.findByEmail("login@company.com")).thenReturn(Optional.of(entity));
//
//        TokenPairDto tokenPairDto = TokenPairDto.builder()
//                .accessToken("access-token")
//                .refreshToken("refresh-token")
//                .accessTokenExpiresIn(900L)
//                .refreshTokenExpiresIn(604800L)
//                .build();
//        when(jweTokenService.generateTokenPairDto(companyId, "login@company.com", Role.COMPANY, true))
//                .thenReturn(tokenPairDto);
//
//        GoogleOAuthResponseDto result = internalGoogleOAuthService.authenticateGoogleUser(code);
//
//        assertNotNull(result.getTokenPairDto());
//        assertEquals("access-token", result.getTokenPairDto().getAccessToken());
//        assertEquals("refresh-token", result.getTokenPairDto().getRefreshToken());
//        assertNull(result.getTempToken());
//        assertEquals("login@company.com", result.getEmail());
//        assertNull(result.getName());
//    }
//
//    @Test
//    void authenticateGoogleUser_throwsException_whenEmailNotVerified() throws Exception {
//        // NEW TEST: Cover the case where Google email is not verified
//        String code = "unverified-code";
//        GoogleIdToken.Payload payload = payload("google-id", "unverified@company.com", false, "Unverified User");
//        doReturn(payload).when(internalGoogleOAuthService).verifyAndGetGoogleIdTokenPayload(code);
//
//        assertThrows(IllegalArgumentException.class, () -> internalGoogleOAuthService.authenticateGoogleUser(code));
//        verify(companyAuthRepository, never()).findByEmail(anyString());
//    }
//
//    private GoogleIdToken.Payload payload(String sub, String email, boolean verified, String name) {
//        GoogleIdToken.Payload payload = new GoogleIdToken.Payload();
//        payload.setSubject(sub);
//        payload.setEmail(email);
//        payload.setEmailVerified(verified);
//        payload.set("name", name);
//        return payload;
//    }
//}