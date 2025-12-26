package rmit.saintgiong.authservice.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import rmit.saintgiong.authservice.common.utils.JweTokenService;
import rmit.saintgiong.shared.token.TokenClaimsDto;

@Component
@Slf4j
@RequiredArgsConstructor
public class JweAuthRequestFilter extends OncePerRequestFilter {

    private final JweTokenService jweTokenService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        List<GrantedAuthority> authorityList = new ArrayList<>();

        String accessHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refreshToken = request.getHeader("X-Refresh-Token");

        if (refreshToken != null) {
            String currentUserId = extractAndSetRoleForSecurityContext(refreshToken, authorityList, true);

            if (accessHeader != null && accessHeader.startsWith("Bearer ")) {
                String accessToken = accessHeader.replace("Bearer ", "");
                extractAndSetRoleForSecurityContext(accessToken, authorityList, false);
            }

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(currentUserId, null, authorityList);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            context.setAuthentication(auth);

            SecurityContextHolder.setContext(context);
        }

        filterChain.doFilter(request, response);
    }

    private String extractAndSetRoleForSecurityContext(String tokenValue, List<GrantedAuthority> authorityList, boolean isRefresh) {
        try {
            TokenClaimsDto tokenClaimsDto = jweTokenService.getTokenClaimsDtoDecryptedFromTokenString(tokenValue);

            if (tokenClaimsDto != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                SimpleGrantedAuthority auth = new SimpleGrantedAuthority("ROLE_" + tokenClaimsDto.getRole().name() + (isRefresh ? "_REFRESH" : ""));
                authorityList.add(auth);

                return tokenClaimsDto.getSub().toString();
            }
        } catch (Exception e) {
            log.warn("Cannot set SecurityContext for {} Token: {}", isRefresh ? "Refresh" : "Access", e.getMessage());
        }

        return null;
    }
}
