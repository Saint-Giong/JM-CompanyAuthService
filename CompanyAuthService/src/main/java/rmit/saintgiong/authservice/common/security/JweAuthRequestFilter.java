package rmit.saintgiong.authservice.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
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
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        List<GrantedAuthority> authorityList = new ArrayList<>();

        String accessHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refreshHeader = request.getHeader("X-Refresh-Token");

        String currentUserId = "";
        if (accessHeader != null && accessHeader.startsWith("Bearer ")) {
            String accessToken = accessHeader.substring(7);
            String userId = extractAndSetRoleForSecurityContext(accessToken, authorityList, false);
            if (userId != null) currentUserId = userId;
        }

        if (refreshHeader != null && !refreshHeader.isEmpty()) {
            String userId = extractAndSetRoleForSecurityContext(refreshHeader, authorityList, true);
            if (userId != null && currentUserId.isEmpty()) currentUserId = userId;
        }

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(currentUserId, null, authorityList);
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);

        filterChain.doFilter(request, response);
    }

    private String extractAndSetRoleForSecurityContext(String tokenValue, List<GrantedAuthority> authorityList, boolean isRefresh) {
        try {
            if (tokenValue == null || tokenValue.trim().isEmpty()) return null;

            TokenClaimsDto tokenClaimsDto = jweTokenService.validateAccessToken(tokenValue);

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

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return false;
    }
}
