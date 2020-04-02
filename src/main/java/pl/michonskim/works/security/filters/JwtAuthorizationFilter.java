package pl.michonskim.works.security.filters;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import pl.michonskim.works.security.token.TokenManager;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final TokenManager tokenManager;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, TokenManager tokenManager) {
        super(authenticationManager);
        this.tokenManager = tokenManager;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        String accessToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (Objects.nonNull(accessToken)) {
            UsernamePasswordAuthenticationToken auth = tokenManager.parseAccessToken(accessToken);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);

    }
}
