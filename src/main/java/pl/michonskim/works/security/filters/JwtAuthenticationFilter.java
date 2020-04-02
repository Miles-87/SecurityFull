package pl.michonskim.works.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pl.michonskim.works.dto.AuthenticationUserDto;
import pl.michonskim.works.dto.TokensDto;
import pl.michonskim.works.security.token.TokenManager;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

// ten filter bedzie reagowal kiedy wyslesz zadanie /login w POST
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final TokenManager tokenManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, TokenManager tokenManager) {
        this.authenticationManager = authenticationManager;
        this.tokenManager = tokenManager;
        // setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/my-login", "POST"));
    }

    // ponizsza metoda kiedy wywolasz zadanie /login w POST automatycznie
    // sprobuje zalogowac naszego usera
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        try {

            // pobieram dane z JSON body
            AuthenticationUserDto authenticationUserDto = new ObjectMapper().readValue(request.getInputStream(), AuthenticationUserDto.class);
            // ta metoda sprobuje zalogowac usera o danych ktore podales
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationUserDto.getUsername(),
                    authenticationUserDto.getPassword(),
                    Collections.emptyList()
            ));
        } catch (Exception e) {
            e.printStackTrace();
            throw new SecurityException(e.getMessage());
        }

    }

    // ta metoda wykona sie kiedy nastapilo prawidlowe logowanie
    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult) throws IOException, ServletException {

        // czwarty argument to Authentication ktory przechowuje usera, ktory bedzie zalogowany
        TokensDto tokens = tokenManager.generateTokens(authResult);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(new ObjectMapper().writeValueAsString(tokens));
        response.getWriter().flush();
        response.getWriter().close();
    }
}
