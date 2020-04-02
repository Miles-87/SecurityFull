package pl.michonskim.works.security.token;

import com.sun.tools.javac.util.List;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import pl.michonskim.works.dto.TokensDto;
import pl.michonskim.works.entity.User;
import pl.michonskim.works.exception.TokenManagerException;
import pl.michonskim.works.repository.UserRepository;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class TokenManager {

    @Value("${token.access.expiration-date-ms}")
    private Long accessTokenExpirationTimeMs;

    @Value("${token.refresh.expiration-date-ms}")
    private Long refreshTokenExpirationTimeMs;

    @Value("${token.refresh.property}")
    private String refreshTokenProperty;

    @Value("${token.prefix}")
    private String tokenPrefix;

    private final UserRepository userRepository;
    private final SecretKey secretKey;

    // ----------------------------------------------------------------------------------------------------------------
    // GENEROWANIE TOKENA
    // ----------------------------------------------------------------------------------------------------------------
    // authentication to obiekt ktory bedziemy otrzymywac na etapie
    // logowania - jak sie zalogujemy to ten obiekt pozwoli na wyciagniecie
    // z niego danych zalogowanego usera, na podstawie ktorych wygenerujemy token
    public TokensDto generateTokens(Authentication authentication) {

        if (authentication == null) {
            throw new TokenManagerException("authentication object is null");
        }

        User user = userRepository
                .findByName(authentication.getName())
                .orElseThrow(() -> new TokenManagerException("no user with username " + authentication.getName()));

        Date creationDate = new Date();
        long currentDateMs = System.currentTimeMillis();
        long accessTokenExpirationDateInMillis = currentDateMs + accessTokenExpirationTimeMs;
        Date accessTokenExpirationDate = new Date(accessTokenExpirationDateInMillis);
        Date refreshTokenExpirationDate = new Date(System.currentTimeMillis() + refreshTokenExpirationTimeMs);

        String accessToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuedAt(creationDate)
                .setExpiration(accessTokenExpirationDate)
                .signWith(secretKey)
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuedAt(creationDate)
                .setExpiration(refreshTokenExpirationDate)
                .claim(refreshTokenProperty, accessTokenExpirationDateInMillis)
                .signWith(secretKey)
                .compact();

        return TokensDto
                .builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


    // ----------------------------------------------------------------------------------------------------------------
    // PARSOWANIE TOKENA
    // ----------------------------------------------------------------------------------------------------------------
    public UsernamePasswordAuthenticationToken parseAccessToken(String accessToken) {

        if (Objects.isNull(accessToken)) {
            throw new TokenManagerException("access token is null");
        }

        if (!accessToken.startsWith(tokenPrefix)) {
            throw new TokenManagerException("access token is not correct");
        }

        String token = accessToken.replace(tokenPrefix, "");

        Long userId = getId(token);
        User user = userRepository
                .findById(userId)
                .orElseThrow(() -> new TokenManagerException("cannot find user with id from token"));

        return new UsernamePasswordAuthenticationToken(
                user.getName(),
                null,
                List.of(new SimpleGrantedAuthority(user.getRole().toString())));

    }

    private Claims getClaims(String token) {
        if (Objects.isNull(token)) {
            throw new TokenManagerException("token is null");
        }

        return Jwts
                .parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Long getId(String token) {
        return Long.parseLong(getClaims(token).getSubject());
    }

    public Date getExpirationDate(String token) {
        return getClaims(token).getExpiration();
    }

    private boolean isTokenValid(String token) {
       Date expirationDate = getExpirationDate(token);
       return expirationDate.after(new Date());
    }
}
