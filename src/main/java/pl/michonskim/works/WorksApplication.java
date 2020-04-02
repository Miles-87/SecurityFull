package pl.michonskim.works;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import javax.crypto.SecretKey;

@SpringBootApplication
public class WorksApplication {

    public static void main(String[] args) {
        SpringApplication.run(WorksApplication.class, args);
    }

    @Bean
    public SecretKey secretKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS512);
    }

}
