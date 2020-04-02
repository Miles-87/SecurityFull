package pl.michonskim.works.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.michonskim.works.entity.User;
import pl.michonskim.works.exception.UserNotFoundException;
import pl.michonskim.works.repository.UserRepository;

import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Qualifier("userDetailsServiceImpl")
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository
                .findByName(username)
                .orElseThrow(() -> new UserNotFoundException("no user with name " + username));

        return new org.springframework.security.core.userdetails.User(
                user.getName(),
                user.getPassword(),
                true, true, true, true,
                Stream.of(user.getRole())
                        .map(role -> new SimpleGrantedAuthority(role.toString()))
                        .collect(Collectors.toList())
        );
    }
}
