package pl.michonskim.works.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.michonskim.works.dto.RegisterUserDto;
import pl.michonskim.works.entity.User;
import pl.michonskim.works.exception.UserException;
import pl.michonskim.works.mapper.MyModelMapper;
import pl.michonskim.works.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class RegisterService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Long create(RegisterUserDto registerUserDto) {
        if (registerUserDto == null) {
            throw new UserException("User shouldn't be null", LocalDateTime.now());
        }
        if (userRepository.findByName(registerUserDto.getName()).isPresent()) {
            throw new UserException("User with this name exists", LocalDateTime.now());
        }
        if (userRepository.findByEmail(registerUserDto.getEmail()).isPresent()) {
            throw new UserException("User with this email exist", LocalDateTime.now());
        }
        if (!Objects.equals(registerUserDto.getPassword(), registerUserDto.getPasswordConfirmation())) {
            throw new UserException("Password and password confirmation should be equals", LocalDateTime.now());
        }
        if (registerUserDto.getRole() == null) {
            throw new UserException("Role shouldn't be null", LocalDateTime.now());
        }
        User user = MyModelMapper.fromRegistryUserDtoToUser(registerUserDto);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return user.getId();
    }
}
