package pl.michonskim.works.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pl.michonskim.works.entity.enums.Role;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterUserDto {
    private String name;
    private String password;
    private String passwordConfirmation;
    private String email;
    private Role role;
}
