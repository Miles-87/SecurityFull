package pl.michonskim.works.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pl.michonskim.works.entity.enums.Role;

import javax.persistence.*;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User {

    @GeneratedValue
    @Id
    private Long id;

    private String name;
    private String password;
    private String email;

    @Enumerated(EnumType.STRING)
    private Role role;

}
