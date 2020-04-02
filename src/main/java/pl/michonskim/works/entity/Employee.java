package pl.michonskim.works.entity;

import lombok.*;
import pl.michonskim.works.entity.enums.Gender;

import javax.persistence.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class Employee {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String surname;
    private Integer age;
    @Enumerated(EnumType.STRING)
    private Gender gender;

    @ManyToOne(cascade = CascadeType.PERSIST)
    @JoinColumn(name = "company_id")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private Company company;
}
