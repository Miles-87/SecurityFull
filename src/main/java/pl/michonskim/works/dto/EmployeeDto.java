package pl.michonskim.works.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pl.michonskim.works.entity.enums.Gender;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmployeeDto {
    private Long id;
    private String name;
    private String surname;
    private Integer age;
    private Gender gender;
    private CompanyDto companyDto;
}
