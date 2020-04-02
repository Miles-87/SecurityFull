package pl.michonskim.works.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CompanyDto {

    private Long id;
    private String name;
    private Integer numberOfEmployee;
    private String specialization;
}
