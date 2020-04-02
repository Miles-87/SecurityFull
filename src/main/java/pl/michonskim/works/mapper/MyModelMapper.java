package pl.michonskim.works.mapper;

import pl.michonskim.works.dto.CompanyDto;
import pl.michonskim.works.dto.EmployeeDto;
import pl.michonskim.works.dto.RegisterUserDto;
import pl.michonskim.works.entity.Company;
import pl.michonskim.works.entity.Employee;
import pl.michonskim.works.entity.User;

import java.util.HashSet;

public interface MyModelMapper {

    static CompanyDto fromCompanyToCompanyDto(Company company){
        return CompanyDto.builder()
                .id(company.getId())
                .name(company.getName())
                .numberOfEmployee(company.getNumberOfEmployee())
                .specialization(company.getSpecialization())
                .build();
    }

    static Company fromCompanyDtoToCompany(CompanyDto companyDto){
        return Company.builder()
                .id(companyDto.getId())
                .name(companyDto.getName())
                .numberOfEmployee(companyDto.getNumberOfEmployee())
                .specialization(companyDto.getSpecialization())
                .employees(new HashSet<>())
                .build();
    }

    static EmployeeDto fromEmployeeToEmployeeDto(Employee employee){
        return EmployeeDto.builder()
                .id(employee.getId())
                .name(employee.getName())
                .surname(employee.getSurname())
                .age(employee.getAge())
                .gender(employee.getGender())
                .companyDto(employee.getCompany()== null ?null:fromCompanyToCompanyDto(employee.getCompany()))
                .build();
    }

    static Employee fromEmployeeDtoToEmployee(EmployeeDto employeeDto){
        return Employee.builder()
                .id(employeeDto.getId())
                .name(employeeDto.getName())
                .surname(employeeDto.getSurname())
                .age(employeeDto.getAge())
                .gender(employeeDto.getGender())
                .company(employeeDto.getCompanyDto()== null ? null : fromCompanyDtoToCompany(employeeDto.getCompanyDto()))
                .build();
    }

    static User fromRegistryUserDtoToUser(RegisterUserDto registerUserDto){
        return User.builder()
                .name(registerUserDto.getName())
                .email(registerUserDto.getEmail())
                .password(registerUserDto.getPassword())
                .role(registerUserDto.getRole())
                .build();
    }

}
