package pl.michonskim.works.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.michonskim.works.dto.EmployeeDto;
import pl.michonskim.works.entity.Employee;
import pl.michonskim.works.exception.CompanyNotFoundException;
import pl.michonskim.works.exception.EmployeeNotFoundException;
import pl.michonskim.works.exception.EmployeeNullException;
import pl.michonskim.works.mapper.MyModelMapper;
import pl.michonskim.works.repository.CompanyRepository;
import pl.michonskim.works.repository.EmployeeRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class EmployeeService {

    private final EmployeeRepository employeeRepository;
    private final CompanyRepository companyRepository;

    public List<EmployeeDto> all() {
        return employeeRepository.findAll()
                .stream()
                .map(MyModelMapper::fromEmployeeToEmployeeDto)
                .collect(Collectors.toList());
    }

    public EmployeeDto one(Long id) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new EmployeeNotFoundException("there is no employee with this id", LocalDateTime.now()));
        return MyModelMapper.fromEmployeeToEmployeeDto(employee);

    }

    public List<EmployeeDto> allEmployeeByCompany(Long id) {
        return employeeRepository.findAllByCompany_Id(id)
                .stream()
                .map(MyModelMapper::fromEmployeeToEmployeeDto)
                .collect(Collectors.toList());
    }

    public EmployeeDto add(EmployeeDto employeeDto) {
        if (employeeDto == null) {
            throw new EmployeeNullException("employee shouldn't be null", LocalDateTime.now());
        }
        Employee employee = MyModelMapper.fromEmployeeDtoToEmployee(employeeDto);
        Employee employeeFromDb = employeeRepository.save(employee);
        return MyModelMapper.fromEmployeeToEmployeeDto(employeeFromDb);
    }

    public EmployeeDto update(Long id, EmployeeDto employeeDto) {
        if (employeeDto == null) {
            throw new EmployeeNullException("employee shouldn't be null", LocalDateTime.now());
        }
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new EmployeeNotFoundException("there is no employee with this id", LocalDateTime.now()));
        employee.setName(employeeDto.getName() == null ? employee.getName() : employeeDto.getName());
        employee.setSurname(employeeDto.getSurname() == null ? employee.getSurname() : employeeDto.getSurname());
        employee.setAge(employeeDto.getAge() == null ? employee.getAge() : employeeDto.getAge());
        employee.setGender(employeeDto.getGender() == null ? employee.getGender() : employeeDto.getGender());
        Employee employeeFromDb = employeeRepository.save(employee);
        return MyModelMapper.fromEmployeeToEmployeeDto(employeeFromDb);

    }

    public EmployeeDto delete(Long id) {
        if (id == null) {
            throw new EmployeeNotFoundException("there is no employee with this id", LocalDateTime.now());
        }
        Employee employee = employeeRepository.findById(id).orElseThrow(() -> new EmployeeNotFoundException("there is no employee with this id", LocalDateTime.now()));
        employeeRepository.delete(employee);
        return MyModelMapper.fromEmployeeToEmployeeDto(employee);
    }

}
