package pl.michonskim.works.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.michonskim.works.dto.CompanyDto;
import pl.michonskim.works.entity.Company;
import pl.michonskim.works.exception.CompanyAlreadyExistException;
import pl.michonskim.works.exception.CompanyNotFoundException;
import pl.michonskim.works.exception.CompanyNullException;
import pl.michonskim.works.mapper.MyModelMapper;
import pl.michonskim.works.repository.CompanyRepository;
import pl.michonskim.works.repository.EmployeeRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class CompanyService {

    private final CompanyRepository companyRepository;
    private final EmployeeRepository employeeRepository;

    public List<CompanyDto> findAll() {
        return companyRepository.findAll()
                .stream()
                .map(MyModelMapper::fromCompanyToCompanyDto)
                .collect(Collectors.toList());
    }

    public CompanyDto findOne(Long id) {
        if (id == null) {
            throw new CompanyNotFoundException("There is no company with this id", LocalDateTime.now());
        }
        return companyRepository.findById(id)
                .map(MyModelMapper::fromCompanyToCompanyDto)
                .orElseThrow(() -> new CompanyNotFoundException("There is no company with this id", LocalDateTime.now()));
    }

    public CompanyDto add(CompanyDto companyDto) {
        if (companyDto == null) {
            throw new CompanyNullException("Company shouldn't be null", LocalDateTime.now());
        }
        if(companyRepository.findById(companyDto.getId()).isPresent()){
            throw new CompanyAlreadyExistException("exist");
        }
        Company company = MyModelMapper.fromCompanyDtoToCompany(companyDto);
        Company companyFromDb = companyRepository.save(company);
        return MyModelMapper.fromCompanyToCompanyDto(companyFromDb);
    }

    public CompanyDto update(Long id, CompanyDto companyDto) {
        if (id == null) {
            throw new CompanyNotFoundException("There is no company with this id", LocalDateTime.now());
        }
        if (companyDto == null) {
            throw new CompanyNullException("Company shouldn't be null", LocalDateTime.now());
        }
        Company company = companyRepository.getOne(id);
        company.setName(companyDto.getName() == null ? company.getName() : companyDto.getName());
        company.setNumberOfEmployee(companyDto.getNumberOfEmployee() == null ? company.getNumberOfEmployee() : companyDto.getNumberOfEmployee());
        company.setSpecialization(companyDto.getSpecialization() == null ? company.getSpecialization() : companyDto.getSpecialization());
        Company companyFromDb = companyRepository.save(company);
        return MyModelMapper.fromCompanyToCompanyDto(companyFromDb);

    }

    public CompanyDto delete(Long id) {
        Company company = companyRepository.findById(id)
                .orElseThrow(() -> new CompanyNotFoundException("There is no company with this id", LocalDateTime.now()));

        employeeRepository.saveAll(employeeRepository.findAllByCompany_Id(company.getId()))
                .stream()
                .peek(employee -> employee.setCompany(null))
                .collect(Collectors.toList());

        companyRepository.delete(company);
        return MyModelMapper.fromCompanyToCompanyDto(company);

    }
}