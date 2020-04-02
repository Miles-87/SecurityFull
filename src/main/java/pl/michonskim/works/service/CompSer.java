package pl.michonskim.works.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.michonskim.works.dto.CompanyDto;
import pl.michonskim.works.entity.Company;
import pl.michonskim.works.exception.CompanyNotFoundException;
import pl.michonskim.works.mapper.MyModelMapper;
import pl.michonskim.works.repository.CompanyRepository;
import pl.michonskim.works.repository.EmployeeRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class CompSer {

    private final CompanyRepository companyRepository;
    private final EmployeeRepository employeeRepository;

    public List<CompanyDto> all(){
        return companyRepository.findAll()
                .stream()
                .map(MyModelMapper::fromCompanyToCompanyDto)
                .collect(Collectors.toList());
    }

    public CompanyDto one(Long id){
        Company company = companyRepository.findById(id).orElseThrow(()-> new CompanyNotFoundException("no",LocalDateTime.now()));
        return MyModelMapper.fromCompanyToCompanyDto(company);
    }

    public CompanyDto add(CompanyDto companyDto){
        Company company = MyModelMapper.fromCompanyDtoToCompany(companyDto);
        Company companyFromDb = companyRepository.save(company);
        return MyModelMapper.fromCompanyToCompanyDto(companyFromDb);
    }

    public List<CompanyDto> byName(String name){
        return companyRepository.findByName(name)
                .stream()
                .map(MyModelMapper::fromCompanyToCompanyDto)
                .collect(Collectors.toList());

    }


    public CompanyDto update(CompanyDto companyDto,Long id){
        Company company = companyRepository.findById(id).orElseThrow(()-> new CompanyNotFoundException("",LocalDateTime.now()));
        company.setName(companyDto.getName() == null? company.getName():companyDto.getName());
        company.setSpecialization(companyDto.getSpecialization()==null ? company.getSpecialization():companyDto.getSpecialization());
        company.setNumberOfEmployee(companyDto.getNumberOfEmployee()==null ? company.getNumberOfEmployee():companyDto.getNumberOfEmployee());
        Company companyFromDb = companyRepository.save(company);
        return MyModelMapper.fromCompanyToCompanyDto(companyFromDb);
    }

    public CompanyDto delete(Long id){
        Company company = companyRepository.findById(id).orElseThrow(()->new CompanyNotFoundException("",LocalDateTime.now()));
        companyRepository.delete(company);
        return MyModelMapper.fromCompanyToCompanyDto(company);
    }


}
