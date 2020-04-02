package pl.michonskim.works.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pl.michonskim.works.entity.Company;
import pl.michonskim.works.entity.Employee;

import java.util.List;

@Repository
public interface CompanyRepository extends JpaRepository<Company, Long> {

    List<Company> findByName(String name);
}
