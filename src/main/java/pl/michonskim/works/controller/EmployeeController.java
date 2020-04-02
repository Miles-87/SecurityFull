package pl.michonskim.works.controller;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.michonskim.works.service.EmployeeService;
import pl.michonskim.works.dto.EmployeeDto;

import java.util.List;


@RestController
@RequestMapping("/employees")
public class EmployeeController {

    EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping
    public ResponseEntity<List<EmployeeDto>> all() {
        return new ResponseEntity<>(employeeService.all(), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<EmployeeDto> findOne(@PathVariable Long id) {
        return new ResponseEntity<>(employeeService.one(id), HttpStatus.OK);

    }

    @GetMapping("/company/{id}")
    public ResponseEntity<List<EmployeeDto>> findAllByCompanyId(@PathVariable Long id){
        return new ResponseEntity<>(employeeService.allEmployeeByCompany(id),HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<EmployeeDto> add(@RequestBody EmployeeDto employeeDto) {
        return new ResponseEntity<>(employeeService.add(employeeDto), HttpStatus.CREATED);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<EmployeeDto> delete(@PathVariable Long id) {
        return new ResponseEntity<>(employeeService.delete(id), HttpStatus.OK);
    }
}
