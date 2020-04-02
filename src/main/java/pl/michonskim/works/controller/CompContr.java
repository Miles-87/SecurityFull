package pl.michonskim.works.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.michonskim.works.dto.CompanyDto;
import pl.michonskim.works.service.CompSer;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/mycom")
public class CompContr {

    private CompSer compSer;

    public CompContr(CompSer compSer) {
        this.compSer = compSer;
    }

    @GetMapping
    ResponseEntity<List<CompanyDto>> findAll() {
        return new ResponseEntity<>(compSer.all(), HttpStatus.OK);
    }

    @GetMapping("/die")
    ResponseEntity<LocalDateTime> jakis(){
        return new ResponseEntity<>(LocalDateTime.now(), HttpStatus.CREATED);
    }

    @GetMapping("/{id}")
    ResponseEntity<CompanyDto> one(@PathVariable Long id){
        return new ResponseEntity(compSer.one(id),HttpStatus.OK);
    }

    @PostMapping
    ResponseEntity<CompanyDto> add(@RequestBody CompanyDto companyDto){
        return new ResponseEntity<>(compSer.add(companyDto),HttpStatus.CREATED);
    }

    @GetMapping("/{name}")
    ResponseEntity<List<CompanyDto>> byName(@RequestParam(required = false) String name){
        return new ResponseEntity<>(compSer.byName(name), HttpStatus.OK);
    }

    @PutMapping("/{id}")
    ResponseEntity<CompanyDto> update(@PathVariable Long id,@RequestBody CompanyDto companyDto){
        return new ResponseEntity<>(compSer.update(companyDto, id), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    ResponseEntity<CompanyDto> delete(@PathVariable Long id){
        return new ResponseEntity<>(compSer.delete(id),HttpStatus.OK);
    }



}
