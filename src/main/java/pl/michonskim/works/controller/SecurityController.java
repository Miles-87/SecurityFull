package pl.michonskim.works.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.michonskim.works.dto.RegisterUserDto;
import pl.michonskim.works.service.RegisterService;

@Slf4j
@RestController
@RequestMapping("/security")
public class SecurityController {

    RegisterService registerService;

    public SecurityController(RegisterService registerService) {
        this.registerService = registerService;
    }

    @PostMapping("/users")
    ResponseEntity<Long> add(@RequestBody RegisterUserDto registerUserDto) {
        return new ResponseEntity(registerService.create(registerUserDto), HttpStatus.CREATED);
    }
}
