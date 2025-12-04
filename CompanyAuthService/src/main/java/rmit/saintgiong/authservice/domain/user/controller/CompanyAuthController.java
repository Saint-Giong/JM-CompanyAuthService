package rmit.saintgiong.authservice.domain.user.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CompanyAuthController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
