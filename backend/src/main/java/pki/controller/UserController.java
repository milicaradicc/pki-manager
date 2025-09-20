package pki.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pki.model.User;
import pki.service.UserService;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // open access API
    @GetMapping("/home")
    public ResponseEntity<String> getHelloMessage() {
        return new ResponseEntity<>("Hello world", HttpStatus.OK);
    }

    // authenticated API
    @GetMapping("/profile")
    public ResponseEntity<User> getUserProfile() {
        User loggedUser = this.userService.getLoggedUser();
        return new ResponseEntity<>(loggedUser, HttpStatus.OK);
    }

    // API only for admin
    @GetMapping("/")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> getAllUsers() {
        return new ResponseEntity<>("Hello world for admin", HttpStatus.OK);
    }

}
