package pki.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pki.model.User;
import pki.service.UserService;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @GetMapping("/profile")
    public ResponseEntity<User> getUserProfile() {
        User loggedUser = userService.getLoggedUser();
        return ResponseEntity.ok(loggedUser);
    }

    @GetMapping("/")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> getAllUsers() {
        return new ResponseEntity<>("Hello world for admin", HttpStatus.OK);
    }
}
