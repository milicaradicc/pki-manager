package pki.controller;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import pki.dto.user.CaUserDTO;
import pki.dto.GetUserDTO;
import pki.model.User;
import pki.service.UserService;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {
    private ModelMapper modelMapper = new ModelMapper();

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PreAuthorize("hasAuthority('ROLE_user') or hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca')")
    @GetMapping("/profile")
    public ResponseEntity<GetUserDTO> getUserProfile() {
        User loggedUser = userService.getLoggedUser();
        return ResponseEntity.ok(modelMapper.map(loggedUser, GetUserDTO.class));
    }

    @GetMapping("/")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> getAllUsers() {
        return new ResponseEntity<>("Hello world for admin", HttpStatus.OK);
    }

    @GetMapping("/ca")
    @PreAuthorize("hasRole('ROLE_admin')")
    public ResponseEntity<List<CaUserDTO>> getAllCaUsers() {
        return new ResponseEntity<>(userService.getAllCAUsers("ca"), HttpStatus.OK);
    }
}
