package pki.service;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import pki.model.User;
import pki.repository.UserRepository;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User getLoggedUser() {
        JwtAuthenticationToken token = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        return this.findUserByEmail(token.getTokenAttributes().get("email").toString());
    }

    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User save(User data) {
        return this.userRepository.save(data);
    }
}
