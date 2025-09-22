package pki.service;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import pki.model.User;
import pki.repository.UserRepository;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public User getLoggedUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken token) {
            String email = String.valueOf(token.getTokenAttributes().get("email"));
            return findUserByEmail(email);
        }
        return null;
    }

    public User save(User user) {
        Optional<User> existing = userRepository.findByEmail(user.getEmail());
        if (existing.isPresent()) {
            return existing.get();
        }
        return userRepository.save(user);
    }

    public List<String> getLoggedUserRoles() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken token) {
            Map<String, Object> realmAccess = (Map<String, Object>) token.getTokenAttributes().get("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                return (List<String>) realmAccess.get("roles");
            }
        }
        return List.of();
    }

    // zato sto svi korisnici mogu da imaju user (cim se kreira doda mu se automatski)
    public String getPrimaryRole() {
        List<String> roles = getLoggedUserRoles();
        if (roles.contains("admin")) return "admin";
        if (roles.contains("ca")) return "ca";
        if (roles.contains("user")) return "user";
        return null;
    }
}
