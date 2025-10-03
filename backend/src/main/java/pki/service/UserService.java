package pki.service;

import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import pki.dto.user.CaUserDTO;
import pki.model.User;
import pki.repository.UserRepository;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final Keycloak keycloak;

    @Value("${keycloak.realm}")
    private String realm;

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

    public List<CaUserDTO> getAllCAUsers(String roleName) {
        return keycloak.realm(realm)
                .roles()
                .get(roleName)
                .getUserMembers()
                .stream().map(ur -> new CaUserDTO(ur.getUsername(), ur.getEmail()))
                .toList();
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
