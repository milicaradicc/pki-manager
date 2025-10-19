package pki.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import pki.dto.organization.CreateOrganizationDTO;
import pki.model.Organization;
import pki.model.User;
import pki.service.OrganizationService;
import pki.service.UserService;

import java.io.IOException;
import java.util.ArrayList;

@Component
@RequiredArgsConstructor
public class JwtUserFilter extends OncePerRequestFilter {
    private final UserService userService;
    private final OrganizationService organizationService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Preskači filter za javne endpoint-e
        return path.startsWith("/api/crl/") ||
                path.startsWith("/crl/") ||
                path.equals("/user/home");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // Proveri da li je autentifikacija JwtAuthenticationToken
            if (!(authentication instanceof JwtAuthenticationToken)) {
                filterChain.doFilter(request, response);
                return;
            }

            JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
            String email = String.valueOf(token.getTokenAttributes().get("email"));

            // Proveri da li email postoji i nije "null"
            if (email == null || email.equals("null") || email.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            User user = this.userService.findUserByEmail(email);

            // Novi korisnik detektovan, sačuvaj podatke
            if (user == null) {
                String keycloakId = String.valueOf(token.getTokenAttributes().get("sub"));
                String firstname = String.valueOf(token.getTokenAttributes().get("given_name"));
                String lastname = String.valueOf(token.getTokenAttributes().get("family_name"));
                String organizationName = String.valueOf(token.getTokenAttributes().get("organization"));

                Organization organization = null;

                if (organizationName != null && !organizationName.isEmpty() && !organizationName.equals("null")) {
                    if (organizationService.exists(organizationName)) {
                        organization = organizationService.getByName(organizationName);
                    } else {
                        organization = organizationService.create(new CreateOrganizationDTO(organizationName));
                    }
                }

                this.userService.save(new User(null, keycloakId, email, firstname, lastname, organization, new ArrayList<>()));
            }
        } catch (ClassCastException e) {
            // Autentifikacija nije JWT tip, nastavi dalje
            filterChain.doFilter(request, response);
            return;
        } catch (Exception e) {
            // Loguj grešku za debugging
            logger.error("Error saving user from JWT token", e);
            throw new IllegalArgumentException("Unable to save user", e);
        }

        filterChain.doFilter(request, response);
    }
}