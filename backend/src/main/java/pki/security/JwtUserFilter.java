package pki.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            JwtAuthenticationToken token = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

            String email = String.valueOf(token.getTokenAttributes().get("email"));
            User user = this.userService.findUserByEmail(email);

            // new user detected, save data
            if (user == null) {
                String keycloakId = String.valueOf(token.getTokenAttributes().get("sub"));
                String firstname = String.valueOf(token.getTokenAttributes().get("given_name"));
                String lastname = String.valueOf(token.getTokenAttributes().get("family_name"));
                String organizationName = String.valueOf(token.getTokenAttributes().get("organization"));
                Organization organization;
                if (organizationService.exists(organizationName))
                    organization = organizationService.getByName(organizationName);
                else
                    organization = organizationService.create(new CreateOrganizationDTO(organizationName));
                this.userService.save(new User(null, keycloakId, email, firstname, lastname, organization, new ArrayList<>()));
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to save user");
        }

        filterChain.doFilter(request, response);
    }
}

