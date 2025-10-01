package pki.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pki.dto.organization.GetOrganizationDto;
import pki.service.OrganizationService;

import java.util.List;

@RestController
@RequestMapping("/organizations")
@RequiredArgsConstructor
public class OrganizationController {
    private final OrganizationService organizationService;

    @PreAuthorize("hasAuthority('ROLE_admin') or hasAuthority('ROLE_ca') or hasAuthority('ROLE_user')")
    @GetMapping()
    public ResponseEntity<List<GetOrganizationDto>> getAll() {
        List<GetOrganizationDto> organizations = organizationService.getAll();
        return ResponseEntity.ok(organizations);
    }
}
