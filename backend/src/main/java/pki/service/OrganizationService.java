package pki.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pki.dto.organization.CreateOrganizationDTO;
import pki.model.Organization;
import pki.repository.OrganizationRepository;

import java.security.GeneralSecurityException;

@Service
@RequiredArgsConstructor
public class OrganizationService {
    private final OrganizationRepository organizationRepository;
    private final KeyService keyService;

    public Organization create(CreateOrganizationDTO createOrganizationDTO) throws GeneralSecurityException {
        Organization organization = new Organization();
        if (organizationRepository.existsById(createOrganizationDTO.getName()))
            throw new IllegalArgumentException("Organization with name " + createOrganizationDTO.getName() + " already exists");
        organization.setName(createOrganizationDTO.getName());
        organization.setWrappedKek(keyService.generateWrappedKek());
        return organizationRepository.save(organization);
    }

    public boolean exists(String name) {
        return organizationRepository.existsById(name);
    }

    public Organization getByName(String name) {
        return organizationRepository.findById(name).orElse(null);
    }
}
