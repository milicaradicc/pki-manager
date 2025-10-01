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

    public void create(CreateOrganizationDTO createOrganizationDTO) throws GeneralSecurityException {
        Organization organization = new Organization();
        organization.setName(createOrganizationDTO.getName());
        organization.setWrappedKek(keyService.generateWrappedKek());
        organizationRepository.save(organization);
    }
}
