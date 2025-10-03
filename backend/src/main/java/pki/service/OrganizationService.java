package pki.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pki.dto.organization.CreateOrganizationDTO;
import pki.dto.organization.GetOrganizationDto;
import pki.model.Organization;
import pki.repository.OrganizationRepository;

import java.security.GeneralSecurityException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class OrganizationService {
    private final OrganizationRepository organizationRepository;
    private final KeyService keyService;

    public Organization create(CreateOrganizationDTO createOrganizationDTO) throws GeneralSecurityException {
        Organization organization = new Organization();
        if (exists(createOrganizationDTO.getName()))
            throw new IllegalArgumentException("Organization with name " + createOrganizationDTO.getName() + " already exists");
        organization.setName(createOrganizationDTO.getName());
        organization.setWrappedKek(keyService.generateWrappedKek());
        return organizationRepository.save(organization);
    }

    public boolean exists(String name) {
        return organizationRepository.findByNameCaseInsensitive(name).isPresent();
    }

    public Organization getByName(String name) {
        return organizationRepository.findByNameCaseInsensitive(name).orElse(null);
    }

    public List<GetOrganizationDto> getAll() {
        return organizationRepository.findAll()
                .stream()
                .map(organization -> new GetOrganizationDto(organization.getName()))
                .toList();
    }
}
