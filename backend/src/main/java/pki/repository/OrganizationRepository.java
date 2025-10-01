package pki.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pki.model.Certificate;
import pki.model.CertificateParty;
import pki.model.CertificateType;
import pki.model.Organization;

import java.util.List;
import java.util.Optional;

public interface OrganizationRepository extends JpaRepository<Organization,Integer> {
    Optional<Organization> findByName(String name);
    boolean existsByName(String name);
}
